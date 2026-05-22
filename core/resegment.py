# -*- coding: utf-8 -*-
"""
TCP 重分段、ACK 克隆与 SEQ/ACK/SACK 修正。

核心流程：
  1. 将改写后的 new_stream 重新切回物理包（resegment_tcp_flow）
  2. 映射重传片 payload 到新流坐标（remap_retransmissions）
  3. 克隆反向 ACK 包维持确认节奏（clone_response_ack）
  4. 统一修正所有包的 seq/ack/SACK（adjust_seq_ack）
"""

import copy
from decimal import Decimal
from loguru import logger
from scapy.layers.inet import IP, TCP
from core.context import TcpRewritePlan
from core.flow import reverse_flow_key
from core.utils import clear_autofields, map_offset, real_tcp_payload, seq_add, seq_offset, set_l4_payload
from config import TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_FIN, TCP_FLAG_SYN, TCP_FLAG_RST, DEFAULT_MAX_FRAME_LEN, DEFAULT_TCP_MAX_PAYLOAD


def tcp_payload_capacity(packet):
    """
    计算当前 TCP 包可承载的最大 payload 字节数。
    取 TCP 最大 payload 和链路层帧长限制的较小值。
    """
    if TCP not in packet:
        return 0
    payload = real_tcp_payload(packet)  # 裁掉以太网尾部 padding 后的真实 TCP payload
    # 整个包序列化长度 - 真实 payload 长度 = IP头+TCP头+链路层头
    header_len = len(bytes(packet)) - len(payload)
    # 链路层最长帧长减去头部开销，得到帧长约束下的可用空间
    by_frame = max(0, DEFAULT_MAX_FRAME_LEN - header_len)
    # 取 TCP MSS 和链路层帧长的较小值
    return max(0, min(DEFAULT_TCP_MAX_PAYLOAD, by_frame))


def is_pure_ack(packet):
    """判断 TCP 包是否为无 payload 的 ACK（至少含 ACK 标志、无 SYN/FIN/RST、无数据）。"""
    if not (IP in packet and TCP in packet):
        return False
    flags = int(packet[TCP].flags)  # 读取 TCP 标志位（整数）
    if not (flags & TCP_FLAG_ACK):  # 必须有 ACK 标志
        return False
    # SYN/FIN/RST 包不是"纯 ACK"（它们有特殊的序列号语义）
    if flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST):
        return False
    # 无 payload 才是纯 ACK
    return not real_tcp_payload(packet)


def clear_tcp_end_flags(packet):
    """清理 TCP 中间分片不应携带的 PSH/FIN 标志。"""
    if TCP in packet:
        # 按位清除 PSH 和 FIN（~取反后按位与，保留其他标志不变）
        packet[TCP].flags = int(packet[TCP].flags) & ~TCP_FLAG_PSH & ~TCP_FLAG_FIN


def apply_segment_end_flags(active_packets, last_flags):
    """
    把原消息末片的 PSH/FIN 语义转移到新重分段后的末片上。
    中间分片清除 PSH/FIN 标志。
    """
    # 除最后一个包外，全部清除 PSH/FIN（它们现在是中间分片）
    for packet in active_packets[:-1]:
        clear_tcp_end_flags(packet)
        # 清除派生字段，让 Scapy 在写出时重算 len/chksum
        clear_autofields(packet, packet[IP] if IP in packet else None, packet[TCP] if TCP in packet else None)
    if active_packets:
        # 末片继承原始最后一包的 flags（PSH/FIN 等）
        active_packets[-1][TCP].flags = last_flags
        clear_autofields(active_packets[-1], active_packets[-1][IP], active_packets[-1][TCP])


def find_next_reverse_ack(packets, packet_keys, start_index, key, deleted_indices,
                          ack_offset=None, base_seq=None):
    """
    查找当前数据片之后的反向纯 ACK（反方向流中仅 ACK 标志的包）。
    如果指定 ack_offset，则需要 ACK 确认号匹配该偏移。
    """
    reverse_key = reverse_flow_key(key)  # 交换 src/dst 得到反方向流标识
    for index in range(start_index + 1, len(packets)):
        if index in deleted_indices:  # 跳过已被标记删除的包
            continue
        current_key = packet_keys.get(index)
        # 如果遇到同方向的下一个数据包（有 payload），ACK 不可能越过它确认后面的数据
        if current_key == key and real_tcp_payload(packets[index]):
            break
        # 必须属于反方向且是纯 ACK
        if current_key != reverse_key or not is_pure_ack(packets[index]):
            continue
        if ack_offset is None:  # 不要求精确偏移匹配，找到第一个即可
            return index
        # 要求 ACK 确认号精确匹配到 base_seq + ack_offset
        if base_seq is not None and seq_offset(int(packets[index][TCP].ack), base_seq) == ack_offset:
            return index
    return None


def clone_response_ack(packets, packet_keys, start_index, key, base_seq, ack_offset):
    """
    从邻近的反向 ACK 包克隆一个新的确认包。
    优先向前找，找不到向后找。
    克隆后设置新的 ack 确认号。
    """
    reverse_key = reverse_flow_key(key)
    template = None
    # 向前搜索：找反方向第一个纯 ACK 包作为模板
    for index in range(start_index + 1, len(packets)):
        if packet_keys.get(index) == reverse_key and is_pure_ack(packets[index]):
            template = packets[index]
            break
    # 向前找不到，向后搜索
    if template is None:
        for index in range(start_index - 1, -1, -1):
            if packet_keys.get(index) == reverse_key and is_pure_ack(packets[index]):
                template = packets[index]
                break
    if template is None:
        return None  # 整个 pcap 中找不到可克隆的 ACK 模板

    ack_packet = copy.deepcopy(template)  # 深拷贝模板包（不修改原始包）
    set_l4_payload(ack_packet[TCP], b"")  # 清空 payload，ACK 包不应带数据
    # 合并模板包原有的 flags（如 PSH）与 ACK 标志
    ack_packet[TCP].flags = int(template[TCP].flags) | TCP_FLAG_ACK
    # 新 ACK 确认号 = base_seq + 已写入新流的累积偏移
    ack_packet[TCP].ack = seq_add(base_seq, ack_offset)
    clear_autofields(ack_packet, ack_packet[IP], ack_packet[TCP])  # 让 Scapy 重算 len/chksum
    return ack_packet


def assign_insert_times(insert_after, packets, deleted_indices):
    """
    为新增 TCP 包分配稳定的时间戳。
    在前一个真实包和后一个真实包之间均匀分布，使用 Decimal 保持精度。
    """
    for after_index, inserted_packets in insert_after.items():
        if not inserted_packets:
            continue
        # 取插入位置的前一个包的时间（基准时间）
        base_time = getattr(packets[after_index], "time", None)
        next_time = None
        # 向后找到第一个未被删除的真实包，取其时间（上界时间）
        for probe in range(after_index + 1, len(packets)):
            if probe in deleted_indices:  # 跳过已标记删除的包
                continue
            next_time = getattr(packets[probe], "time", None)
            break
        for pos, packet in enumerate(inserted_packets, start=1):
            try:
                # 用 Decimal 保持高精度避免浮点误差
                base_decimal = Decimal(str(base_time)) if base_time is not None else None
                next_decimal = Decimal(str(next_time)) if next_time is not None else None
                if base_decimal is not None and next_decimal is not None and next_decimal > base_decimal:
                    # 在前后真实包之间均匀插值（如3个新包插入2个真实包之间：step=1/4间隔）
                    step = (next_decimal - base_decimal) / Decimal(len(inserted_packets) + 1)
                    packet.time = base_decimal + step * Decimal(pos)
                elif base_decimal is not None:
                    # 只有前包时间，每个新包间隔 1 微秒
                    packet.time = base_decimal + Decimal("0.000001") * Decimal(pos)
            except (ArithmeticError, TypeError, ValueError) as exc:
                logger.debug(f"新增 TCP 包时间戳分配失败，保留模板时间: {exc}")


def resegment_tcp_flow(flow, packets, packet_keys, plan):
    """
    把改写后的 TCP 字节流(new_stream)重新切回物理包。

    两阶段策略：
      第一阶段：优先用原有数据包承载 new_stream，超出部分删除旧包
      第二阶段：旧包不够时，以最后一个旧主片为模板克隆新增包
    """
    # 只取主片（primary=True，即非重传片），按(old_start, index)排序保证顺序
    primary_segments = sorted(
        (meta for meta in flow.segments.values() if meta.primary),
        key=lambda meta: (meta.old_start, meta.index),
    )
    if not primary_segments:
        return

    cursor = 0  # 指向 new_stream 中下一个未分配的字节位置
    active_packets = []  # 收集所有承载 new_stream 的包（含原始包和新增克隆包）
    last_primary = primary_segments[-1]  # 保存最后一个主片用于第二阶段的模板
    last_packet = packets[last_primary.index]  # 最后一个主片对应的原始包
    last_flags = int(last_packet[TCP].flags)  # 保留原始末片的 flags（PSH/FIN等）
    last_capacity = tcp_payload_capacity(last_packet)  # 最后一片的容量
    if last_capacity <= 0:
        logger.warning(f"TCP流{flow.key} 最后一片容量为 0，跳过重分段")
        return

    # ---- 第一阶段：填充已有包 ----
    for meta in primary_segments:
        packet = packets[meta.index]
        capacity = tcp_payload_capacity(packet)  # 当前包的 payload 容量
        if capacity <= 0:
            continue
        # 从 new_stream 的 cursor 位置切出 capacity 字节
        chunk = flow.new_stream[cursor:cursor + capacity]
        if not chunk:
            # new_stream 已全部分配完毕，剩余的旧包标记删除
            plan.deleted_indices.add(meta.index)
            continue

        # 计算新 SEQ = base_seq + 当前写入的流偏移
        new_seq = seq_add(flow.base_seq, cursor)
        set_l4_payload(packet[TCP], chunk)  # 替换 TCP payload 为对应 chunk
        packet[TCP].seq = new_seq  # 更新 SEQ
        flow.packet_new_seq[meta.index] = new_seq  # 记录精确新 SEQ（避免二次映射）
        clear_autofields(packet, packet[IP], packet[TCP])  # 清除派生字段让 Scapy 重算
        active_packets.append(packet)
        if chunk != meta.old_payload:  # payload 发生了变化才标记
            plan.changed_indices.add(meta.index)

        # 查找当前数据包后紧跟的反向纯 ACK，将其确认号覆盖为新偏移
        ack_index = find_next_reverse_ack(packets, packet_keys, meta.index, flow.key, plan.deleted_indices)
        if ack_index is not None:
            plan.ack_overrides[ack_index] = seq_add(flow.base_seq, cursor + len(chunk))
        cursor += len(chunk)  # 推进游标

    # ---- 第二阶段：克隆新增包 ----
    extra_packets = []  # 收集所有新增的克隆包
    extra_id = 1  # 克隆包计数器，用于递增 IP.id
    while cursor < len(flow.new_stream):
        # 在新增数据包前插入一个确认 ACK，维持"发送方收到确认后才发新数据"的交互节奏
        ack_packet = clone_response_ack(packets, packet_keys, last_primary.index, flow.key, flow.base_seq, cursor)
        if ack_packet is not None:
            extra_packets.append(ack_packet)

        # 从 new_stream 的 cursor 位置再切一块（最多 last_capacity 字节）
        chunk = flow.new_stream[cursor:cursor + last_capacity]
        piece = copy.deepcopy(last_packet)  # 以最后一个主片为模板深拷贝
        new_seq = seq_add(flow.base_seq, cursor)  # 计算新 SEQ
        set_l4_payload(piece[TCP], chunk)  # 填入新 payload
        piece[TCP].seq = new_seq
        if hasattr(piece[IP], "id"):  # 递增 IP 标识符避免 IP ID 冲突
            try:
                piece[IP].id = (int(piece[IP].id) + extra_id) & 0xFFFF  # 16位回绕
            except (TypeError, ValueError) as exc:
                logger.debug(f"新增 TCP 分片 IP id 递增失败，保留模板值: {exc}")
        clear_autofields(piece, piece[IP], piece[TCP])
        active_packets.append(piece)
        extra_packets.append(piece)
        cursor += len(chunk)
        extra_id += 1

    # 重分段完成后：末片继承原消息的 PSH/FIN，中间分片清除 PSH/FIN
    apply_segment_end_flags(active_packets, last_flags)

    if extra_packets:
        # 为新增包序列末尾找一个反向 ACK 确认全部数据
        ack_index = find_next_reverse_ack(packets, packet_keys, last_primary.index, flow.key, plan.deleted_indices)
        if ack_index is None:
            # 找不到现有 ACK → 克隆一个新的确认包
            ack_packet = clone_response_ack(packets, packet_keys, last_primary.index, flow.key, flow.base_seq, len(flow.new_stream))
            if ack_packet is not None:
                extra_packets.append(ack_packet)
        else:
            # 找到现有 ACK → 直接覆盖其确认号
            plan.ack_overrides[ack_index] = seq_add(flow.base_seq, len(flow.new_stream))
        # 将新增包插入到最后一片之后
        plan.insert_after[last_primary.index].extend(extra_packets)

    # 清理被删除旧包的对应反向 ACK（数据都没了，确认它的 ACK 也没意义）
    for meta in primary_segments:
        if meta.index not in plan.deleted_indices:
            continue
        # 查找与该旧包 old_end 偏移精确匹配的反向 ACK
        ack_index = find_next_reverse_ack(packets, packet_keys, meta.index, flow.key, plan.deleted_indices,
                                          ack_offset=meta.old_end, base_seq=flow.base_seq)
        if ack_index is not None:
            plan.deleted_indices.add(ack_index)  # 一并删除


def resegment_preserve(flow, packets, plan):
    """
    保留原始 TCP segment 边界：用 map_offset 将每个主片的 old_start/old_end
    映射到 new_stream 对应片段，直接写回原包。

    不增删包、不克隆 ACK、不修改 flags。
    仅当某 segment 映射后 payload 超过 MTU 时降级为流级合并。
    :return: True=成功, False=需要降级到流级合并
    """
    # 取所有主片，按 old_start 排序保证顺序
    primary_segments = sorted(
        (meta for meta in flow.segments.values() if meta.primary),
        key=lambda meta: (meta.old_start, meta.index),
    )
    for meta in primary_segments:
        packet = packets[meta.index]
        # 用 edits 将旧流偏移映射为新流偏移
        new_start = map_offset(meta.old_start, flow.edits)
        new_end = map_offset(meta.old_end, flow.edits)
        # 从 new_stream 中取出该 segment 对应片段
        new_payload = flow.new_stream[new_start:new_end]

        # 安全检查：新 payload 不能超过该包的 MTU 容量
        capacity = tcp_payload_capacity(packet)
        if capacity > 0 and len(new_payload) > capacity:
            logger.warning(
                f"TCP流{flow.key} 包#{meta.index} payload "
                f"{len(meta.old_payload)}->{len(new_payload)} 超过MTU({capacity})，降级流级合并"
            )
            # 降级：清空已做的改动，标记此流需要流级合并
            flow.preserve_boundaries = False
            plan.changed_indices.clear()
            plan.deleted_indices.clear()
            return False

        if new_payload == meta.old_payload:  # 内容未变则跳过
            continue

        # 直接写回原包：设置新 payload + 新 SEQ
        new_seq = seq_add(flow.base_seq, new_start)
        set_l4_payload(packet[TCP], new_payload)
        packet[TCP].seq = new_seq
        flow.packet_new_seq[meta.index] = new_seq  # 记录精确 SEQ
        flow.segment_payloads[meta.index] = new_payload  # 记录改写后的 payload
        clear_autofields(packet, packet[IP], packet[TCP])  # 让 Scapy 重算 len/chksum
        plan.changed_indices.add(meta.index)  # 标记此包已修改

    return True


def remap_retransmissions(flow, packets, plan):
    """
    把非主片（重传片）的 payload 映射到新流坐标。
    根据 edits 区间将旧偏移映射为新偏移，取 new_stream 对应片段。
    """
    for meta in sorted(flow.segments.values(), key=lambda item: item.index):
        # 跳过主片和已标记删除的包（主片已在 resegment_tcp_flow 中处理）
        if meta.primary or meta.index in plan.deleted_indices:
            continue

        packet = packets[meta.index]
        # 用 edits 将旧流偏移映射为新流偏移
        new_start = map_offset(meta.old_start, flow.edits)
        new_end = map_offset(meta.old_end, flow.edits)
        new_payload = flow.new_stream[new_start:new_end]  # 取 new_stream 对应片段
        if not new_payload:
            plan.deleted_indices.add(meta.index)  # 映射后为空则删除
            continue

        capacity = tcp_payload_capacity(packet)  # 当前包容量
        if capacity <= 0:
            continue
        # 如果新 payload 超过单包容量，按 capacity 切分为多个 chunk
        chunks = [new_payload[pos:pos + capacity] for pos in range(0, len(new_payload), capacity)]
        first = chunks[0]  # 第一个 chunk 放入当前包
        new_seq = seq_add(flow.base_seq, new_start)  # 新 SEQ = base_seq + 映射后偏移
        set_l4_payload(packet[TCP], first)
        packet[TCP].seq = new_seq
        flow.packet_new_seq[meta.index] = new_seq
        clear_autofields(packet, packet[IP], packet[TCP])
        if first != meta.old_payload:
            plan.changed_indices.add(meta.index)

        # 超出一个包容量时，克隆新包承载剩余 chunk
        if len(chunks) <= 1:
            continue
        extra_packets = []
        offset = len(first)  # 已放入第一个包的字节数
        for chunk in chunks[1:]:
            piece = copy.deepcopy(packet)  # 以当前包为模板深拷贝
            set_l4_payload(piece[TCP], chunk)
            piece[TCP].seq = seq_add(flow.base_seq, new_start + offset)  # 新 SEQ 递增
            clear_tcp_end_flags(piece)  # 中间分片不应有 PSH/FIN
            clear_autofields(piece, piece[IP], piece[TCP])
            extra_packets.append(piece)
            offset += len(chunk)
        clear_tcp_end_flags(packet)  # 原包也清除 PSH/FIN（它现在也是中间分片）
        plan.insert_after[meta.index].extend(extra_packets)  # 插入到当前包之后


def adjust_sack_options(tcp, state):
    """
    修正 TCP SACK option 中的序列号区间。
    SACK 区间指向反方向的旧流坐标，需要用反向流的 edits 映射到新坐标。
    """
    changed = False
    options = []
    for name, value in tcp.options:  # 遍历所有 TCP option
        # 非 SACK option 直接保留
        if str(name).lower() != "sack" or not isinstance(value, (tuple, list)):
            options.append((name, value))
            continue
        new_values = []
        for seq in value:  # value 是 SACK 区间元组（如 (left_edge, right_edge, ...)）
            offset = seq_offset(int(seq), state.base_seq)  # 将绝对 seq 转为流内偏移
            if offset is None or offset > state.old_len + 1:  # 超出流范围，保留原值
                new_values.append(seq)
                continue
            # 映射为新流偏移 → 绝对 seq
            new_seq = seq_add(state.base_seq, map_offset(offset, state.edits))
            new_values.append(new_seq)
            changed = changed or int(seq) != new_seq  # 任一值变化即标记
        options.append((name, tuple(new_values)))
    if changed:
        tcp.options = options  # 写回修改后的 option 列表
    return changed


def adjust_seq_ack(packet, key, modified_flows, index=None, keep_seq=False, ack_overrides=None):
    """
    修正 TCP 包的 seq、ack 与 SACK option。

    SEQ 映射：用当前方向流的 edits 将旧流偏移映射为新流偏移
    ACK 映射：用反向流的 edits 做同样映射
    SACK：调用 adjust_sack_options 修正每个区间
    """
    if TCP not in packet:
        return False
    changed = False
    tcp = packet[TCP]
    ack_overrides = ack_overrides or {}  # 确保不为 None

    # ---- SEQ 修正（当前方向）----
    state = modified_flows.get(key)  # 取当前方向的流状态
    if state and not keep_seq:  # keep_seq=True 用于新增包（SEQ 已精确设置）
        if index is not None and index in state.packet_new_seq:
            # 优先取重分段阶段记录的精确新 SEQ（避免二次映射误差）
            new_seq = state.packet_new_seq[index]
        else:
            # 用 seq_offset + map_offset 做通用映射
            offset = seq_offset(int(tcp.seq), state.base_seq)
            new_seq = None
            if offset is not None and offset <= state.old_len + 1:
                new_seq = seq_add(state.base_seq, map_offset(offset, state.edits))
        if new_seq is not None and int(tcp.seq) != new_seq:
            tcp.seq = new_seq
            changed = True

    # ---- ACK 修正（反向）----
    reverse_state = modified_flows.get(reverse_flow_key(key))  # 取反方向流状态
    if index is not None and index in ack_overrides:
        # 被计划强制覆盖的 ACK（来自 resegment_tcp_flow 的精确覆盖）
        new_ack = ack_overrides[index]
        if int(tcp.ack) != new_ack:
            tcp.ack = new_ack
            changed = True
    elif reverse_state and int(tcp.flags) & TCP_FLAG_ACK:
        # 通用 ACK 映射：将确认号映射到反向流的新坐标
        offset = seq_offset(int(tcp.ack), reverse_state.base_seq)
        if offset is not None and offset <= reverse_state.old_len + 1:
            new_ack = seq_add(reverse_state.base_seq, map_offset(offset, reverse_state.edits))
            if int(tcp.ack) != new_ack:
                tcp.ack = new_ack
                changed = True
        # 同时修正 SACK option（SACK 也指向反向流坐标）
        changed = adjust_sack_options(tcp, reverse_state) or changed

    if changed:
        clear_autofields(packet, packet[IP] if IP in packet else None, tcp)  # 让 Scapy 重算
    return changed


def direction_key_for_inserted(packet, nearby_key):
    """
    为新增 TCP 包生成 FlowKey（继承附近原始包的连接 ID）。
    """
    if nearby_key is None or not (IP in packet and TCP in packet):
        return None
    conn_id = nearby_key[0]  # 继承附近包的连接 ID（端点对+分代）
    # 根据新包的实际四元组生成流标识
    return conn_id, packet[IP].src, int(packet[TCP].sport), packet[IP].dst, int(packet[TCP].dport)


def resegment_tcp_flows(flows, packets, packet_keys, stats):
    """
    对所有已改写的 TCP 流执行重分段计划。
    包括：主片重分段、重传片映射、时间戳分配、统计更新。
    """
    plan = TcpRewritePlan()
    for key, flow in flows.items():
        if not flow.edits and flow.new_stream == flow.old_stream:  # 无变化则跳过
            continue
        plan.modified_flows[key] = flow  # 记录该流已被修改
        resegment_tcp_flow(flow, packets, packet_keys, plan)  # 主片重分段
        remap_retransmissions(flow, packets, plan)  # 重传片映射
        stats.tcp_stream_changed += 1
        if flow.conflicts:  # 存在重叠冲突（不同重传片同一位置字节不一致）
            logger.warning(f"TCP流{key} 存在 {flow.conflicts} 个重叠冲突字节，已按首个有效片优先处理")
        if flow.holes:  # 存在未被任何包覆盖的字节（抓包缺失）
            logger.warning(f"TCP流{key} 存在 {flow.holes} 个未覆盖字节，替换结果可能受缺包影响")

    assign_insert_times(plan.insert_after, packets, plan.deleted_indices)  # 为新增包分配时间戳
    stats.tcp_packets_changed += len(plan.changed_indices)
    stats.tcp_inserted += sum(len(items) for items in plan.insert_after.values())
    stats.tcp_deleted += len(plan.deleted_indices)
    return plan


def apply_tcp_sequence_adjustments(packets, packet_keys, plan):
    """
    统一修正原始包和新增包的 TCP seq/ack/SACK。
    遍历所有包：对原始包修正 SEQ/ACK；对新增包也修正 SEQ（ACK 已在克隆时设置正确）。
    """
    for index, packet in enumerate(packets):
        if index in plan.deleted_indices:  # 跳过已标记删除的包
            continue
        key = packet_keys.get(index)
        if key is not None:
            # 修正原始包的 seq/ack/SACK
            adjust_seq_ack(packet, key, plan.modified_flows, index=index, ack_overrides=plan.ack_overrides)
        for inserted in plan.insert_after.get(index, []):  # 处理插入在当前包之后的新包
            inserted_key = direction_key_for_inserted(inserted, key)  # 为新包生成流标识
            if inserted_key is None:
                continue
            if is_pure_ack(inserted):  # 纯 ACK 包的 ack 已在克隆时正确设置，跳过
                continue
            # 新增数据包：keep_seq=True（SEQ已在重分段时精确设置，不需要二次映射）
            adjust_seq_ack(inserted, inserted_key, plan.modified_flows, keep_seq=True)
