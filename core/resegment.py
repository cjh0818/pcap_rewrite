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
from core.utils import (
    clear_autofields,
    map_offset,
    real_tcp_payload,
    seq_add,
    seq_offset,
    set_l4_payload,
)
from config import TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_FIN


def tcp_payload_capacity(packet, args):
    """
    计算当前 TCP 包可承载的最大 payload 字节数。
    取 --tcp-max 和链路层帧长限制的较小值。
    """
    if TCP not in packet:
        return 0
    payload = real_tcp_payload(packet)
    # header_len = 整个包长度 - 真实 TCP payload 长度
    header_len = len(bytes(packet)) - len(payload)
    # 链路层最长帧长限制
    by_frame = max(0, args.max_frame_len - header_len)
    return max(0, min(args.tcp_max, by_frame))


def is_pure_ack(packet):
    """判断 TCP 包是否为无 payload 的纯 ACK（仅 ACK 标志且无数据）。"""
    return (
        IP in packet
        and TCP in packet
        and int(packet[TCP].flags) == TCP_FLAG_ACK
        and not real_tcp_payload(packet)
    )


def clear_tcp_end_flags(packet):
    """清理 TCP 中间分片不应携带的 PSH/FIN 标志。"""
    if TCP in packet:
        packet[TCP].flags = int(packet[TCP].flags) & ~TCP_FLAG_PSH & ~TCP_FLAG_FIN


def apply_segment_end_flags(active_packets, last_flags):
    """
    把原消息末片的 PSH/FIN 语义转移到新重分段后的末片上。
    中间分片清除 PSH/FIN 标志。
    """
    for packet in active_packets[:-1]:
        clear_tcp_end_flags(packet)
        clear_autofields(packet, packet[IP] if IP in packet else None, packet[TCP] if TCP in packet else None)
    if active_packets:
        active_packets[-1][TCP].flags = last_flags
        clear_autofields(active_packets[-1], active_packets[-1][IP], active_packets[-1][TCP])


def find_next_reverse_ack(packets, packet_keys, start_index, key, deleted_indices,
                          ack_offset=None, base_seq=None):
    """
    查找当前数据片之后的反向纯 ACK（反方向流中仅 ACK 标志的包）。
    如果指定 ack_offset，则需要 ACK 确认号匹配该偏移。
    """
    reverse_key = reverse_flow_key(key)
    for index in range(start_index + 1, len(packets)):
        if index in deleted_indices:
            continue
        current_key = packet_keys.get(index)
        # 遇到同方向下一个数据包就停止（ACK 不可能越过数据包确认）
        if current_key == key and real_tcp_payload(packets[index]):
            break
        if current_key != reverse_key or not is_pure_ack(packets[index]):
            continue
        if ack_offset is None:
            return index
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
    # 优先向前搜索
    for index in range(start_index + 1, len(packets)):
        if packet_keys.get(index) == reverse_key and is_pure_ack(packets[index]):
            template = packets[index]
            break
    # 找不到则向后搜索
    if template is None:
        for index in range(start_index - 1, -1, -1):
            if packet_keys.get(index) == reverse_key and is_pure_ack(packets[index]):
                template = packets[index]
                break
    if template is None:
        return None

    ack_packet = copy.deepcopy(template)
    set_l4_payload(ack_packet[TCP], b"")
    ack_packet[TCP].flags = TCP_FLAG_ACK
    # 设置确认号 = base_seq + 已写入新流的偏移
    ack_packet[TCP].ack = seq_add(base_seq, ack_offset)
    clear_autofields(ack_packet, ack_packet[IP], ack_packet[TCP])
    return ack_packet


def assign_insert_times(insert_after, packets, deleted_indices):
    """
    为新增 TCP 包分配稳定的时间戳。
    在前一个真实包和后一个真实包之间均匀分布，使用 Decimal 保持精度。
    """
    for after_index, inserted_packets in insert_after.items():
        if not inserted_packets:
            continue
        base_time = getattr(packets[after_index], "time", None)
        next_time = None
        for probe in range(after_index + 1, len(packets)):
            if probe in deleted_indices:
                continue
            next_time = getattr(packets[probe], "time", None)
            break
        for pos, packet in enumerate(inserted_packets, start=1):
            try:
                base_decimal = Decimal(str(base_time)) if base_time is not None else None
                next_decimal = Decimal(str(next_time)) if next_time is not None else None
                if base_decimal is not None and next_decimal is not None and next_decimal > base_decimal:
                    step = (next_decimal - base_decimal) / Decimal(len(inserted_packets) + 1)
                    packet.time = base_decimal + step * Decimal(pos)
                elif base_decimal is not None:
                    packet.time = base_decimal + Decimal("0.000001") * Decimal(pos)
            except (ArithmeticError, TypeError, ValueError) as exc:
                logger.debug(f"新增 TCP 包时间戳分配失败，保留模板时间: {exc}")


def resegment_tcp_flow(flow, packets, packet_keys, args, plan):
    """
    把改写后的 TCP 字节流(new_stream)重新切回物理包。

    两阶段策略：
      第一阶段：优先用原有数据包承载 new_stream，超出部分删除旧包
      第二阶段：旧包不够时，以最后一个旧主片为模板克隆新增包
    """
    # 只取主片（非重传片），按流偏移排序
    primary_segments = sorted(
        (meta for meta in flow.segments.values() if meta.primary),
        key=lambda meta: (meta.old_start, meta.index),
    )
    if not primary_segments:
        return

    cursor = 0  # 指向 new_stream 中下一个未分配的字节
    active_packets = []
    last_primary = primary_segments[-1]
    last_packet = packets[last_primary.index]
    last_flags = int(last_packet[TCP].flags)
    last_capacity = tcp_payload_capacity(last_packet, args)
    if last_capacity <= 0:
        logger.warning(f"TCP流{flow.key} 最后一片容量为 0，跳过重分段")
        return

    # ---- 第一阶段：填充已有包 ----
    for meta in primary_segments:
        packet = packets[meta.index]
        capacity = tcp_payload_capacity(packet, args)
        if capacity <= 0:
            continue
        chunk = flow.new_stream[cursor:cursor + capacity]
        if not chunk:
            # new_stream 已分配完毕，多余的旧 payload 包要删除
            plan.deleted_indices.add(meta.index)
            continue

        new_seq = seq_add(flow.base_seq, cursor)
        set_l4_payload(packet[TCP], chunk)
        packet[TCP].seq = new_seq
        flow.packet_new_seq[meta.index] = new_seq
        clear_autofields(packet, packet[IP], packet[TCP])
        active_packets.append(packet)
        if chunk != meta.old_payload:
            plan.changed_indices.add(meta.index)

        # 查找紧随的反向 ACK 并覆盖其确认号
        ack_index = find_next_reverse_ack(packets, packet_keys, meta.index, flow.key, plan.deleted_indices)
        if ack_index is not None:
            plan.ack_overrides[ack_index] = seq_add(flow.base_seq, cursor + len(chunk))
        cursor += len(chunk)

    # ---- 第二阶段：克隆新增包 ----
    extra_packets = []
    extra_id = 1
    while cursor < len(flow.new_stream):
        # 新增数据前先插一个确认 ACK
        ack_packet = clone_response_ack(packets, packet_keys, last_primary.index, flow.key, flow.base_seq, cursor)
        if ack_packet is not None:
            extra_packets.append(ack_packet)

        chunk = flow.new_stream[cursor:cursor + last_capacity]
        piece = copy.deepcopy(last_packet)
        new_seq = seq_add(flow.base_seq, cursor)
        set_l4_payload(piece[TCP], chunk)
        piece[TCP].seq = new_seq
        if hasattr(piece[IP], "id"):
            try:
                piece[IP].id = (int(piece[IP].id) + extra_id) & 0xFFFF
            except (TypeError, ValueError) as exc:
                logger.debug(f"新增 TCP 分片 IP id 递增失败，保留模板值: {exc}")
        clear_autofields(piece, piece[IP], piece[TCP])
        active_packets.append(piece)
        extra_packets.append(piece)
        cursor += len(chunk)
        extra_id += 1

    # 重分段后末片继承原消息的 PSH/FIN
    apply_segment_end_flags(active_packets, last_flags)

    if extra_packets:
        ack_index = find_next_reverse_ack(packets, packet_keys, last_primary.index, flow.key, plan.deleted_indices)
        if ack_index is None:
            ack_packet = clone_response_ack(packets, packet_keys, last_primary.index, flow.key, flow.base_seq, len(flow.new_stream))
            if ack_packet is not None:
                extra_packets.append(ack_packet)
        else:
            plan.ack_overrides[ack_index] = seq_add(flow.base_seq, len(flow.new_stream))
        plan.insert_after[last_primary.index].extend(extra_packets)

    # 被删除的旧数据包对应的 ACK 一并删除
    for meta in primary_segments:
        if meta.index not in plan.deleted_indices:
            continue
        ack_index = find_next_reverse_ack(packets, packet_keys, meta.index, flow.key, plan.deleted_indices,
                                          ack_offset=meta.old_end, base_seq=flow.base_seq)
        if ack_index is not None:
            plan.deleted_indices.add(ack_index)


def remap_retransmissions(flow, packets, args, plan):
    """
    把非主片（重传片）的 payload 映射到新流坐标。
    根据 edits 区间将旧偏移映射为新偏移，取 new_stream 对应片段。
    """
    for meta in sorted(flow.segments.values(), key=lambda item: item.index):
        if meta.primary or meta.index in plan.deleted_indices:
            continue

        packet = packets[meta.index]
        new_start = map_offset(meta.old_start, flow.edits)
        new_end = map_offset(meta.old_end, flow.edits)
        new_payload = flow.new_stream[new_start:new_end]
        if not new_payload:
            plan.deleted_indices.add(meta.index)
            continue

        capacity = tcp_payload_capacity(packet, args)
        if capacity <= 0:
            continue
        chunks = [new_payload[pos:pos + capacity] for pos in range(0, len(new_payload), capacity)]
        first = chunks[0]
        new_seq = seq_add(flow.base_seq, new_start)
        set_l4_payload(packet[TCP], first)
        packet[TCP].seq = new_seq
        flow.packet_new_seq[meta.index] = new_seq
        clear_autofields(packet, packet[IP], packet[TCP])
        if first != meta.old_payload:
            plan.changed_indices.add(meta.index)

        # 超出一个包容量时分片
        if len(chunks) <= 1:
            continue
        extra_packets = []
        offset = len(first)
        for chunk in chunks[1:]:
            piece = copy.deepcopy(packet)
            set_l4_payload(piece[TCP], chunk)
            piece[TCP].seq = seq_add(flow.base_seq, new_start + offset)
            clear_tcp_end_flags(piece)
            clear_autofields(piece, piece[IP], piece[TCP])
            extra_packets.append(piece)
            offset += len(chunk)
        clear_tcp_end_flags(packet)
        plan.insert_after[meta.index].extend(extra_packets)


def adjust_sack_options(tcp, state):
    """
    修正 TCP SACK option 中的序列号区间。
    SACK 区间指向反方向的旧流坐标，需要用反向流的 edits 映射到新坐标。
    """
    changed = False
    options = []
    for name, value in tcp.options:
        if str(name).lower() != "sack" or not isinstance(value, (tuple, list)):
            options.append((name, value))
            continue
        new_values = []
        for seq in value:
            offset = seq_offset(int(seq), state.base_seq)
            if offset is None or offset > state.old_len + 1:
                new_values.append(seq)
                continue
            new_seq = seq_add(state.base_seq, map_offset(offset, state.edits))
            new_values.append(new_seq)
            changed = changed or int(seq) != new_seq
        options.append((name, tuple(new_values)))
    if changed:
        tcp.options = options
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
    ack_overrides = ack_overrides or {}

    # SEQ 修正（当前方向）
    state = modified_flows.get(key)
    if state and not keep_seq:
        if index is not None and index in state.packet_new_seq:
            new_seq = state.packet_new_seq[index]
        else:
            offset = seq_offset(int(tcp.seq), state.base_seq)
            new_seq = None
            if offset is not None and offset <= state.old_len + 1:
                new_seq = seq_add(state.base_seq, map_offset(offset, state.edits))
        if new_seq is not None and int(tcp.seq) != new_seq:
            tcp.seq = new_seq
            changed = True

    # ACK 修正（反向）
    reverse_state = modified_flows.get(reverse_flow_key(key))
    if index is not None and index in ack_overrides:
        new_ack = ack_overrides[index]
        if int(tcp.ack) != new_ack:
            tcp.ack = new_ack
            changed = True
    elif reverse_state and int(tcp.flags) & TCP_FLAG_ACK:
        offset = seq_offset(int(tcp.ack), reverse_state.base_seq)
        if offset is not None and offset <= reverse_state.old_len + 1:
            new_ack = seq_add(reverse_state.base_seq, map_offset(offset, reverse_state.edits))
            if int(tcp.ack) != new_ack:
                tcp.ack = new_ack
                changed = True
        changed = adjust_sack_options(tcp, reverse_state) or changed

    if changed:
        clear_autofields(packet, packet[IP] if IP in packet else None, tcp)
    return changed


def direction_key_for_inserted(packet, nearby_key):
    """
    为新增 TCP 包生成 FlowKey（继承附近原始包的连接 ID）。
    """
    if nearby_key is None or not (IP in packet and TCP in packet):
        return None
    conn_id = nearby_key[0]
    return conn_id, packet[IP].src, int(packet[TCP].sport), packet[IP].dst, int(packet[TCP].dport)


def resegment_tcp_flows(flows, packets, packet_keys, args, stats):
    """
    对所有已改写的 TCP 流执行重分段计划。
    包括：主片重分段、重传片映射、时间戳分配、统计更新。
    """
    plan = TcpRewritePlan()
    for key, flow in flows.items():
        if not flow.edits and flow.new_stream == flow.old_stream:
            continue
        plan.modified_flows[key] = flow
        resegment_tcp_flow(flow, packets, packet_keys, args, plan)
        remap_retransmissions(flow, packets, args, plan)
        stats.tcp_stream_changed += 1
        if flow.conflicts:
            logger.warning(f"TCP流{key} 存在 {flow.conflicts} 个重叠冲突字节，已按首个有效片优先处理")
        if flow.holes:
            logger.warning(f"TCP流{key} 存在 {flow.holes} 个未覆盖字节，替换结果可能受缺包影响")

    assign_insert_times(plan.insert_after, packets, plan.deleted_indices)
    stats.tcp_packets_changed += len(plan.changed_indices)
    stats.tcp_inserted += sum(len(items) for items in plan.insert_after.values())
    stats.tcp_deleted += len(plan.deleted_indices)
    return plan


def apply_tcp_sequence_adjustments(packets, packet_keys, plan):
    """
    统一修正原始包和新增包的 TCP seq/ack/SACK。
    """
    for index, packet in enumerate(packets):
        if index in plan.deleted_indices:
            continue
        key = packet_keys.get(index)
        if key is not None:
            adjust_seq_ack(packet, key, plan.modified_flows, index=index, ack_overrides=plan.ack_overrides)
        for inserted in plan.insert_after.get(index, []):
            inserted_key = direction_key_for_inserted(inserted, key)
            if inserted_key is None:
                continue
            if is_pure_ack(inserted):
                continue
            adjust_seq_ack(inserted, inserted_key, plan.modified_flows, keep_seq=True)
