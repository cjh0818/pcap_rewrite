# -*- coding: utf-8 -*-
"""
核心流程调度：串联 L2/L3/ICMP/UDP 包级改写 与 TCP 流级改写。

处理顺序：
  1. rewrite_l2_l3_udp_pass: ARP → IPv4 header → ICMP → UDP（包级）
  2. rewrite_tcp_pass: TCP 流重组 → 协议改写 → 重分段 → SEQ/ACK 修正（流级）
  3. build_output_packets: 按删除/插入计划生成最终输出包序列
"""

import traceback
import zlib
from loguru import logger
from scapy.layers.inet import IP, TCP, UDP
from core.context import RewriteContext, RewriteError, TcpRewritePlan
from core.flow import collect_tcp_flows, is_ipv4_fragment
from core.resegment import apply_tcp_sequence_adjustments, resegment_preserve, resegment_tcp_flows
from core.utils import compute_edits, real_udp_payload, set_l4_payload, clear_autofields
from protocols import TCP_DISPATCHER, UDP_DISPATCHER
from protocols.http1 import rewrite_http1_stream_safe
from config import HTTP_REQUEST_RE, HTTP_RESPONSE_RE, DEFAULT_UDP_MAX_PAYLOAD


# =============================================================================
# L2/L3/ICMP + UDP 包级改写阶段
# =============================================================================

def rewrite_udp_packet(packet, index, args, stats):
    """
    对单个 UDP 包执行协议 handler 改写。
    先用 UDP_DISPATCHER 选择 handler，对 raw 结果追加二进制 IP 替换。
    改写后 payload 超过阈值时回滚。
    """
    if not (IP in packet and UDP in packet):
        return
    if is_ipv4_fragment(packet):
        logger.warning(f"帧#{index} IPv4 分片 UDP payload 跳过应用层改写")
        return
    udp = packet[UDP]
    payload = real_udp_payload(packet)  # 裁掉以太网尾部 padding 后的真实 UDP payload
    ctx = RewriteContext(args, packet[IP], udp, "UDP", index, None, None, {})  # 构建改写上下文
    # 使用 UDP_DISPATCHER 按优先级选择匹配的协议 handler
    result = UDP_DISPATCHER.rewrite(payload, ctx)
    if not result.ok:  # handler 返回失败（如 QUIC/DTLS 含旧 IP 拒绝）
        stats.failures += 1
        logger.error(f"帧#{index} UDP[{result.label}] 拒绝替换: {result.reason}")
        return

    new_payload = result.payload
    changed = result.changed
    if not changed:
        return
    # 普通 UDP 包仍受单帧 MTU 约束；由 FragmentManager 重组出来的虚拟包
    # 会在输出阶段重新切成 IPv4 分片，因此不能按 1472 字节回滚。
    if len(new_payload) > DEFAULT_UDP_MAX_PAYLOAD and not getattr(packet, "_is_fragment_reassembly", False):
        stats.failures += 1
        logger.error(f"帧#{index} UDP payload 超过阈值 {len(new_payload)}>{DEFAULT_UDP_MAX_PAYLOAD}，已回滚")
        return
    if len(new_payload) > 65507:
        stats.failures += 1
        logger.error(f"帧#{index} UDP payload 超过协议上限 {len(new_payload)}>65507，已回滚")
        return

    set_l4_payload(udp, new_payload)  # 写入新 payload
    clear_autofields(packet, packet[IP], udp)  # 清除 IP/UDP 的 len/chksum 派生字段
    stats.udp_changed += 1
    logger.info(f"帧#{index} UDP[{result.label}] payload {len(payload)}->{len(new_payload)}")


def rewrite_l2_l3_udp_pass(packets, args, stats):
    """
    执行 ARP → IPv4 header → ICMP → UDP 的包级改写阶段。
    每个包只命中一条路径：ARP 改写后跳过后续，ICMP 改写后跳过 UDP。
    """
    from protocols.arp import rewrite_arp
    from protocols.ipv4 import rewrite_ipv4_header
    from protocols.icmp import rewrite_icmp

    for index, packet in enumerate(packets, start=1):  # 帧号从 1 开始
        stats.total_in += 1
        if packet is None:  # 分片重组后的续片占位，输出阶段会还原
            continue
        # ARP 是链路层协议（EthType=0x0806），不含 IP 层，改写后无需继续处理
        if rewrite_arp(packet, index, args, stats):
            continue
        # 替换 IPv4 header 的 src/dst 地址字段
        rewrite_ipv4_header(packet, index, args, stats)
        # ICMP 是 IP 上层协议（protocol=1），不含 UDP/TCP，改写后跳过 UDP
        if rewrite_icmp(packet, index, args, stats):
            continue
        rewrite_udp_packet(packet, index, args, stats)  # 尝试 UDP 改写


# =============================================================================
# TCP 流级改写阶段
# =============================================================================

def rewrite_tcp_stream(flow, packets, args, flow_state):
    """
    调用协议 handler 改写完整 TCP 字节流。

    策略：
      - HTTP 匹配 → rewrite_http1_stream_safe（流级合并，因为 HTTP body 可能跨包）
      - 其他 → TCP_DISPATCHER 选择 handler → 根据 handler.requires_stream_merge
        决定后续重分段策略（保留边界 / 流级合并）

    :return: 是否发生了改写
    """
    first_packet = packets[flow.packet_indices[0]]  # 取该流的第一个包
    ctx = RewriteContext(  # 构建改写上下文
        args=args,
        ip_layer=first_packet[IP],
        transport_layer=first_packet[TCP],
        proto_name="TCP",
        packet_index=flow.packet_indices[0] + 1,  # 帧号从1开始
        flow_key=flow.key,
        conn_key=flow.key[0],  # 连接 ID 用于跨方向共享状态（WebSocket等）
        flow_state=flow_state,
    )

    # HTTP 优先使用流级安全改写（HTTP body 可能跨多个 TCP segment，必须流级合并）
    if HTTP_REQUEST_RE.match(flow.old_stream) or HTTP_RESPONSE_RE.match(flow.old_stream):
        result = rewrite_http1_stream_safe(flow.old_stream, ctx, args)
        flow.preserve_boundaries = False  # HTTP 必须流级合并
    else:
        # 先探测 handler 以获取 requires_stream_merge 元属性（不执行改写）
        handler = TCP_DISPATCHER.select_handler(flow.old_stream, ctx)
        # 取反：handler 要求流级合并 → preserve=False；handler 不要求 → preserve=True
        flow.preserve_boundaries = (
            not getattr(handler, "requires_stream_merge", False) if handler else True
        )
        # 然后执行实际改写
        result = TCP_DISPATCHER.rewrite(flow.old_stream, ctx)

    if not result.ok:  # handler 拒绝改写（如 RDP 含旧 IP）
        logger.error(f"TCP流{flow.key} [{result.label}] 拒绝替换: {result.reason}")
        flow.new_stream = flow.old_stream  # 回退为原始流
        flow.edits = []
        flow.label = result.label
        return False

    if result.requires_stream_merge is not None:
        # SOCKS5 等外层 handler 会在 rewrite 后才知道内层协议是否需要流级重分段。
        flow.preserve_boundaries = not result.requires_stream_merge

    new_stream = result.payload
    changed = result.changed
    # 保存改写结果到流状态
    flow.new_stream = new_stream
    flow.edits = compute_edits(flow.old_stream, flow.new_stream)  # 计算编辑区间
    flow.label = result.label
    return changed or bool(flow.edits)


def rewrite_tcp_pass(packets, args, stats):
    """
    执行 TCP 流重组 → 协议改写 → 重分段 → SEQ/ACK 修正阶段。

    分流策略：
      - preserve_boundaries=True 的流走 resegment_preserve（零增删包）
      - preserve_boundaries=False 的流走 resegment_tcp_flows（现有流级合并）

    每个 TCP 流按最早出现的包排序处理。
    """
    flows, packet_keys = collect_tcp_flows(packets)  # 步骤1: 按五元组收集 TCP 流并重组
    flow_state = {}  # 跨连接共享状态（如 WebSocket 握手状态）

    plan = TcpRewritePlan()  # 初始化改写计划
    merged_flows = {}   # preserve_boundaries=False → 需要流级合并
    preserve_flows = {}  # preserve_boundaries=True → 保留原始边界

    # 步骤2: 遍历每个流，调用 handler 改写
    for key, flow in sorted(flows.items(), key=lambda item: min(item[1].packet_indices)):
        try:
            if rewrite_tcp_stream(flow, packets, args, flow_state):
                plan.modified_flows[key] = flow  # 记录该流已被修改
                if flow.preserve_boundaries:
                    preserve_flows[key] = flow  # 分流到保留边界
                else:
                    merged_flows[key] = flow  # 分流到流级合并
                logger.info(
                    f"TCP流{key} [{flow.label}] payload {len(flow.old_stream)}->{len(flow.new_stream)} "
                    f"edits={len(flow.edits)} preserve={flow.preserve_boundaries}"
                )
        except RewriteError as exc:  # handler 主动拒绝（如 RDP 含旧 IP）
            stats.failures += 1
            flow.new_stream = flow.old_stream
            flow.edits = []
            logger.error(f"TCP流{key} handler 拒绝: {exc}")
        except (AttributeError, IndexError, KeyError, TypeError, ValueError, zlib.error) as exc:
            stats.failures += 1  # 未预期的运行时异常
            flow.new_stream = flow.old_stream
            flow.edits = []
            logger.error(f"TCP流{key} handler 异常: {exc}")
            logger.debug(traceback.format_exc())

    if not plan.modified_flows:
        return TcpRewritePlan()  # 无变化，返回空计划

    # 步骤3: per-segment 保留边界：零增删包，直接写回每个 segment
    degraded = []  # 记录降级到流级合并的流（MTU 溢出）
    for key, flow in preserve_flows.items():
        if not resegment_preserve(flow, packets, plan):
            degraded.append(key)  # 超过 MTU → 降级
            merged_flows[key] = flow
        else:
            stats.tcp_stream_changed += 1

    for key in degraded:
        del preserve_flows[key]  # 从保留边界集合中移除降级流

    # 步骤4: 流级合并：执行 resegment + ACK 克隆 + 重传片映射
    if merged_flows:
        merge_plan = resegment_tcp_flows(merged_flows, packets, packet_keys, stats)
        # 将流级合并计划合并到总计划中
        plan.changed_indices.update(merge_plan.changed_indices)
        plan.deleted_indices.update(merge_plan.deleted_indices)
        plan.ack_overrides.update(merge_plan.ack_overrides)
        for idx, pkts in merge_plan.insert_after.items():
            plan.insert_after[idx].extend(pkts)
        for key, flow_state in merge_plan.modified_flows.items():
            plan.modified_flows[key] = flow_state

    # 步骤5: 统一修正所有包的 TCP seq/ack/SACK
    apply_tcp_sequence_adjustments(packets, packet_keys, plan)
    return plan


def build_output_packets(packets, plan, stats):
    """
    按删除和插入计划生成最终输出包序列。
    """
    output_packets = []
    for index, packet in enumerate(packets):
        if packet is None:
            continue
        if index in plan.deleted_indices:  # 跳过标记删除的包
            continue
        output_packets.append(packet)
        # 将插入计划中该索引后的所有新包追加到输出
        output_packets.extend(plan.insert_after.get(index, []))
    stats.total_out = len(output_packets)  # 统计最终输出包数
    return output_packets
