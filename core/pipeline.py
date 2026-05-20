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
from core.flow import collect_tcp_flows
from core.resegment import apply_tcp_sequence_adjustments, resegment_tcp_flows
from core.utils import compute_edits, real_udp_payload, replace_binary_ipv4, set_l4_payload, clear_autofields
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
    改写后 payload 超过 --udp-max 时回滚。
    """
    if not (IP in packet and UDP in packet):
        return
    udp = packet[UDP]
    payload = real_udp_payload(packet)
    ctx = RewriteContext(args, packet[IP], udp, "UDP", index, None, None, {})
    result = UDP_DISPATCHER.rewrite(payload, ctx)
    if not result.ok:
        stats.failures += 1
        logger.error(f"帧#{index} UDP[{result.label}] 拒绝替换: {result.reason}")
        return

    new_payload = result.payload
    changed = result.changed
    # raw handler 输出的 payload 还需要做 packed 二进制替换
    if result.label in {"tcp.raw", "udp.raw"}:
        bin_payload, bin_changed = replace_binary_ipv4(new_payload, args)
        if bin_changed:
            new_payload = bin_payload
            changed = True

    if not changed:
        return
    if len(new_payload) > DEFAULT_UDP_MAX_PAYLOAD:
        stats.failures += 1
        logger.error(f"帧#{index} UDP payload 超过阈值 {len(new_payload)}>{DEFAULT_UDP_MAX_PAYLOAD}，已回滚")
        return

    set_l4_payload(udp, new_payload)
    clear_autofields(packet, packet[IP], udp)
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

    for index, packet in enumerate(packets, start=1):
        stats.total_in += 1
        # 优先处理下层的 ARP 协议，ARP 协议上层没有其他协议，改写后跳过后续 L3/L4 处理
        if rewrite_arp(packet, index, args, stats):
            continue
        # 处理 IPv4 的 src/dst 字段，改写后继续处理 ICMP/UDP 协议
        rewrite_ipv4_header(packet, index, args, stats)
        if rewrite_icmp(packet, index, args, stats):
            continue
        rewrite_udp_packet(packet, index, args, stats)


# =============================================================================
# TCP 流级改写阶段
# =============================================================================

def rewrite_tcp_stream(flow, packets, args, flow_state):
    """
    调用协议 handler 改写完整 TCP 字节流。
    优先匹配 HTTP 正则走 http1 流级安全改写，
    其余交给 TCP_DISPATCHER 按优先级分发。
    :return: 是否发生了改写
    """
    first_packet = packets[flow.packet_indices[0]]
    ctx = RewriteContext(
        args=args,
        ip_layer=first_packet[IP],
        transport_layer=first_packet[TCP],
        proto_name="TCP",
        packet_index=flow.packet_indices[0] + 1,
        flow_key=flow.key,
        conn_key=flow.key[0],
        flow_state=flow_state,
    )

    # HTTP 优先使用流级安全改写（处理 WebSocket 切换等长连接场景）
    if HTTP_REQUEST_RE.match(flow.old_stream) or HTTP_RESPONSE_RE.match(flow.old_stream):
        result = rewrite_http1_stream_safe(flow.old_stream, ctx, args)
    else:
        result = TCP_DISPATCHER.rewrite(flow.old_stream, ctx)

    if not result.ok:
        logger.error(f"TCP流{flow.key} [{result.label}] 拒绝替换: {result.reason}")
        flow.new_stream = flow.old_stream
        flow.edits = []
        flow.label = result.label
        return False

    new_stream = result.payload
    changed = result.changed
    bin_changed = False
    # raw handler 输出的流还需要做 packed 二进制替换
    if result.label in {"tcp.raw", "udp.raw"}:
        bin_stream, bin_changed = replace_binary_ipv4(new_stream, args)
        if bin_changed:
            new_stream = bin_stream
            changed = True

    flow.new_stream = new_stream
    flow.edits = compute_edits(flow.old_stream, flow.new_stream)
    flow.label = result.label + ("+binary" if bin_changed else "")
    return changed or bool(flow.edits)


def rewrite_tcp_pass(packets, args, stats):
    """
    执行 TCP 流重组 → 协议改写 → 重分段 → SEQ/ACK 修正阶段。
    每个 TCP 流按最早出现的包排序处理。
    """
    flows, packet_keys = collect_tcp_flows(packets)
    flow_state = {}  # 跨连接共享状态（如 WebSocket 握手状态）
    changed_count = 0

    for key, flow in sorted(flows.items(), key=lambda item: min(item[1].packet_indices)):
        try:
            if rewrite_tcp_stream(flow, packets, args, flow_state):
                changed_count += 1
                logger.info(
                    f"TCP流{key} [{flow.label}] payload {len(flow.old_stream)}->{len(flow.new_stream)} "
                    f"edits={len(flow.edits)}"
                )
        except RewriteError as exc:
            stats.failures += 1
            flow.new_stream = flow.old_stream
            flow.edits = []
            logger.error(f"TCP流{key} handler 拒绝: {exc}")
        except (AttributeError, IndexError, KeyError, TypeError, ValueError, zlib.error) as exc:
            stats.failures += 1
            flow.new_stream = flow.old_stream
            flow.edits = []
            logger.error(f"TCP流{key} handler 异常: {exc}")
            logger.debug(traceback.format_exc())

    if not changed_count:
        return TcpRewritePlan()

    plan = resegment_tcp_flows(flows, packets, packet_keys, stats)
    apply_tcp_sequence_adjustments(packets, packet_keys, plan)
    return plan


def build_output_packets(packets, plan, stats):
    """
    按删除和插入计划生成最终输出包序列。
    """
    output_packets = []
    for index, packet in enumerate(packets):
        if index in plan.deleted_indices:
            continue
        output_packets.append(packet)
        output_packets.extend(plan.insert_after.get(index, []))
    stats.total_out = len(output_packets)
    return output_packets
