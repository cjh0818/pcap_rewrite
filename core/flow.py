# -*- coding: utf-8 -*-
"""
TCP 流标识生成、按 SYN 分代、流收集与字节流重组。

核心流程：
  1. assign_tcp_generations: 按 SYN 事件为连接分代
  2. collect_tcp_flows: 遍历所有 TCP 包，按五元组+分代分组
  3. build_stream_state: 对每个方向的包按 SEQ 重组完整字节流
"""

from collections import defaultdict
from scapy.layers.inet import IP, TCP
from core.context import SegmentMeta, TcpFlowState
from core.utils import real_tcp_payload, seq_offset
from config import TCP_FLAG_SYN, TCP_FLAG_ACK


def endpoint_pair(ip_layer, tcp_layer):
    """
    生成无方向 TCP 连接端点对（排序后便于双向流关联）。
    """
    left = (ip_layer.src, int(tcp_layer.sport))
    right = (ip_layer.dst, int(tcp_layer.dport))
    return (left, right) if left <= right else (right, left)


def assign_tcp_generations(packets):
    """
    按 SYN 事件为端点复用的 TCP 连接分代。
    同一个 IP:Port 对可能被多次复用，每次 SYN(无ACK) 递增代数。
    :return: {packet_index: generation_number}
    """
    generations = {}
    packet_generations = {}
    for index, packet in enumerate(packets):
        if not (IP in packet and TCP in packet):
            continue
        pair = endpoint_pair(packet[IP], packet[TCP])
        flags = int(packet[TCP].flags)
        syn = bool(flags & TCP_FLAG_SYN)
        ack = bool(flags & TCP_FLAG_ACK)
        # SYN 且无 ACK = 新连接发起（三次握手第一步）
        if syn and not ack:
            generations[pair] = generations.get(pair, 0) + 1
        elif pair not in generations:
            generations[pair] = 0
        packet_generations[index] = generations.get(pair, 0)
    return packet_generations


def make_flow_key(packet, generation):
    """
    为 IPv4/TCP 包生成单方向 TCP 流标识。
    流标识 = (连接ID, 源IP, 源端口, 目的IP, 目的端口)
    连接ID = (端点对, 分代编号)
    """
    if not (IP in packet and TCP in packet):
        return None
    ip = packet[IP]
    tcp = packet[TCP]
    conn_id = (endpoint_pair(ip, tcp), generation)
    return conn_id, ip.src, int(tcp.sport), ip.dst, int(tcp.dport)


def reverse_flow_key(key):
    """生成当前 TCP 流的反方向流标识（交换 src/dst）。"""
    conn_id, src, sport, dst, dport = key
    return conn_id, dst, dport, src, sport


def collect_tcp_flows(packets):
    """
    收集所有 TCP 包并构建单方向流状态。
    步骤：
      1. 按 SYN 分代
      2. 为每个包生成流标识
      3. 按流标识分组
      4. 对每组重组字节流
    :return: ({flow_key: TcpFlowState}, {packet_index: flow_key})
    """
    packet_generations = assign_tcp_generations(packets)
    packet_keys = {}
    indices_by_key = defaultdict(list)
    for index, packet in enumerate(packets):
        key = make_flow_key(packet, packet_generations.get(index, 0))
        if key is None:
            continue
        packet_keys[index] = key
        indices_by_key[key].append(index)

    flows = {}
    for key, indices in indices_by_key.items():
        state = build_stream_state(key, indices, packets)
        if state is not None:
            flows[key] = state
    return flows, packet_keys


def build_stream_state(key, packet_indices, packets):
    """
    按 SEQ 重组单方向 TCP payload 字节流。

    算法：
      - 以最小 SEQ 为基准序列号
      - 按 (偏移, -长度) 排序，优先处理早出现的长片段
      - 首次写入的字节标记为"主片"(primary)，重传覆盖的字节只计数冲突
      - 统计 holes（未被任何包覆盖的字节数）和 conflicts（覆盖但不一致）
    :return: TcpFlowState 或 None（该方向无 payload）
    """
    payloads = []
    for index in packet_indices:
        # 读取真实 TCP payload（排除以太网尾部 padding）
        payload = real_tcp_payload(packets[index])
        if payload:
            payloads.append((index, int(packets[index][TCP].seq), payload))
    if not payloads:
        return None

    # 以最小 seq 为基准，使偏移计算不受抓包乱序影响
    base_seq = min(seq for _, seq, _ in payloads)

    # stream: 重组后的字节数组；filled: 标记每个位置是否已被写入（0/1）
    stream = bytearray()
    filled = bytearray()
    segments = {}
    conflicts = 0

    def ensure(size):
        """扩容重组缓冲区到指定长度。"""
        if len(stream) < size:
            stream.extend(b"\x00" * (size - len(stream)))
            filled.extend(b"\x00" * (size - len(filled)))

    # 排序：同 seq 时长片段优先，减少短异常重传遮住真实 payload
    ordered = []
    for index, seq, payload in payloads:
        offset = seq_offset(seq, base_seq)
        if offset is None:
            continue
        ordered.append((offset, -len(payload), index, payload, seq))
    ordered.sort()

    for offset, _, index, payload, seq in ordered:
        ensure(offset + len(payload))
        contributed = 0
        for pos_delta, value in enumerate(payload):
            pos = offset + pos_delta
            if not filled[pos]:
                # 该位置首次被写入，计入主片贡献
                stream[pos] = value
                filled[pos] = 1
                contributed += 1
            elif stream[pos] != value:
                # 重传但字节不同，记录冲突但不覆盖
                conflicts += 1
        # 记录每个包的元数据：contributed=0 视为纯重传片
        segments[index] = SegmentMeta(
            index=index,
            seq=seq,
            old_start=offset,
            old_end=offset + len(payload),
            old_payload=payload,
            primary=contributed > 0,
            contributed=contributed,
        )

    # 统计未覆盖字节（holes）— 表示抓包可能缺失
    holes = sum(1 for mark in filled if not mark)
    # packet_starts 用于诊断应用层消息边界
    packet_starts = sorted(meta.old_start for meta in segments.values() if meta.primary)

    return TcpFlowState(
        key=key,
        packet_indices=list(packet_indices),
        base_seq=base_seq,
        old_stream=bytes(stream),
        segments=segments,
        packet_starts=packet_starts,
        conflicts=conflicts,
        holes=holes,
    )
