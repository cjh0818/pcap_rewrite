# -*- coding: utf-8 -*-
"""
通用工具函数：IP 校验、checksum 清理、偏移映射、Scapy 辅助操作等。
"""

import argparse
import difflib
import ipaddress
from loguru import logger
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Raw
from config import TCP_SEQ_MOD, TCP_SEQ_HALF, HTTP_HEADER_END


# =============================================================================
# IPv4 参数校验与预处理
# =============================================================================

def validate_ipv4(value, arg_name):
    """
    校验命令行中的 IPv4 参数。
    :param value: 待校验的 IP 字符串
    :param arg_name: 命令行参数名称，用于生成错误提示
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{arg_name} 不是合法 IP: {value}") from exc
    if ip.version != 4:
        raise argparse.ArgumentTypeError(f"{arg_name} 不是 IPv4: {value}")


def attach_ip_material(args):
    """
    预生成文本和 packed IPv4 替换材料，挂载到 args 对象上。
    后续所有模块通过 args.old_ip_bytes / args.new_ip_bin 等直接取用。
    """
    args.old_ip_bytes = args.old_ip.encode("ascii")
    args.new_ip_bytes = args.new_ip.encode("ascii")
    args.old_ip_bin = ipaddress.ip_address(args.old_ip).packed
    args.new_ip_bin = ipaddress.ip_address(args.new_ip).packed


# =============================================================================
# TCP 序列号工具（32 位环形空间运算）
# =============================================================================

def seq_offset(seq, base_seq):
    """
    将 TCP 绝对序列号转换为相对于流基准序列号的字节偏移。
    偏移量超过半个序列号空间说明序列号回绕或方向错误，返回 None。
    :param seq: TCP 绝对序列号
    :param base_seq: 当前 TCP 方向的流重组基准序列号
    """
    diff = (int(seq) - int(base_seq)) % TCP_SEQ_MOD
    if diff >= TCP_SEQ_HALF:
        return None
    return diff


def seq_add(base_seq, offset):
    """
    在 TCP 32 位环形序列号空间中执行加法。
    :param base_seq: 基准序列号
    :param offset: 相对字节偏移
    """
    return (int(base_seq) + int(offset)) % TCP_SEQ_MOD


# =============================================================================
# Scapy 派生字段清理（让 Scapy 在序列化时重新计算 len/chksum）
# =============================================================================

def safe_delattr(obj, names):
    """
    安全删除 Scapy 自动派生字段。
    删除后 Scapy 在 build() 时会重新计算 len/chksum 等字段。
    :param obj: Scapy 层对象（可能为 None）
    :param names: 要删除的字段名列表
    """
    if obj is None:
        return
    for name in names:
        try:
            delattr(obj, name)
        except (AttributeError, KeyError, TypeError, ValueError):
            continue


def clear_autofields(packet, ip_layer=None, l4_layer=None):
    """
    清理 IP/TCP/UDP/ICMP 的长度和校验和字段，交由 Scapy 写包时重算。
    :param packet: Scapy 数据包对象
    :param ip_layer: IP 层对象（可选）
    :param l4_layer: TCP/UDP/ICMP 层对象（可选）
    """
    safe_delattr(ip_layer, ("len", "plen", "chksum"))
    safe_delattr(l4_layer, ("len", "chksum"))
    # ICMP 也有独立的 checksum，payload 变化后需要重算。
    if ICMP in packet:
        safe_delattr(packet[ICMP], ("chksum",))
    try:
        # wirelen 是抓包时的原始线缆长度，payload 改写后已不可信。
        packet.wirelen = None
    except (AttributeError, TypeError):
        logger.debug("当前 Packet 不支持重置 wirelen，已跳过")


# =============================================================================
# TCP/UDP payload 读取（裁掉链路层 padding / 以太网尾部填充）
# =============================================================================

def real_tcp_payload(packet):
    """
    根据 IP.total_length 和 TCP.dataofs 计算真实 TCP payload，
    裁掉可能被 Scapy 误读的以太网尾部 padding。
    :param packet: Scapy 数据包对象
    """
    if TCP not in packet:
        return b""
    payload = bytes(packet[TCP].payload)
    if IP not in packet:
        return payload
    ip = packet[IP]
    tcp = packet[TCP]
    try:
        if ip.len is None or ip.ihl is None or tcp.dataofs is None:
            return payload
        # IP 总长度减去 IP 头长和 TCP 头长，得到真实 TCP 数据长度。
        payload_len = int(ip.len) - int(ip.ihl) * 4 - int(tcp.dataofs) * 4
    except (TypeError, ValueError):
        return payload
    if payload_len <= 0:
        return b""
    return payload[:payload_len]


def real_udp_payload(packet):
    """
    按 UDP.len 字段读取真实 UDP payload，裁掉以太网 padding。
    :param packet: Scapy 数据包对象
    """
    if UDP not in packet:
        return b""
    payload = bytes(packet[UDP].payload)
    try:
        udp_len = int(packet[UDP].len)
    except (TypeError, ValueError):
        return payload
    if udp_len < 8:
        return payload
    return payload[:max(0, udp_len - 8)]


# =============================================================================
# 传输层 payload 写入
# =============================================================================

def set_l4_payload(layer, payload):
    """
    用新的 Raw payload 覆盖传输层负载。
    :param layer: TCP/UDP 等 Scapy 层对象
    :param payload: 新的协议负载字节串
    """
    layer.remove_payload()
    if payload:
        layer.add_payload(Raw(payload))


# =============================================================================
# Payload 文本/二进制兜底替换
# =============================================================================

def replace_binary_ipv4(payload, args):
    """
    在 raw payload 中执行 packed IPv4 等长替换（4 字节二进制 IP）。
    :param payload: 协议负载字节串
    :param args: 命令行参数对象
    :return: (新payload, 是否发生了变化)
    """
    if args.old_ip_bin not in payload:
        return payload, False
    return payload.replace(args.old_ip_bin, args.new_ip_bin), True


def general_replace_payload(payload, args):
    """
    对无专用 handler 的 payload 执行文本(ASCII)和二进制(4字节)兜底替换。
    :param payload: 协议负载字节串
    :param args: 命令行参数对象
    :return: (新payload, 是否变化, 标签字符串)
    """
    labels = []
    new_payload = payload
    # 先尝试 ASCII 文本替换（如 b"10.0.0.1"）
    if args.old_ip_bytes in new_payload:
        new_payload = new_payload.replace(args.old_ip_bytes, args.new_ip_bytes)
        labels.append("ascii")
    # 再尝试 packed 二进制替换（4 字节大端 IP）
    binary_payload, bin_changed = replace_binary_ipv4(new_payload, args)
    if bin_changed:
        new_payload = binary_payload
        labels.append("binary")
    is_changed = new_payload != payload
    change_labels = "+".join(labels) if labels else "unchanged"
    return new_payload, is_changed, change_labels


# =============================================================================
# TCP 流编辑区间计算与偏移映射
# =============================================================================

def compute_edits(old, new):
    """
    使用 difflib 计算 old_stream 到 new_stream 的编辑区间列表。
    每个区间为 (old_start, old_end, replacement_bytes) 三元组。
    :param old: 改写前的原始字节串
    :param new: 改写后的目标字节串
    :return: 编辑区间列表，相等则返回空列表
    """
    if old == new:
        return []
    matcher = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    edits = []
    for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes():
        if tag == "equal":
            continue
        edits.append((old_start, old_end, new[new_start:new_end]))
    return edits


def map_offset(offset, edits):
    """
    把旧 TCP 流中的字节偏移映射到新 TCP 流中的对应偏移。
    遍历编辑区间，累加新旧流的长度差，直至定位到目标偏移。
    :param offset: 旧流中的字节偏移
    :param edits: compute_edits 返回的编辑区间列表
    :return: 新流中的对应字节偏移
    """
    delta = 0
    for start, end, replacement in edits:
        old_len = end - start
        new_len = len(replacement)
        if offset < start:
            break
        # 偏移正好落在编辑区间内部时，映射到区间起点 + 新内容中的相对位置。
        if offset >= end:
            delta += new_len - old_len
            continue
        return start + delta + min(offset - start, new_len)
    return offset + delta


# =============================================================================
# HTTP header 查找辅助
# =============================================================================

def find_http_header_end(data, start=0):
    """
    在字节串中查找 HTTP 头部结束标记 \\r\\n\\r\\n。
    :param data: 协议字节串
    :param start: 查找起始偏移
    :return: header_end 偏移，未找到返回 -1
    """
    return data.find(HTTP_HEADER_END, start)
