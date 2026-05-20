# -*- coding: utf-8 -*-
"""
IPv4 header 改写：替换 IP 层 src/dst 地址字段。
"""

from loguru import logger
from scapy.layers.inet import IP, TCP, UDP
from core.utils import clear_autofields


def rewrite_ipv4_header(packet, index, args, stats):
    """
    改写 IPv4 header 的源/目的地址。
    修改后清除 IP 和 L4 的长度/校验和字段，交由 Scapy 重算。
    :param packet: Scapy 数据包对象
    :param index: 帧序号（用于日志）
    :param args: 命令行参数对象
    :param stats: PacketStats 统计对象
    :return: 是否发生了改写
    """
    if IP not in packet:
        return False
    ip = packet[IP]
    changed = False
    # 源 IP 匹配时替换
    if ip.src == args.old_ip:
        ip.src = args.new_ip
        changed = True
    # 目的 IP 匹配时替换
    if ip.dst == args.old_ip:
        ip.dst = args.new_ip
        changed = True
    if changed:
        # 确定 L4 层对象，用于清理其派生字段
        l4 = packet[TCP] if TCP in packet else packet[UDP] if UDP in packet else None
        clear_autofields(packet, ip, l4)
        stats.ipv4_changed += 1
        logger.info(f"帧#{index} IPv4 header {args.old_ip}->{args.new_ip}")
    return changed
