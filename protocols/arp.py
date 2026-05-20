# -*- coding: utf-8 -*-
"""
ARP 协议改写：替换 ARP 包中的 psrc/pdst IPv4 地址字段。
"""

from loguru import logger

from scapy.layers.l2 import ARP


def rewrite_arp(packet, index, args, stats):
    """
    改写 ARP 协议中的 IPv4 地址字段（psrc / pdst）。
    :param packet: Scapy 数据包对象
    :param index: 帧序号（用于日志）
    :param args: 命令行参数对象
    :param stats: PacketStats 统计对象
    :return: 是否发生了改写
    """
    if ARP not in packet:
        return False
    arp = packet[ARP]
    changed = False
    # 源协议地址匹配旧 IP 时替换为新 IP
    if arp.psrc == args.old_ip:
        arp.psrc = args.new_ip
        changed = True
    # 目的协议地址匹配旧 IP 时替换为新 IP
    if arp.pdst == args.old_ip:
        arp.pdst = args.new_ip
        changed = True
    if changed:
        stats.arp_changed += 1
        logger.info(f"帧#{index} ARP {args.old_ip}->{args.new_ip}")
    return changed
