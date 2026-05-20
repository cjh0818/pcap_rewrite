# -*- coding: utf-8 -*-
"""
统计对象：记录单文件及批处理的改写数量。
"""

from dataclasses import dataclass


@dataclass
class PacketStats:
    """
    统计单个 PCAP 或批处理总量，所有字段都是可累加计数器。
    """
    total_in: int = 0
    total_out: int = 0
    arp_changed: int = 0
    ipv4_changed: int = 0
    icmp_changed: int = 0
    udp_changed: int = 0
    tcp_stream_changed: int = 0
    tcp_packets_changed: int = 0
    tcp_inserted: int = 0
    tcp_deleted: int = 0
    failures: int = 0


def merge_stats(total, current):
    """
    把当前文件统计合并到批量总统计。
    :param total: 批量累计统计对象
    :param current: 当前文件统计对象
    """
    for field_name in total.__dict__:
        setattr(total, field_name, getattr(total, field_name) + getattr(current, field_name))
