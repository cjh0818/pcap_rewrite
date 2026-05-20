# -*- coding: utf-8 -*-
"""
ICMP 协议改写：处理 ICMP payload 及差错报文中的被引用 IPv4 header。
"""

from loguru import logger

from scapy.layers.inet import ICMP, IP, IPerror

from core.utils import (
    clear_autofields,
    replace_payload_literals,
    safe_delattr,
    set_l4_payload,
)


def rewrite_icmp(packet, index, args, stats):
    """
    改写 ICMP payload 或差错报文中引用的 IPv4 header。
    对于 IPerror（ICMP 差错报文），直接修改被引用的源/目的 IP；
    对于其他 ICMP，对 payload 执行文本/二进制兜底替换。
    :param packet: Scapy 数据包对象
    :param index: 帧序号（用于日志）
    :param args: 命令行参数对象
    :param stats: PacketStats 统计对象
    :return: 是否发生了改写
    """
    if not (IP in packet and ICMP in packet):
        return False

    changed = False
    icmp = packet[ICMP]
    # IPerror 是 ICMP 差错报文（如 Destination Unreachable）中引用的原始 IP 头
    if IPerror in icmp:
        quoted = icmp[IPerror]
        if quoted.src == args.old_ip:
            quoted.src = args.new_ip
            changed = True
        if quoted.dst == args.old_ip:
            quoted.dst = args.new_ip
            changed = True
        if changed:
            safe_delattr(quoted, ("len", "chksum"))
    else:
        # 非差错 ICMP（如 Echo Request/Reply）：对 payload 做文本/二进制替换
        old_payload = bytes(icmp.payload)
        new_payload, payload_changed, label = replace_payload_literals(old_payload, args)
        if payload_changed:
            set_l4_payload(icmp, new_payload)
            changed = True
            logger.info(f"帧#{index} ICMP payload[{label}] {len(old_payload)}->{len(new_payload)}")

    if changed:
        clear_autofields(packet, packet[IP], icmp)
        stats.icmp_changed += 1
    return changed
