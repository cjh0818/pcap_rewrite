# -*- coding: utf-8 -*-
"""
DNS 协议改写：支持 UDP DNS message 和 TCP DNS length-prefixed message。

当前只改写 A 记录中的 IPv4 rdata。DNS name、TXT、EDNS 等字段含旧 IP 时跳过，
避免破坏压缩名称、长度前缀或二进制扩展字段。
畸形 / 不完整消息中含旧 IP 时原样保留并标记 skip，不抛异常回滚整条 TCP stream。
"""

from scapy.layers.dns import DNS

from core.context import RewriteError, RewriteResult, is_port
from core.dispatcher import ProtocolHandler
from core.utils import has_old_material, safe_delattr
from config import DNS_PORT


def looks_like_dns_message(payload):
    """
    粗略判断 payload 是否像 DNS message。
    DNS header 固定 12 字节，至少要有一个 question 或 RR。
    """
    if len(payload) < 12:
        return False
    try:
        qdcount = int.from_bytes(payload[4:6], "big")
        ancount = int.from_bytes(payload[6:8], "big")
        nscount = int.from_bytes(payload[8:10], "big")
        arcount = int.from_bytes(payload[10:12], "big")
    except (TypeError, ValueError):
        return False
    total = qdcount + ancount + nscount + arcount
    return 0 < total < 1024


def looks_like_tcp_dns(payload):
    """判断 TCP payload 是否像一个或多个 2 字节长度前缀的 DNS message。"""
    if len(payload) < 14:
        return False
    pos = 0
    while pos < len(payload):
        if pos + 2 > len(payload):
            return False
        msg_len = int.from_bytes(payload[pos:pos + 2], "big")
        if msg_len < 12 or pos + 2 + msg_len > len(payload):
            return False
        if not looks_like_dns_message(payload[pos + 2:pos + 2 + msg_len]):
            return False
        pos += 2 + msg_len
    return True


def iter_dns_rr(section):
    """Scapy 的 DNS RR section 可能是 _list，也可能是单个 DNSRR。"""
    if not section:
        return []
    if isinstance(section, list):
        return list(section)
    if hasattr(section, "rdata"):
        return [section]
    return []


def rewrite_dns_message(message, ctx):
    """
    改写一个 DNS message。返回 (payload, changed, label)。
    仅支持 A 记录 rdata 的 4 字节 IPv4 地址替换。
    畸形消息或不支持的记录中含旧 IP 时跳过而非抛异常。
    """
    if not looks_like_dns_message(message):
        if has_old_material(message, ctx):
            return message, False, "dns.invalid_message_skipped"
        return message, False, "dns.unchanged"

    dns = DNS(message)
    changed = False
    for section_name in ("an", "ns", "ar"):
        for rr in iter_dns_rr(getattr(dns, section_name, None)):
            if int(getattr(rr, "type", 0)) != 1:  # A
                continue
            if getattr(rr, "rdata", None) == ctx.args.old_ip:
                rr.rdata = ctx.args.new_ip
                safe_delattr(rr, ("rdlen",))
                changed = True

    if not changed:
        if has_old_material(message, ctx):
            return message, False, "dns.unsupported_field_skipped"
        return message, False, "dns.unchanged"

    new_message = bytes(dns)
    if ctx.old_ip_bin != ctx.new_ip_bin and has_old_material(new_message, ctx):
        raise RewriteError("dns.ip_remains_after_replace")
    return new_message, True, "dns"


def rewrite_tcp_dns(payload, ctx):
    """改写 TCP DNS length-prefixed message 序列。返回 (payload, changed, label)。"""
    out = bytearray()
    pos = 0
    changed = False
    skipped_incomplete_with_ip = False
    skipped_unsupported_with_ip = False

    while pos < len(payload):
        if pos + 2 > len(payload):
            tail = payload[pos:]
            if has_old_material(tail, ctx):
                skipped_incomplete_with_ip = True
            out.extend(tail)
            break
        msg_len = int.from_bytes(payload[pos:pos + 2], "big")
        end = pos + 2 + msg_len
        if msg_len < 12 or end > len(payload):
            tail = payload[pos:]
            if has_old_material(tail, ctx):
                skipped_incomplete_with_ip = True
            out.extend(tail)
            break
        new_msg, msg_changed, msg_label = rewrite_dns_message(payload[pos + 2:end], ctx)
        if "skipped" in msg_label:
            if "unsupported" in msg_label:
                skipped_unsupported_with_ip = True
            else:
                skipped_incomplete_with_ip = True
        out.extend(len(new_msg).to_bytes(2, "big"))
        out.extend(new_msg)
        changed = changed or msg_changed or len(new_msg) != msg_len
        pos = end

    if changed:
        if skipped_unsupported_with_ip or skipped_incomplete_with_ip:
            label = "dns.tcp+skipped"
        else:
            label = "dns.tcp"
    elif skipped_unsupported_with_ip:
        label = "dns.tcp.unsupported_skipped"
    elif skipped_incomplete_with_ip:
        label = "dns.tcp.incomplete_skipped"
    else:
        label = "dns.tcp.unchanged"

    return bytes(out), changed, label


class DNSHandler(ProtocolHandler):
    """DNS 协议改写处理器。"""

    name = "dns"

    def detect(self, payload, ctx):
        if not payload or ctx.proto_name not in {"TCP", "UDP"}:
            return False
        if is_port(ctx, DNS_PORT):
            return True
        if ctx.proto_name == "UDP":
            return looks_like_dns_message(payload)
        return looks_like_tcp_dns(payload)

    def rewrite(self, payload, ctx):
        if ctx.proto_name == "TCP":
            new_payload, changed, label = rewrite_tcp_dns(payload, ctx)
            return RewriteResult(True, changed, new_payload, label)
        new_payload, changed, label = rewrite_dns_message(payload, ctx)
        return RewriteResult(True, changed, new_payload, label)
