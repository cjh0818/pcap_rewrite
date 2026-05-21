# -*- coding: utf-8 -*-
"""
DHCP/BOOTP 协议改写。

支持固定 IPv4 字段 ciaddr/yiaddr/siaddr/giaddr，以及 Scapy 已解析为
IPv4 字符串的 DHCP options。未能结构化定位但含旧 IP 的 DHCP payload 会拒绝。
"""

from scapy.layers.dhcp import BOOTP, DHCP

from core.context import RewriteError, RewriteResult, is_port
from core.dispatcher import ProtocolHandler
from core.utils import has_old_material
from config import DHCP_CLIENT_PORT, DHCP_SERVER_PORT


BOOTIP_FIELDS = ("ciaddr", "yiaddr", "siaddr", "giaddr")


def is_dhcp_port(ctx):
    """判断当前 UDP 端口是否为 DHCP/BOOTP 端口。"""
    return (
        ctx.sport() in {DHCP_SERVER_PORT, DHCP_CLIENT_PORT}
        or ctx.dport() in {DHCP_SERVER_PORT, DHCP_CLIENT_PORT}
    )


def looks_like_bootp(payload):
    """BOOTP 固定头 236 字节，DHCP 还会带 magic cookie。"""
    if len(payload) < 236:
        return False
    op = payload[0]
    hlen = payload[2]
    if op not in (1, 2) or hlen > 16:
        return False
    return True


def replace_option_value(value, ctx):
    """
    替换 Scapy DHCP option 中已解析出的 IPv4 字符串。
    tuple/list 会递归处理，用于 router/name_server 这类多地址 option。
    """
    if isinstance(value, str):
        return (ctx.args.new_ip, True) if value == ctx.args.old_ip else (value, False)
    if isinstance(value, tuple):
        changed = False
        items = []
        for item in value:
            new_item, item_changed = replace_option_value(item, ctx)
            items.append(new_item)
            changed = changed or item_changed
        return tuple(items), changed
    if isinstance(value, list):
        changed = False
        items = []
        for item in value:
            new_item, item_changed = replace_option_value(item, ctx)
            items.append(new_item)
            changed = changed or item_changed
        return items, changed
    return value, False


def rewrite_dhcp_payload(payload, ctx):
    """改写 BOOTP/DHCP payload。"""
    if not looks_like_bootp(payload):
        if has_old_material(payload, ctx):
            raise RewriteError("dhcp.invalid_bootp_with_ip")
        return payload, False

    bootp = BOOTP(payload)
    changed = False
    for field in BOOTIP_FIELDS:
        if getattr(bootp, field, None) == ctx.args.old_ip:
            setattr(bootp, field, ctx.args.new_ip)
            changed = True

    if DHCP in bootp:
        new_options = []
        for option in bootp[DHCP].options:
            if isinstance(option, tuple):
                option_name = option[0]
                new_values, opt_changed = replace_option_value(option[1:], ctx)
                new_options.append((option_name,) + new_values)
                changed = changed or opt_changed
            else:
                new_options.append(option)
        bootp[DHCP].options = new_options

    if not changed:
        if has_old_material(payload, ctx):
            raise RewriteError("dhcp.old_ip_not_in_supported_field")
        return payload, False

    new_payload = bytes(bootp)
    if ctx.old_ip_bin != ctx.new_ip_bin and has_old_material(new_payload, ctx):
        raise RewriteError("dhcp.ip_remains_after_replace")
    return new_payload, True


class DHCPHandler(ProtocolHandler):
    """DHCP/BOOTP 协议改写处理器。"""

    name = "dhcp"

    def detect(self, payload, ctx):
        return ctx.proto_name == "UDP" and payload and (is_dhcp_port(ctx) or looks_like_bootp(payload))

    def rewrite(self, payload, ctx):
        new_payload, changed = rewrite_dhcp_payload(payload, ctx)
        return RewriteResult(True, changed, new_payload, "dhcp" if changed else "dhcp.unchanged")
