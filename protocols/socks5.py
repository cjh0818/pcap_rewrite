# -*- coding: utf-8 -*-
"""
SOCKS5 协议改写：替换请求中的 IPv4 地址（ATYP=0x01）和域名（ATYP=0x03）中的 IP 文本。
支持 Greeting 和 Request 消息的识别。
"""

from core.context import RewriteError, RewriteResult, is_port
from core.dispatcher import ProtocolHandler
from config import SOCKS_PORT


class SOCKS5Handler(ProtocolHandler):
    """SOCKS5 协议改写处理器。"""

    name = "socks5"

    def detect(self, payload, ctx):
        """TCP 且端口=1080 或首字节为 0x05(SOCKS5 VER)。"""
        if ctx.proto_name != "TCP" or len(payload) < 2:
            return False
        if is_port(ctx, SOCKS_PORT):
            return True
        return payload[0] == 0x05 and len(payload) >= 3

    def rewrite(self, payload, ctx):
        """
        Greeting 无地址字段直接跳过。
        Request 按 ATYP 分别处理：
        - 0x01(IPv4): 等长替换 4 字节二进制 IP
        - 0x03(Domain): 在域名中替换 IP 文本，更新域名长度
        - 0x04(IPv6): 拒绝
        """
        # Greeting: VER(1) + NMETHODS(1) + METHODS(N) — 无地址字段
        if len(payload) >= 2 and payload[0] == 0x05 and len(payload) == 2 + payload[1]:
            return RewriteResult(True, False, payload, "socks5.greeting")

        # Request: VER CMD RSV ATYP ADDR PORT
        if len(payload) < 7 or payload[0] != 0x05:
            if ctx.old_ip in payload:
                raise RewriteError("socks5.unrecognized_with_ip")
            return RewriteResult(True, False, payload, "socks5.unrecognized_without_ip")

        atyp = payload[3]
        pos = 4
        changed = False

        if atyp == 0x01:  # IPv4 二进制，固定 4 字节
            if len(payload) < pos + 4 + 2:
                raise RewriteError("socks5.ipv4_request_incomplete")
            addr = payload[pos:pos + 4]
            if addr == ctx.old_ip_bin:
                # 等长替换 packed IPv4
                payload = payload[:pos] + ctx.new_ip_bin + payload[pos + 4:]
                changed = True
            label = "socks5.ipv4" if changed else "socks5.ipv4.unchanged"
            return RewriteResult(True, changed, payload, label)

        if atyp == 0x03:  # 域名：1 字节长度 + 域名 + 2 字节端口
            if len(payload) < pos + 1:
                raise RewriteError("socks5.domain_missing_len")
            dom_len = payload[pos]
            dom_start = pos + 1
            dom_end = dom_start + dom_len
            if len(payload) < dom_end + 2:
                raise RewriteError("socks5.domain_request_incomplete")
            domain = payload[dom_start:dom_end]
            new_domain = domain.replace(ctx.old_ip, ctx.new_ip)
            if len(new_domain) > 255:
                raise RewriteError("socks5.domain_too_long_after_replace")
            if new_domain != domain:
                payload = payload[:pos] + bytes([len(new_domain)]) + new_domain + payload[dom_end:]
                changed = True
            label = "socks5.domain" if changed else "socks5.domain.unchanged"
            return RewriteResult(True, changed, payload, label)

        if atyp == 0x04:  # IPv6
            if ctx.old_ip in payload:
                raise RewriteError("socks5.ipv6_with_ascii_ip_not_supported")
            return RewriteResult(True, False, payload, "socks5.ipv6.unchanged")

        if ctx.old_ip in payload:
            raise RewriteError(f"socks5.atyp_{atyp:#x}_with_ip_not_supported")
        return RewriteResult(True, False, payload, "socks5.unchanged")
