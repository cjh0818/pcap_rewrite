# -*- coding: utf-8 -*-
"""
Telnet 明文协议改写。

Telnet 数据流中可能夹杂 IAC 协商字节，但用户可见内容仍是无长度字段文本；
这里只替换 ASCII IPv4 文本，不执行 packed IPv4 兜底替换。
"""

from core.context import RewriteResult, is_port
from core.dispatcher import ProtocolHandler
from config import TELNET_PORT


TELNET_IAC = 0xFF


def looks_like_telnet(payload):
    """非标准端口下，仅在存在 Telnet IAC 协商字节时识别。"""
    return bool(payload) and TELNET_IAC in payload[:16]


class TelnetHandler(ProtocolHandler):
    """Telnet 明文协议改写处理器。"""

    name = "telnet"

    def detect(self, payload, ctx):
        if ctx.proto_name != "TCP" or not payload:
            return False
        return is_port(ctx, TELNET_PORT) or looks_like_telnet(payload)

    def rewrite(self, payload, ctx):
        if ctx.old_ip not in payload:
            return RewriteResult(True, False, payload, "telnet.unchanged")
        return RewriteResult(True, True, payload.replace(ctx.old_ip, ctx.new_ip), "telnet.ascii")
