# -*- coding: utf-8 -*-
"""
TCP Raw 兜底处理器：当所有结构化协议 handler 都无法识别时，
对 TCP payload 执行字节级文本/二进制替换。
"""

from core.context import RewriteResult
from core.dispatcher import ProtocolHandler


class RawTCPHandler(ProtocolHandler):
    """TCP Raw fallback：字节级兜底替换。"""

    name = "tcp.raw"

    def detect(self, payload, ctx):
        """TCP 协议永远可被 raw handler 兜底。"""
        return ctx.proto_name == "TCP"

    def rewrite(self, payload, ctx):
        """
        对 TCP payload 执行 ASCII 文本和 packed 二进制替换。
        如果 --no-raw 开启且 payload 含旧 IP，则拒绝改写。
        """
        if ctx.old_ip not in payload:
            return RewriteResult(True, False, payload, self.name)
        if not ctx.allow_raw:
            return RewriteResult(False, False, payload, "tcp.raw.disabled", "old_ip_in_raw_payload")
        new_payload = payload.replace(ctx.old_ip, ctx.new_ip)
        return RewriteResult(True, True, new_payload, self.name)
