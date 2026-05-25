# -*- coding: utf-8 -*-
"""
TCP Raw 兜底处理器：当所有结构化协议 handler 都无法识别时，
对 TCP payload 执行字节级文本/二进制替换。
"""

from core.context import RewriteResult
from core.dispatcher import ProtocolHandler
from core.utils import general_replace_payload


class RawTCPHandler(ProtocolHandler):
    """TCP Raw fallback：字节级兜底替换。"""

    name = "tcp.raw"
    requires_stream_merge = True

    def detect(self, payload, ctx):
        """TCP 协议永远可被 raw handler 兜底。"""
        return ctx.proto_name == "TCP"

    def rewrite(self, payload, ctx):
        """
        对 TCP payload 执行安全文本替换和非文本上下文 packed IPv4 兜底。
        """
        new_payload, changed, label = general_replace_payload(payload, ctx.args)
        return RewriteResult(True, changed, new_payload, f"{self.name}.{label}")
