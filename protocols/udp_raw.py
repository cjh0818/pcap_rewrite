# -*- coding: utf-8 -*-
"""
UDP Raw 兜底处理器：当 DTLS/QUIC 等 handler 无法识别时，
对 UDP payload 执行字节级文本/二进制替换。
"""

from core.context import RewriteResult
from core.dispatcher import ProtocolHandler
from core.utils import general_replace_payload


class RawUDPHandler(ProtocolHandler):
    """UDP Raw fallback：字节级兜底替换。"""

    name = "udp.raw"

    def detect(self, payload, ctx):
        """UDP 协议永远可被 raw handler 兜底。"""
        return ctx.proto_name == "UDP"

    def rewrite(self, payload, ctx):
        """
        对 UDP payload 执行安全文本替换和非文本上下文 packed IPv4 兜底。
        """
        new_payload, changed, label = general_replace_payload(payload, ctx.args)
        return RewriteResult(True, changed, new_payload, f"{self.name}.{label}")
