# -*- coding: utf-8 -*-
"""
DTLS 识别与拒绝：DTLS 是加密协议，无法安全替换，
含旧 IP 时明确拒绝，不含时跳过。
"""

from core.context import RewriteResult
from core.dispatcher import ProtocolHandler
from config import TLS_CONTENT_TYPES


def looks_like_dtls(payload):
    """
    判断 UDP payload 是否像 DTLS record。
    DTLS 记录头：1 字节 ContentType + 2 字节版本(0xFEFD/0xFEFF) + ...
    :param payload: 协议负载字节串
    """
    if len(payload) < 13:
        return False
    return payload[0] in TLS_CONTENT_TYPES and payload[1] == 0xFE and payload[2] in (0xFF, 0xFD)


class DTLSRejectHandler(ProtocolHandler):
    """DTLS 拒绝处理器：DTLS 加密无法安全替换。"""

    name = "dtls.reject"

    def detect(self, payload, ctx):
        """UDP 且头部像 DTLS 时命中。"""
        return ctx.proto_name == "UDP" and looks_like_dtls(payload)

    def rewrite(self, payload, ctx):
        """含旧 IP 时拒绝，不含时安全跳过。"""
        if ctx.old_ip in payload:
            return RewriteResult(False, False, payload, self.name, "dtls.with_ip_not_supported")
        return RewriteResult(True, False, payload, "dtls.unchanged")
