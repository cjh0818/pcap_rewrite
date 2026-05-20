# -*- coding: utf-8 -*-
"""
QUIC 识别与拒绝：QUIC 是加密协议，无法安全替换。
"""

from core.context import RewriteResult
from core.dispatcher import ProtocolHandler
from config import COMMON_QUIC_PORTS


def looks_like_quic(payload, ctx):
    """
    判断 UDP payload 是否像 QUIC long header。
    QUIC long header 首字节最高位为 1，且端口是常见 QUIC 端口。
    :param payload: 协议负载字节串
    :param ctx: RewriteContext
    """
    if not payload:
        return False
    # 非 443/8443 端口降低误判率
    if ctx.sport() not in COMMON_QUIC_PORTS and ctx.dport() not in COMMON_QUIC_PORTS:
        return False
    return bool(payload[0] & 0x80)


class QUICRejectHandler(ProtocolHandler):
    """QUIC 拒绝处理器：QUIC 加密无法安全替换。"""

    name = "quic.reject"

    def detect(self, payload, ctx):
        """UDP 且头部像 QUIC long header 时命中。"""
        return ctx.proto_name == "UDP" and looks_like_quic(payload, ctx)

    def rewrite(self, payload, ctx):
        """含旧 IP 时拒绝，不含时安全跳过。"""
        if ctx.old_ip in payload:
            return RewriteResult(False, False, payload, self.name, "quic.with_ip_not_supported")
        return RewriteResult(True, False, payload, "quic.unchanged")
