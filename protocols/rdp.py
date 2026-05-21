# -*- coding: utf-8 -*-
"""
RDP 识别与拒绝。

RDP 基于 TPKT/X.224，并通常升级到 TLS/CredSSP。应用数据为二进制或加密，
当前不做 IP 替换；命中旧 IP 时明确拒绝，避免 raw fallback 破坏协议。
"""

from core.context import RewriteResult, is_port
from core.dispatcher import ProtocolHandler
from core.utils import has_old_material
from config import RDP_PORT


def looks_like_tpkt(payload):
    """TPKT header: version=3, reserved=0, 2 字节总长度。"""
    if len(payload) < 4:
        return False
    if payload[0] != 0x03 or payload[1] != 0x00:
        return False
    pkt_len = int.from_bytes(payload[2:4], "big")
    return 4 <= pkt_len <= len(payload)


class RDPRejectHandler(ProtocolHandler):
    """RDP 拒绝处理器。"""

    name = "rdp.reject"

    def detect(self, payload, ctx):
        if ctx.proto_name != "TCP" or not payload:
            return False
        return is_port(ctx, RDP_PORT) or looks_like_tpkt(payload)

    def rewrite(self, payload, ctx):
        if has_old_material(payload, ctx):
            return RewriteResult(False, False, payload, self.name, "rdp.with_ip_not_supported")
        return RewriteResult(True, False, payload, "rdp.unchanged")
