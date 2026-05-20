# -*- coding: utf-8 -*-
"""
HTTP/2 识别与拒绝：HTTP/2 是二进制帧协议，暂不支持结构化替换。
"""

from core.context import RewriteResult
from core.dispatcher import ProtocolHandler
from config import HTTP2_CONNECTION_PREFACE


class HTTP2RejectHandler(ProtocolHandler):
    """HTTP/2 拒绝处理器：二进制帧协议暂不支持。"""

    name = "http2.reject"

    def detect(self, payload, ctx):
        """TCP 且以 HTTP/2 连接前导（connection preface）开头时命中。"""
        return ctx.proto_name == "TCP" and payload.startswith(HTTP2_CONNECTION_PREFACE)

    def rewrite(self, payload, ctx):
        """
        含旧 IP 时拒绝（二进制帧格式不支持裸文本替换），不含时安全跳过。
        """
        if ctx.old_ip in payload:
            return RewriteResult(False, False, payload, self.name, "http2.not_supported_with_ip")
        return RewriteResult(True, False, payload, self.name)
