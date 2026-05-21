# -*- coding: utf-8 -*-
"""
HTTP/2 识别与拒绝：HTTP/2 是二进制帧协议，header 使用 HPACK/QPACK 类压缩，
DATA/HEADERS 又有 frame length 和 stream 语义，当前不做结构化 IP 替换。
"""

from core.context import RewriteResult
from core.dispatcher import ProtocolHandler
from core.utils import has_old_material
from config import HTTP2_CONNECTION_PREFACE


HTTP2_FRAME_HEADER_LEN = 9
HTTP2_MAX_FRAME_LEN = 16384 + 16384
# 已知 HTTP/2 frame 类型：0x00-0x09 + 扩展帧
HTTP2_KNOWN_FRAME_TYPES = set(range(0x00, 0x0A)) | {0x0A, 0x0B, 0x0C}


def looks_like_http2_frames(payload):
    """
    粗略判断 payload 是否像 HTTP/2 frame 序列。
    无连接前导的一侧通常以 SETTINGS frame 开头。
    """
    if len(payload) < HTTP2_FRAME_HEADER_LEN:
        return False
    pos = 0
    first = True
    while pos < len(payload):
        if pos + HTTP2_FRAME_HEADER_LEN > len(payload):
            return False
        frame_len = int.from_bytes(payload[pos:pos + 3], "big")
        frame_type = payload[pos + 3]
        stream_id = int.from_bytes(payload[pos + 5:pos + 9], "big") & 0x7FFFFFFF
        if frame_len > HTTP2_MAX_FRAME_LEN or frame_type not in HTTP2_KNOWN_FRAME_TYPES:
            return False
        if first and (frame_type != 0x04 or stream_id != 0):  # 无前导时首帧应为 SETTINGS
            return False
        if pos + HTTP2_FRAME_HEADER_LEN + frame_len > len(payload):
            return False
        pos += HTTP2_FRAME_HEADER_LEN + frame_len
        first = False
    return True


class HTTP2RejectHandler(ProtocolHandler):
    """HTTP/2 拒绝处理器：二进制帧协议暂不支持。"""

    name = "http2.reject"

    def detect(self, payload, ctx):
        """TCP 且像 HTTP/2 connection preface 或 frame 序列时命中。"""
        if ctx.proto_name != "TCP" or not payload:
            return False
        if payload.startswith(HTTP2_CONNECTION_PREFACE):
            return True
        return looks_like_http2_frames(payload)

    def rewrite(self, payload, ctx):
        """
        含旧 IP 时拒绝（二进制帧格式不支持裸文本替换），不含时安全跳过。
        """
        if has_old_material(payload, ctx):
            return RewriteResult(False, False, payload, self.name, "http2.not_supported_with_ip")
        return RewriteResult(True, False, payload, self.name)
