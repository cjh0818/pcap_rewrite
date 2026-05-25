# -*- coding: utf-8 -*-
"""
WebSocket 协议改写：解析 WebSocket frame，对 text(opcode=0x1) 消息
执行 IP 文本替换，并正确处理 mask 和长度字段。
"""

from core.context import RewriteError, RewriteResult
from core.dispatcher import ProtocolHandler
from core.utils import contains_ip_text_boundary, replace_ip_text_boundary


def websocket_state_established(ctx):
    """
    判断 TCP 连接是否已通过 HTTP Upgrade 建立 WebSocket。
    状态由 HTTP/1.x handler 在处理 101 Switching Protocols 时写入。
    """
    return bool(ctx.tcp_state().get("websocket_established"))


def apply_ws_mask(data, mask_key):
    """
    WebSocket mask 操作：mask 和解 mask 使用同一个 XOR 算法。
    :param data: 待 mask/unmask 的数据
    :param mask_key: 4 字节 mask key
    """
    return bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))


def encode_ws_length(length):
    """
    编码 WebSocket payload length 字段：
    <126: 1 字节；126-65535: 3 字节(0x7E+2字节)；>65535: 9 字节(0x7F+8字节)
    """
    if length < 126:
        return bytes([length])
    if length <= 0xFFFF:
        return bytes([126]) + length.to_bytes(2, "big")
    return bytes([127]) + length.to_bytes(8, "big")


def rewrite_websocket_frames(payload, ctx):
    """
    解析并改写完整 WebSocket frame 序列。
    仅支持 text(opcode=0x1) 且未分片(fin=1) 的消息替换。
    permessage-deflate 压缩模式下拒绝替换。
    """
    state = ctx.tcp_state()
    # permessage-deflate 需要按消息边界解压，包级处理不安全
    if state.get("websocket_permessage_deflate"):
        if contains_ip_text_boundary(payload, ctx.old_ip):
            raise RewriteError("websocket.permessage_deflate_with_ip")
        return payload

    out = bytearray()
    pos = 0
    n = len(payload)

    while pos < n:
        if pos + 2 > n:
            raise RewriteError("websocket.incomplete_header")
        b1 = payload[pos]
        b2 = payload[pos + 1]
        pos += 2

        # 解析 frame header
        fin = bool(b1 & 0x80)       # 是否为最后一帧
        rsv = b1 & 0x70              # RSV 位（扩展用）
        opcode = b1 & 0x0F           # 操作码
        masked = bool(b2 & 0x80)     # 是否有 mask
        length_code = b2 & 0x7F      # payload 长度编码

        if rsv:
            raise RewriteError("websocket.rsv_set_not_supported")

        # 解析 payload 长度（变长编码）
        if length_code < 126:
            length = length_code
        elif length_code == 126:
            if pos + 2 > n:
                raise RewriteError("websocket.incomplete_len16")
            length = int.from_bytes(payload[pos:pos + 2], "big")
            pos += 2
        else:
            if pos + 8 > n:
                raise RewriteError("websocket.incomplete_len64")
            length = int.from_bytes(payload[pos:pos + 8], "big")
            pos += 8

        # 读取 mask key（仅客户端→服务端需要 mask）
        mask_key = b""
        if masked:
            if pos + 4 > n:
                raise RewriteError("websocket.incomplete_mask")
            mask_key = payload[pos:pos + 4]
            pos += 4

        if pos + length > n:
            raise RewriteError("websocket.incomplete_payload")

        raw_frame_payload = payload[pos:pos + length]
        pos += length
        # 如果有 mask 则先解 mask 得到明文
        decoded = apply_ws_mask(raw_frame_payload, mask_key) if masked else raw_frame_payload

        # 控制帧 (Close/Ping/Pong) 含旧 IP 原样保留，不影响同 stream 的 text frame
        if opcode in {0x8, 0x9, 0xA}:
            new_decoded = decoded
        elif contains_ip_text_boundary(decoded, ctx.old_ip):
            if not fin:
                raise RewriteError("websocket.fragmented_text_with_ip_not_supported")
            if opcode == 0x1:
                new_decoded, _ = replace_ip_text_boundary(decoded, ctx.old_ip, ctx.new_ip)
            elif opcode == 0x2:
                raise RewriteError("websocket.binary_with_ip_not_supported")
            else:
                raise RewriteError(f"websocket.opcode_{opcode:#x}_with_ip_not_supported")
        else:
            new_decoded = decoded

        # 重新 mask（如果需要）并构造新 frame
        new_payload_data = apply_ws_mask(new_decoded, mask_key) if masked else new_decoded
        out.append(b1)
        len_bytes = encode_ws_length(len(new_decoded))
        if masked:
            out.append(len_bytes[0] | 0x80)
            out.extend(len_bytes[1:])
            out.extend(mask_key)
        else:
            out.extend(len_bytes)
        out.extend(new_payload_data)

    return bytes(out)


class WebSocketHandler(ProtocolHandler):
    """WebSocket 协议改写处理器。"""

    name = "websocket"

    def detect(self, payload, ctx):
        """TCP 且连接已通过 HTTP Upgrade 建立 WebSocket 时命中。"""
        return ctx.proto_name == "TCP" and websocket_state_established(ctx) and bool(payload)

    def rewrite(self, payload, ctx):
        """调用 rewrite_websocket_frames 对 frame 序列进行改写。"""
        new_payload = rewrite_websocket_frames(payload, ctx)
        return RewriteResult(True, new_payload != payload, new_payload, self.name)
