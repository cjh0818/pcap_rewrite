# -*- coding: utf-8 -*-
"""
HTTP/1.x 协议改写：支持 Content-Length、chunked、gzip/deflate 编码的 body 替换。
同时负责 WebSocket Upgrade 状态切换。
"""

import gzip
import zlib

from core.context import RewriteError, RewriteResult
from core.dispatcher import ProtocolHandler
from core.utils import replace_payload_literals
from config import (
    HTTP_HEADER_END,
    HTTP2_CONNECTION_PREFACE,
    HTTP1_REQUEST_LINE_RE,
    HTTP1_RESPONSE_LINE_RE,
    HTTP_REQUEST_RE,
    HTTP_RESPONSE_RE,
)


# =============================================================================
# HTTP/1.x 头部解析与序列化
# =============================================================================

def looks_like_http1(payload):
    """
    判断字节串是否像 HTTP/1.x 消息起点。
    检查是否存在 \\r\\n\\r\\n 且第一行为合法请求行或响应行。
    """
    header_end = payload.find(HTTP_HEADER_END)
    if header_end < 0:
        return False
    first_line = payload[:header_end].split(b"\r\n", 1)[0]
    return bool(HTTP1_REQUEST_LINE_RE.match(first_line) or HTTP1_RESPONSE_LINE_RE.match(first_line))


def parse_http1_headers(header_block):
    """
    解析 HTTP/1.x 头部块为 (start_line, headers_list)。
    每行 header 拆为 (name, value) 元组并 strip 空白。
    """
    lines = header_block.split(b"\r\n")
    if not lines:
        raise RewriteError("http.empty_header")
    start_line = lines[0]
    if not (HTTP1_REQUEST_LINE_RE.match(start_line) or HTTP1_RESPONSE_LINE_RE.match(start_line)):
        raise RewriteError("http.invalid_start_line")

    headers = []
    for line in lines[1:]:
        if not line:
            continue
        # 过时的行折叠（obs-fold）不支持
        if line.startswith((b" ", b"\t")):
            raise RewriteError("http.obs_fold_not_supported")
        if b":" not in line:
            raise RewriteError("http.invalid_header_line")
        name, value = line.split(b":", 1)
        headers.append((name.strip(), value.strip()))
    return start_line, headers


def serialize_http1_headers(start_line, headers):
    """
    将 start_line 和 headers 序列化为 HTTP/1.x 头部字节串（含结尾空行）。
    """
    out = bytearray(start_line + b"\r\n")
    for name, value in headers:
        out.extend(name)
        out.extend(b": ")
        out.extend(value)
        out.extend(b"\r\n")
    out.extend(b"\r\n")
    return bytes(out)


# =============================================================================
# HTTP 头部操作辅助
# =============================================================================

def header_values(headers, name):
    """读取指定 HTTP 头部的所有值（大小写不敏感）。"""
    lname = name.lower()
    return [value for hname, value in headers if hname.lower() == lname]


def set_header(headers, name, value):
    """
    设置或追加指定 HTTP 头部。
    如果已存在同名头部，替换第一个；否则追加到末尾。
    """
    lname = name.lower()
    output = []
    inserted = False
    for hname, hvalue in headers:
        if hname.lower() == lname:
            if not inserted:
                output.append((hname, value))
                inserted = True
            continue
        output.append((hname, hvalue))
    if not inserted:
        output.append((name, value))
    return output


def remove_header(headers, name):
    """删除指定 HTTP 头部（大小写不敏感）。"""
    lname = name.lower()
    return [(hname, value) for hname, value in headers if hname.lower() != lname]


def has_token_header(headers, name, token):
    """
    判断逗号分隔 HTTP 头部值中是否包含指定 token（大小写不敏感）。
    例如 Transfer-Encoding: chunked, gzip 中检查 chunked。
    """
    token = token.lower()
    for value in header_values(headers, name):
        parts = [p.strip().lower() for p in value.split(b",")]
        if token in parts:
            return True
    return False


def get_single_content_length(headers):
    """
    读取唯一有效的 Content-Length。
    多个值不一致时拒绝改写。
    """
    values = header_values(headers, b"Content-Length")
    if not values:
        return None
    parsed = []
    for value in values:
        if not value.strip().isdigit():
            raise RewriteError("http.invalid_content_length")
        parsed.append(int(value.strip()))
    if len(set(parsed)) != 1:
        raise RewriteError("http.conflicting_content_length")
    return parsed[0]


def get_content_encoding(headers):
    """读取 Content-Encoding（取最后一个值）。"""
    values = header_values(headers, b"Content-Encoding")
    if not values:
        return None
    return values[-1].strip().lower()


# =============================================================================
# HTTP/1.x start-line 判断
# =============================================================================

def is_http_request_line(start_line):
    """判断 HTTP start-line 是否为请求行（GET /path HTTP/1.1）。"""
    return bool(HTTP1_REQUEST_LINE_RE.match(start_line))


def is_http_response_line(start_line):
    """判断 HTTP start-line 是否为响应行（HTTP/1.1 200 OK）。"""
    return bool(HTTP1_RESPONSE_LINE_RE.match(start_line))


# =============================================================================
# Chunked Transfer-Encoding 解析与构造
# =============================================================================

def parse_chunked_body(data):
    """
    解析 HTTP chunked body。
    返回 (body_bytes, trailer_block, consumed_len)。
    """
    pos = 0
    n = len(data)
    body_out = bytearray()

    while True:
        # 读取 chunk-size 行（十六进制）
        line_end = data.find(b"\r\n", pos)
        if line_end < 0:
            raise RewriteError("http.chunked.missing_size_crlf")
        size_line = data[pos:line_end]
        pos = line_end + 2

        # chunk-extension 忽略
        if b";" in size_line:
            size_token = size_line.split(b";", 1)[0]
        else:
            size_token = size_line
        size_token = size_token.strip()
        if not size_token:
            raise RewriteError("http.chunked.empty_size")
        try:
            chunk_size = int(size_token, 16)
        except ValueError as exc:
            raise RewriteError("http.chunked.invalid_size") from exc

        # chunk-size=0 表示最后一个 chunk
        if chunk_size == 0:
            # 可能是 trailer 或直接结束
            if pos + 2 <= n and data[pos:pos + 2] == b"\r\n":
                return bytes(body_out), b"", pos + 2
            trailer_end = data.find(b"\r\n\r\n", pos)
            if trailer_end < 0:
                raise RewriteError("http.chunked.trailer_incomplete")
            trailer = data[pos:trailer_end]
            return bytes(body_out), trailer, trailer_end + 4

        if pos + chunk_size + 2 > n:
            raise RewriteError("http.chunked.data_incomplete")
        chunk_data = data[pos:pos + chunk_size]
        if data[pos + chunk_size:pos + chunk_size + 2] != b"\r\n":
            raise RewriteError("http.chunked.missing_data_crlf")
        body_out.extend(chunk_data)
        pos += chunk_size + 2


def build_chunked_body(body, trailer_block=b""):
    """
    重新构造 HTTP chunked body（含末尾 0\r\n 和可选 trailer）。
    """
    if body:
        out = format(len(body), "x").encode("ascii") + b"\r\n" + body + b"\r\n"
    else:
        out = b""
    out += b"0\r\n"
    if trailer_block:
        out += trailer_block + b"\r\n\r\n"
    else:
        out += b"\r\n"
    return out


# =============================================================================
# HTTP Body 编码处理（gzip/deflate/identity）
# =============================================================================

def gzip_compress_stable(data):
    """
    使用固定参数（mtime=0）压缩 gzip body，确保输出稳定可复现。
    """
    try:
        return gzip.compress(data, mtime=0)
    except TypeError:  # 极老 Python 兼容
        return gzip.compress(data)


def replace_body_with_encoding(body, content_encoding, old_ip, new_ip):
    """
    按 Content-Encoding 解压 body → 替换 IP → 重压缩。
    支持 identity、gzip、deflate（含 raw deflate）。
    不支持的编码（br/zstd）含旧 IP 时拒绝。
    :return: (新body, 是否变化, 编码标签)
    """
    enc = (content_encoding or b"identity").strip().lower()
    if enc in (b"", b"identity"):
        new_body = body.replace(old_ip, new_ip)
        return new_body, new_body != body, "identity"

    if enc in (b"gzip", b"x-gzip"):
        try:
            plain = gzip.decompress(body)
        except (EOFError, OSError, zlib.error) as exc:
            raise RewriteError(f"http.gzip.decompress_failed:{exc}") from exc
        if old_ip not in plain:
            return body, False, "gzip"
        new_plain = plain.replace(old_ip, new_ip)
        return gzip_compress_stable(new_plain), True, "gzip"

    if enc == b"deflate":
        raw_mode = False
        try:
            # 先尝试标准 zlib 解压（带 header）
            plain = zlib.decompress(body)
        except zlib.error:
            try:
                # 再尝试 raw deflate（无 header，如某些老旧服务器）
                plain = zlib.decompress(body, -zlib.MAX_WBITS)
                raw_mode = True
            except zlib.error as exc:
                raise RewriteError(f"http.deflate.decompress_failed:{exc}") from exc
        if old_ip not in plain:
            return body, False, "deflate"
        new_plain = plain.replace(old_ip, new_ip)
        if raw_mode:
            compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
            return compressor.compress(new_plain) + compressor.flush(), True, "deflate.raw"
        return zlib.compress(new_plain), True, "deflate"

    # br/zstd 等暂不支持
    if old_ip in body:
        raise RewriteError(f"http.unsupported_content_encoding.{enc!r}_with_ip")
    return body, False, f"unsupported_encoding.{enc!r}.skipped"


# =============================================================================
# WebSocket Upgrade 状态管理
# =============================================================================

def update_websocket_state_after_http(start_line, headers, ctx):
    """
    检测 HTTP Upgrade 到 WebSocket 的请求/响应，写入连接共享状态。
    只有 TCP 连接下才会写入状态（UDP 无 WebSocket）。
    """
    if ctx.proto_name != "TCP" or ctx.flow_state is None or ctx.conn_key is None:
        return
    state = ctx.tcp_state()

    upgrade_ws = has_token_header(headers, b"Upgrade", b"websocket")
    conn_upgrade = has_token_header(headers, b"Connection", b"upgrade")
    permessage_deflate = False
    for value in header_values(headers, b"Sec-WebSocket-Extensions"):
        if b"permessage-deflate" in value.lower():
            permessage_deflate = True

    # 客户端 WebSocket Upgrade 请求
    if is_http_request_line(start_line) and upgrade_ws and conn_upgrade:
        state["websocket_pending"] = True
        if permessage_deflate:
            state["websocket_permessage_deflate"] = True

    # 服务端 101 Switching Protocols 响应
    if is_http_response_line(start_line) and start_line.startswith(b"HTTP/1.1 101") and upgrade_ws:
        state["websocket_established"] = True
        state.pop("websocket_pending", None)
        if permessage_deflate:
            state["websocket_permessage_deflate"] = True


# =============================================================================
# 单个 HTTP/1.x 消息改写
# =============================================================================

def replace_one_http1_message(data, start, ctx):
    """
    改写单个完整 HTTP/1.x 消息（请求或响应）。
    处理 Content-Length / chunked / close-delimited 三种 body 定界方式。
    :return: (新消息字节串, 消耗的字节数, 标签后缀)
    """
    header_end = data.find(HTTP_HEADER_END, start)
    if header_end < 0:
        raise RewriteError("http.header_incomplete")

    header_block = data[start:header_end]
    body_start = header_end + 4
    start_line, headers = parse_http1_headers(header_block)

    is_request = is_http_request_line(start_line)
    is_response = is_http_response_line(start_line)
    if not is_request and not is_response:
        raise RewriteError("http.unknown_start_line")

    old_ip = ctx.old_ip
    new_ip = ctx.new_ip

    # start-line 和 header values 中的 IP 文本直接替换
    new_start_line = start_line.replace(old_ip, new_ip)
    new_headers = [(name, value.replace(old_ip, new_ip)) for name, value in headers]

    is_chunked = has_token_header(headers, b"Transfer-Encoding", b"chunked")
    content_length = get_single_content_length(headers)
    content_encoding = get_content_encoding(headers)

    label_suffix = ""
    if is_chunked:
        # chunked + Content-Length 同时存在时，删除 Content-Length（RFC 7230）
        new_headers = remove_header(new_headers, b"Content-Length")
        body_bytes, trailer_block, consumed_body_len = parse_chunked_body(data[body_start:])
        original_body_segment = data[body_start:body_start + consumed_body_len]
        new_body_bytes, body_changed, enc_label = replace_body_with_encoding(
            body_bytes, content_encoding, old_ip, new_ip,
        )
        new_trailer = trailer_block.replace(old_ip, new_ip)
        trailer_changed = new_trailer != trailer_block
        if body_changed or trailer_changed:
            new_body = build_chunked_body(new_body_bytes, new_trailer)
            label_suffix = f"chunked.{enc_label}"
        else:
            new_body = original_body_segment
            label_suffix = f"chunked.{enc_label}.unchanged"
        consumed = (body_start - start) + consumed_body_len

    elif content_length is not None:
        body_end = body_start + content_length
        if body_end > len(data):
            raise RewriteError("http.body_incomplete")
        message_body = data[body_start:body_end]
        new_body, body_changed, enc_label = replace_body_with_encoding(
            message_body, content_encoding, old_ip, new_ip,
        )
        if body_changed:
            new_headers = set_header(new_headers, b"Content-Length", str(len(new_body)).encode("ascii"))
        else:
            new_headers = set_header(new_headers, b"Content-Length", str(len(message_body)).encode("ascii"))
        label_suffix = f"cl.{enc_label}"
        consumed = body_end - start

    else:
        # 无长度头：请求无 body；响应视为 close-delimited（读到流末尾）
        if is_request:
            new_body = b""
            consumed = body_start - start
            label_suffix = "no_body"
        else:
            message_body = data[body_start:]
            new_body, _, enc_label = replace_body_with_encoding(
                message_body, content_encoding, old_ip, new_ip,
            )
            consumed = len(data) - start
            label_suffix = f"close_delimited.{enc_label}"

    # 检测并更新 WebSocket 状态
    update_websocket_state_after_http(start_line, headers, ctx)

    new_header_block = serialize_http1_headers(new_start_line, new_headers)
    return new_header_block + new_body, consumed, label_suffix


# =============================================================================
# HTTP/1.x 消息序列改写（流级入口）
# =============================================================================

def replace_in_http1(payload, ctx):
    """
    改写一个 payload 中的 HTTP/1.x 消息序列。
    逐消息解析并替换 IP。
    :return: (新payload, 标签字符串)
    """
    if payload.startswith(HTTP2_CONNECTION_PREFACE):
        raise RewriteError("http2.not_supported")

    output = bytearray()
    pos = 0
    n = len(payload)
    labels = []

    while pos < n:
        rest = payload[pos:]
        if not looks_like_http1(rest):
            if ctx.old_ip in rest:
                raise RewriteError("http.trailing_unparsed_bytes_with_ip")
            output.extend(rest)
            break

        new_msg, consumed, label = replace_one_http1_message(payload, pos, ctx)
        if consumed <= 0:
            raise RewriteError("http.zero_consumed")
        output.extend(new_msg)
        labels.append(label)
        pos += consumed

    new_payload = bytes(output)
    if ctx.old_ip not in ctx.new_ip and ctx.old_ip in new_payload:
        raise RewriteError("http.ip_remains_after_replace")
    return new_payload, "+".join(labels) if labels else "http1"


# =============================================================================
# HTTP/1.x 流级安全改写（含 WebSocket 切换）
# =============================================================================

def rewrite_upgrade_header_only(data, start, ctx):
    """
    只改写 WebSocket Upgrade 的 HTTP 头部，停在 \\r\\n\\r\\n 之后。
    用于流级处理时在 Upgrade 消息后切换到 WebSocket handler。
    """
    header_end = data.find(HTTP_HEADER_END, start)
    if header_end < 0:
        raise RewriteError("http.upgrade_header_incomplete")
    header_block = data[start:header_end]
    start_line, headers = parse_http1_headers(header_block)
    new_start_line = start_line.replace(ctx.old_ip, ctx.new_ip)
    new_headers = [(name, value.replace(ctx.old_ip, ctx.new_ip)) for name, value in headers]
    update_websocket_state_after_http(start_line, headers, ctx)
    consumed = header_end + len(HTTP_HEADER_END) - start
    return serialize_http1_headers(new_start_line, new_headers), consumed, "http1.websocket_upgrade"


def rewrite_http1_stream_safe(stream, ctx, args):
    """
    在完整 TCP 流上安全改写 HTTP/1.x 消息序列。
    处理 WebSocket Upgrade 后的协议切换：Upgrade 消息之后的数据交给 WebSocket handler。
    :return: RewriteResult
    """
    from protocols.websocket import rewrite_websocket_frames

    output = bytearray()
    pos = 0
    labels = []
    changed = False

    while pos < len(stream):
        rest = stream[pos:]
        ws_state = ctx.tcp_state()

        # 已建立或正在建立 WebSocket 时，切换到 WebSocket handler
        if ws_state.get("websocket_established") or ws_state.get("websocket_pending"):
            new_ws = rewrite_websocket_frames(rest, ctx)
            output.extend(new_ws)
            changed = changed or new_ws != rest
            labels.append("websocket")
            pos = len(stream)
            break

        if not looks_like_http1(rest):
            new_tail, tail_changed, label = replace_payload_literals(rest, args)
            if tail_changed:
                changed = True
                labels.append(f"tail.{label}")
            output.extend(new_tail)
            break

        header_end = stream.find(HTTP_HEADER_END, pos)
        if header_end < 0:
            if ctx.old_ip in rest:
                return RewriteResult(False, False, stream, "http1.stream", "http.header_incomplete")
            output.extend(rest)
            break

        header_block = stream[pos:header_end]
        start_line, headers = parse_http1_headers(header_block)

        # Upgrade 响应只改写头部，后续数据交给 WebSocket handler
        if (
            is_http_response_line(start_line)
            and start_line.startswith(b"HTTP/1.1 101")
            and has_token_header(headers, b"Upgrade", b"websocket")
        ):
            new_msg, consumed, label = rewrite_upgrade_header_only(stream, pos, ctx)
        else:
            new_msg, consumed, suffix = replace_one_http1_message(stream, pos, ctx)
            label = f"http1.{suffix}"

        old_msg = stream[pos:pos + consumed]
        output.extend(new_msg)
        changed = changed or new_msg != old_msg
        labels.append(label)
        pos += consumed

    new_stream = bytes(output)
    if ctx.old_ip not in ctx.new_ip and ctx.old_ip in new_stream:
        return RewriteResult(False, False, stream, "http1.stream", "http.ip_remains_after_replace")
    return RewriteResult(True, changed, new_stream, "+".join(labels) if labels else "http1.stream")


# =============================================================================
# HTTP/1.x Handler（包级）
# =============================================================================

class HTTP1Handler(ProtocolHandler):
    """HTTP/1.x 包级改写处理器。"""

    name = "http1"

    def detect(self, payload, ctx):
        """TCP 且匹配 HTTP 请求/响应正则时命中。"""
        return ctx.proto_name == "TCP" and (
            HTTP_REQUEST_RE.match(payload) or HTTP_RESPONSE_RE.match(payload)
        )

    def rewrite(self, payload, ctx):
        """对单包执行 HTTP/1.x 消息序列改写。"""
        new_payload, label = replace_in_http1(payload, ctx)
        return RewriteResult(True, new_payload != payload, new_payload, f"http1.{label}")
