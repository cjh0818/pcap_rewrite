# -*- coding: utf-8 -*-
"""
HTTP/1.x 协议改写：支持 Content-Length、chunked、gzip/deflate 编码的 body 替换。
同时负责 WebSocket Upgrade 状态切换。
"""

import gzip
import io
import zlib

from core.context import RewriteError, RewriteResult
from core.dispatcher import ProtocolHandler
from core.utils import contains_ip_text_boundary, general_replace_payload, replace_ip_text_boundary
from config import (
    HTTP_HEADER_END,
    HTTP2_CONNECTION_PREFACE,
    HTTP1_REQUEST_LINE_RE,
    HTTP1_RESPONSE_LINE_RE,
    HTTP_REQUEST_RE,
    HTTP_RESPONSE_RE,
)

try:
    import brotli
except ImportError:  # pragma: no cover - depends on optional runtime package
    brotli = None

try:
    import zstandard
except ImportError:  # pragma: no cover - depends on optional runtime package
    zstandard = None


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


def parse_coding_tokens(value):
    """解析逗号分隔的 HTTP coding 列表，忽略 coding 参数。"""
    tokens = []
    for part in value.split(b","):
        token = part.split(b";", 1)[0].strip().lower()
        if token:
            tokens.append(token)
    return tokens


def get_content_codings(headers):
    """按出现顺序读取 Content-Encoding coding 列表。"""
    codings = []
    for value in header_values(headers, b"Content-Encoding"):
        codings.extend(parse_coding_tokens(value))
    return [coding for coding in codings if coding not in (b"", b"identity")]


def get_transfer_codings(headers):
    """按出现顺序读取 Transfer-Encoding coding 列表。"""
    codings = []
    for value in header_values(headers, b"Transfer-Encoding"):
        codings.extend(parse_coding_tokens(value))
    return [coding for coding in codings if coding not in (b"", b"identity")]


# =============================================================================
# HTTP/1.x start-line 判断
# =============================================================================

def is_http_request_line(start_line):
    """判断 HTTP start-line 是否为请求行（GET /path HTTP/1.1）。"""
    return bool(HTTP1_REQUEST_LINE_RE.match(start_line))


def is_http_response_line(start_line):
    """判断 HTTP start-line 是否为响应行（HTTP/1.1 200 OK）。"""
    return bool(HTTP1_RESPONSE_LINE_RE.match(start_line))


def http_request_method(start_line):
    """读取 HTTP 请求方法。"""
    if not is_http_request_line(start_line):
        return None
    return start_line.split(b" ", 1)[0].upper()


def http_response_status(start_line):
    """读取 HTTP 响应状态码。"""
    if not is_http_response_line(start_line):
        return None
    try:
        return int(start_line.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None


def pending_request_method_for_response(ctx):
    """读取当前响应对应的请求方法，用于 HEAD 响应 body 判定。"""
    state = ctx.tcp_state()
    methods = state.get("http_request_methods") or []
    return methods[0] if methods else None


def remember_http_request_method(method, ctx):
    """记录请求方法队列，供反向响应流判断 HEAD。"""
    if method is None or ctx.proto_name != "TCP":
        return
    ctx.tcp_state().setdefault("http_request_methods", []).append(method)


def finish_http_response(status_code, ctx):
    """最终响应处理完成后弹出对应请求方法；1xx 中间响应不弹出。"""
    if ctx.proto_name != "TCP" or status_code is None or 100 <= status_code < 200:
        return
    methods = ctx.tcp_state().get("http_request_methods") or []
    if methods:
        methods.pop(0)


def http_response_must_not_have_body(status_code, request_method):
    """按 RFC body length 规则判断响应是否强制无 body。"""
    if status_code is None:
        return False
    return 100 <= status_code < 200 or status_code in {204, 304} or request_method == b"HEAD"


# =============================================================================
# Chunked Transfer-Encoding 解析与构造
# =============================================================================

def parse_chunked_body(data):
    """
    解析 HTTP chunked body。
    返回 (chunks列表, trailer_block, consumed_len)。
    """
    pos = 0
    n = len(data)
    chunks = []

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
                return chunks, b"", pos + 2
            trailer_end = data.find(b"\r\n\r\n", pos)
            if trailer_end < 0:
                raise RewriteError("http.chunked.trailer_incomplete")
            trailer = data[pos:trailer_end]
            return chunks, trailer, trailer_end + 4

        if pos + chunk_size + 2 > n:
            raise RewriteError("http.chunked.data_incomplete")
        chunk_data = data[pos:pos + chunk_size]
        if data[pos + chunk_size:pos + chunk_size + 2] != b"\r\n":
            raise RewriteError("http.chunked.missing_data_crlf")
        chunks.append(chunk_data)
        pos += chunk_size + 2


def build_chunked_body(chunks, trailer_block=b""):
    """
    重新构造 HTTP chunked body（保留多个 chunk 的结构，重算各自的 chunk-size，含末尾 0\r\n 和可选 trailer）。
    """
    out = bytearray()
    for chunk in chunks:
        if chunk:
            out.extend(format(len(chunk), "x").encode("ascii") + b"\r\n" + chunk + b"\r\n")
    out.extend(b"0\r\n")
    if trailer_block:
        out.extend(trailer_block + b"\r\n\r\n")
    else:
        out.extend(b"\r\n")
    return bytes(out)


def split_by_lengths(data, lengths):
    """按原 chunk 长度列表切分数据。"""
    chunks = []
    pos = 0
    for length in lengths:
        chunks.append(data[pos:pos + length])
        pos += length
    if pos != len(data):
        raise RewriteError("http.chunked.split_length_mismatch")
    return chunks


# =============================================================================
# HTTP Body 编码处理（gzip/deflate/br/zstd/identity）
# =============================================================================

def gzip_compress_stable(data):
    """
    使用固定参数（mtime=0）压缩 gzip body，确保输出稳定可复现。
    """
    try:
        return gzip.compress(data, mtime=0)
    except TypeError:  # 极老 Python 兼容
        return gzip.compress(data)


def decode_coding(data, coding):
    """按单个 HTTP coding 解码。"""
    if coding in (b"", b"identity"):
        return data, "identity"
    if coding in (b"gzip", b"x-gzip"):
        try:
            return gzip.decompress(data), "gzip"
        except (EOFError, OSError, zlib.error) as exc:
            raise RewriteError(f"http.gzip.decompress_failed:{exc}") from exc
    if coding == b"deflate":
        try:
            return zlib.decompress(data), "deflate"
        except zlib.error:
            try:
                return zlib.decompress(data, -zlib.MAX_WBITS), "deflate.raw"
            except zlib.error as exc:
                raise RewriteError(f"http.deflate.decompress_failed:{exc}") from exc
    if coding == b"br":
        if brotli is None:
            raise RewriteError("http.br.module_missing")
        try:
            return brotli.decompress(data), "br"
        except Exception as exc:
            raise RewriteError(f"http.br.decompress_failed:{exc}") from exc
    if coding == b"zstd":
        if zstandard is None:
            raise RewriteError("http.zstd.module_missing")
        try:
            decompressor = zstandard.ZstdDecompressor()
            try:
                return decompressor.decompress(data), "zstd"
            except zstandard.ZstdError:
                with decompressor.stream_reader(io.BytesIO(data)) as reader:
                    return reader.read(), "zstd"
        except Exception as exc:
            raise RewriteError(f"http.zstd.decompress_failed:{exc}") from exc
    raise RewriteError(f"http.unsupported_coding.{coding!r}")


def encode_coding(data, coding, variant):
    """按单个 HTTP coding 重编码。"""
    if coding in (b"", b"identity"):
        return data
    if coding in (b"gzip", b"x-gzip"):
        return gzip_compress_stable(data)
    if coding == b"deflate":
        if variant == "deflate.raw":
            compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
            return compressor.compress(data) + compressor.flush()
        return zlib.compress(data)
    if coding == b"br":
        if brotli is None:
            raise RewriteError("http.br.module_missing")
        return brotli.compress(data, quality=4)
    if coding == b"zstd":
        if zstandard is None:
            raise RewriteError("http.zstd.module_missing")
        return zstandard.ZstdCompressor(level=3).compress(data)
    raise RewriteError(f"http.unsupported_coding.{coding!r}")


def coding_label(content_codings, transfer_codings):
    """生成 body 编码路径标签。"""
    labels = []
    labels.extend(f"ce.{coding.decode('ascii', 'replace')}" for coding in content_codings)
    labels.extend(f"te.{coding.decode('ascii', 'replace')}" for coding in transfer_codings)
    return "+".join(labels) if labels else "identity"


def replace_body_with_codings(body, content_codings, transfer_codings, old_ip, new_ip):
    """
    解码 Transfer-Encoding / Content-Encoding 后替换 IP，再按原 coding 顺序重编码。
    Transfer-Encoding 的 chunked 分帧由调用方处理，这里只处理 gzip/deflate/br/zstd 等 coding。
    """
    transfer_codings = [
        coding for coding in transfer_codings
        if coding not in (b"", b"identity", b"chunked")
    ]
    content_codings = [
        coding for coding in content_codings
        if coding not in (b"", b"identity")
    ]

    decoded = body
    decode_stack = []
    for coding in reversed(transfer_codings):
        decoded, variant = decode_coding(decoded, coding)
        decode_stack.append((coding, variant))
    for coding in reversed(content_codings):
        decoded, variant = decode_coding(decoded, coding)
        decode_stack.append((coding, variant))

    label = coding_label(content_codings, transfer_codings)
    if not contains_ip_text_boundary(decoded, old_ip):
        return body, False, label

    replaced, changed = replace_ip_text_boundary(decoded, old_ip, new_ip)
    if not changed:
        return body, False, label

    encoded = replaced
    for coding, variant in reversed(decode_stack):
        encoded = encode_coding(encoded, coding, variant)
    return encoded, True, label


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
    request_method = http_request_method(start_line) if is_request else None
    response_status = http_response_status(start_line) if is_response else None
    response_request_method = pending_request_method_for_response(ctx) if is_response else None

    old_ip = ctx.old_ip
    new_ip = ctx.new_ip

    # start-line 和 header values 中的 IP 文本按边界替换
    new_start_line, _ = replace_ip_text_boundary(start_line, old_ip, new_ip)
    new_headers = [
        (name, replace_ip_text_boundary(value, old_ip, new_ip)[0])
        for name, value in headers
    ]

    transfer_codings = get_transfer_codings(headers)
    is_chunked = b"chunked" in transfer_codings
    content_length = get_single_content_length(headers)
    content_codings = get_content_codings(headers)
    must_not_have_body = (
        is_response
        and http_response_must_not_have_body(response_status, response_request_method)
    )

    label_suffix = ""
    if must_not_have_body:
        new_body = b""
        consumed = body_start - start
        label_suffix = "no_body"

    elif is_chunked:
        # chunked + Content-Length 同时存在时，删除 Content-Length（RFC 7230）
        new_headers = remove_header(new_headers, b"Content-Length")
        chunks, trailer_block, consumed_body_len = parse_chunked_body(data[body_start:])
        original_body_segment = data[body_start:body_start + consumed_body_len]
        body_bytes = b"".join(chunks)
        new_body_bytes, body_changed, enc_label = replace_body_with_codings(
            body_bytes, content_codings, transfer_codings, old_ip, new_ip,
        )
        if body_changed and len(new_body_bytes) == len(body_bytes):
            new_chunks = split_by_lengths(new_body_bytes, [len(chunk) for chunk in chunks])
        elif body_changed:
            new_chunks = [new_body_bytes] if new_body_bytes else []
        else:
            new_chunks = chunks

        new_trailer, trailer_changed = replace_ip_text_boundary(trailer_block, old_ip, new_ip)
        trailer_changed = new_trailer != trailer_block
        if body_changed or trailer_changed:
            new_body = build_chunked_body(new_chunks, new_trailer)
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
        new_body, body_changed, enc_label = replace_body_with_codings(
            message_body, content_codings, transfer_codings, old_ip, new_ip,
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
            new_body, _, enc_label = replace_body_with_codings(
                message_body, content_codings, transfer_codings, old_ip, new_ip,
            )
            consumed = len(data) - start
            label_suffix = f"close_delimited.{enc_label}"

    # 检测并更新 WebSocket 状态
    remember_http_request_method(request_method, ctx)
    update_websocket_state_after_http(start_line, headers, ctx)
    if is_response:
        finish_http_response(response_status, ctx)

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
            if contains_ip_text_boundary(rest, ctx.old_ip):
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
    if not contains_ip_text_boundary(ctx.new_ip, ctx.old_ip) and contains_ip_text_boundary(new_payload, ctx.old_ip):
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
    new_start_line, _ = replace_ip_text_boundary(start_line, ctx.old_ip, ctx.new_ip)
    new_headers = [
        (name, replace_ip_text_boundary(value, ctx.old_ip, ctx.new_ip)[0])
        for name, value in headers
    ]
    if is_http_response_line(start_line):
        finish_http_response(http_response_status(start_line), ctx)
    elif is_http_request_line(start_line):
        remember_http_request_method(http_request_method(start_line), ctx)
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

        # WebSocket 已建立 → 切换到 WebSocket handler
        if ws_state.get("websocket_established"):
            new_ws = rewrite_websocket_frames(rest, ctx)
            output.extend(new_ws)
            changed = changed or new_ws != rest
            labels.append("websocket")
            pos = len(stream)
            break

        # websocket_pending 但数据仍像 HTTP（反方向的 101 响应），继续走 HTTP 解析
        if ws_state.get("websocket_pending") and not looks_like_http1(rest):
            new_ws = rewrite_websocket_frames(rest, ctx)
            output.extend(new_ws)
            changed = changed or new_ws != rest
            labels.append("websocket")
            pos = len(stream)
            break

        if not looks_like_http1(rest):
            new_tail, tail_changed, label = general_replace_payload(rest, args)
            if tail_changed:
                changed = True
                labels.append(f"tail.{label}")
            output.extend(new_tail)
            break

        header_end = stream.find(HTTP_HEADER_END, pos)
        if header_end < 0:
            if contains_ip_text_boundary(rest, ctx.old_ip):
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
    if not contains_ip_text_boundary(ctx.new_ip, ctx.old_ip) and contains_ip_text_boundary(new_stream, ctx.old_ip):
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
