# -*- coding: utf-8 -*-
"""
TLS ClientHello SNI 改写。

解析 TLS record → Handshake → ClientHello → Extensions → SNI → server_name，
仅在 SNI 中替换 IPv4 文本。非 Handshake(0x16) record 或非 ClientHello 消息
中含 IP 时拒绝改写。
"""

from core.context import RewriteError, RewriteResult
from core.dispatcher import ProtocolHandler
from config import TLS_CONTENT_TYPES, TLS_MINOR_VERSIONS, TLS_MAX_RECORD_LEN


def looks_like_tls(payload):
    """
    判断 payload 是否为完整 TLS record 序列。
    验证每个 record 的 ContentType、版本和长度是否合法。
    """
    n = len(payload)
    if n < 5:
        return False
    pos = 0
    while pos < n:
        if pos + 5 > n:
            return False
        record_type = payload[pos]
        version_major = payload[pos + 1]
        version_minor = payload[pos + 2]
        # TLS record 长度为大端 2 字节
        record_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
        if record_type not in TLS_CONTENT_TYPES:
            return False
        if version_major != 0x03 or version_minor not in TLS_MINOR_VERSIONS:
            return False
        if record_len == 0 or record_len > TLS_MAX_RECORD_LEN:
            return False
        if pos + 5 + record_len > n:
            return False
        pos += 5 + record_len
    return True


def replace_in_tls(payload, old_ip, new_ip):
    """
    改写 TLS record 序列中 Handshake(0x16) record 的 ClientHello SNI。
    遍历每个 record，只改写 type=0x16 且 body 含旧 IP 的 record。
    """
    output = bytearray()
    pos = 0
    n = len(payload)
    while pos < n:
        record_type = payload[pos]
        version = bytes(payload[pos + 1:pos + 3])
        record_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
        record_end = pos + 5 + record_len
        body = bytes(payload[pos + 5:record_end])

        if old_ip not in body:
            # body 不含旧 IP，原样保留整个 record
            output.append(record_type)
            output.extend(version)
            output.extend(record_len.to_bytes(2, "big"))
            output.extend(body)
            pos = record_end
            continue

        # 非 Handshake record 中出现 IP 是异常情况，拒绝
        if record_type != 0x16:
            raise RewriteError(f"tls.record_type_{record_type:#04x}_with_ip")

        new_body = replace_in_handshake_records(body, old_ip, new_ip)
        if len(new_body) >= (1 << 16):
            raise RewriteError("tls.record_too_long_after_replace")

        output.append(record_type)
        output.extend(version)
        # 更新 record 长度字段为改写后的 body 长度
        output.extend(len(new_body).to_bytes(2, "big"))
        output.extend(new_body)
        pos = record_end

    new_payload = bytes(output)
    # 安全检查：确保旧 IP 已被完全替换
    if old_ip not in new_ip and old_ip in new_payload:
        raise RewriteError("tls.ip_remains_after_replace")
    return new_payload


def replace_in_handshake_records(body, old_ip, new_ip):
    """
    遍历 TLS Handshake 消息序列，改写 ClientHello(msg_type=0x01)。
    非 ClientHello 消息含 IP 时拒绝。
    """
    output = bytearray()
    pos = 0
    n = len(body)
    while pos < n:
        if pos + 4 > n:
            raise RewriteError("tls.handshake.incomplete_header")
        msg_type = body[pos]
        # Handshake 消息长度为 3 字节大端
        msg_len = int.from_bytes(body[pos + 1:pos + 4], "big")
        msg_end = pos + 4 + msg_len
        if msg_end > n:
            raise RewriteError("tls.handshake.msg_truncated")
        msg_body = body[pos + 4:msg_end]

        if old_ip not in msg_body:
            output.append(msg_type)
            output.extend(msg_len.to_bytes(3, "big"))
            output.extend(msg_body)
            pos = msg_end
            continue

        if msg_type != 0x01:  # 只允许 ClientHello
            raise RewriteError(f"tls.handshake.msg_type_{msg_type:#04x}_with_ip")

        new_msg_body = replace_in_client_hello(msg_body, old_ip, new_ip)
        if len(new_msg_body) >= (1 << 24):
            raise RewriteError("tls.handshake.msg_too_long_after_replace")
        output.append(msg_type)
        output.extend(len(new_msg_body).to_bytes(3, "big"))
        output.extend(new_msg_body)
        pos = msg_end
    return bytes(output)


def replace_in_client_hello(body, old_ip, new_ip):
    """
    解析 ClientHello 结构：跳过版本、随机数、session_id、cipher_suites、
    compression_methods，只在 Extensions 区域进行替换。
    ClientHello 前 34 字节是版本+随机数，不应包含 IP 文本。
    """
    n = len(body)
    if n < 34:
        raise RewriteError("tls.client_hello.too_short")
    pos = 0
    # 前 34 字节 = 2(版本) + 32(随机数)
    fixed_head = body[pos:pos + 34]
    if old_ip in fixed_head:
        raise RewriteError("tls.client_hello.ip_in_version_or_random")
    pos += 34

    # Session ID（1 字节长度 + N 字节值）
    if pos >= n:
        raise RewriteError("tls.client_hello.missing_session_id")
    sid_len = body[pos]
    if pos + 1 + sid_len > n:
        raise RewriteError("tls.client_hello.session_id_overflow")
    sid_block = body[pos:pos + 1 + sid_len]
    if old_ip in sid_block:
        raise RewriteError("tls.client_hello.ip_in_session_id")
    pos += 1 + sid_len

    # Cipher Suites（2 字节长度 + N 字节值）
    if pos + 2 > n:
        raise RewriteError("tls.client_hello.missing_cipher_suites")
    cs_len = int.from_bytes(body[pos:pos + 2], "big")
    if pos + 2 + cs_len > n:
        raise RewriteError("tls.client_hello.cipher_suites_overflow")
    cs_block = body[pos:pos + 2 + cs_len]
    if old_ip in cs_block:
        raise RewriteError("tls.client_hello.ip_in_cipher_suites")
    pos += 2 + cs_len

    # Compression Methods（1 字节长度 + N 字节值）
    if pos + 1 > n:
        raise RewriteError("tls.client_hello.missing_compression_methods")
    cm_len = body[pos]
    if pos + 1 + cm_len > n:
        raise RewriteError("tls.client_hello.compression_overflow")
    cm_block = body[pos:pos + 1 + cm_len]
    if old_ip in cm_block:
        raise RewriteError("tls.client_hello.ip_in_compression_methods")
    pos += 1 + cm_len

    # Extensions（2 字节长度 + N 字节值）— 这是 SNI 所在的位置
    if pos + 2 > n:
        raise RewriteError("tls.client_hello.missing_extensions")
    ext_len = int.from_bytes(body[pos:pos + 2], "big")
    ext_start = pos + 2
    ext_end = ext_start + ext_len
    if ext_end != n:
        raise RewriteError("tls.client_hello.extensions_length_mismatch")

    new_ext_block = replace_in_extensions(body[ext_start:ext_end], old_ip, new_ip)
    if len(new_ext_block) >= (1 << 16):
        raise RewriteError("tls.client_hello.extensions_too_long_after_replace")
    return body[:pos] + len(new_ext_block).to_bytes(2, "big") + new_ext_block


def replace_in_extensions(block, old_ip, new_ip):
    """
    遍历 TLS Extensions 列表，只改写 SNI(ext_type=0x0000) extension。
    非 SNI extension 含 IP 时拒绝。
    """
    output = bytearray()
    pos = 0
    n = len(block)
    while pos < n:
        if pos + 4 > n:
            raise RewriteError("tls.extensions.incomplete_header")
        ext_type = int.from_bytes(block[pos:pos + 2], "big")
        ext_data_len = int.from_bytes(block[pos + 2:pos + 4], "big")
        ext_end = pos + 4 + ext_data_len
        if ext_end > n:
            raise RewriteError("tls.extensions.data_overflow")
        ext_data = block[pos + 4:ext_end]

        if old_ip not in ext_data:
            output.extend(block[pos:ext_end])
            pos = ext_end
            continue

        if ext_type != 0x0000:  # 只允许 SNI
            raise RewriteError(f"tls.extensions.ext_type_{ext_type:#06x}_with_ip")

        new_ext_data = replace_in_sni_extension(ext_data, old_ip, new_ip)
        if len(new_ext_data) >= (1 << 16):
            raise RewriteError("tls.extensions.ext_data_too_long_after_replace")
        output.extend(block[pos:pos + 2])
        output.extend(len(new_ext_data).to_bytes(2, "big"))
        output.extend(new_ext_data)
        pos = ext_end
    return bytes(output)


def replace_in_sni_extension(ext_data, old_ip, new_ip):
    """
    改写 SNI extension 中的 server_name_list。
    SNI extension data = 2 字节 list_len + server_name_list。
    """
    if len(ext_data) < 2:
        raise RewriteError("tls.sni.too_short")
    list_len = int.from_bytes(ext_data[:2], "big")
    if 2 + list_len != len(ext_data):
        raise RewriteError("tls.sni.list_length_mismatch")

    new_list = replace_in_server_name_list(ext_data[2:], old_ip, new_ip)
    if len(new_list) >= (1 << 16):
        raise RewriteError("tls.sni.list_too_long_after_replace")
    return len(new_list).to_bytes(2, "big") + new_list


def replace_in_server_name_list(block, old_ip, new_ip):
    """
    遍历 ServerName 列表，对 name_type=0x00(host_name) 的条目执行 IP 替换。
    替换后更新 name_length 字段。
    """
    output = bytearray()
    pos = 0
    n = len(block)
    while pos < n:
        if pos + 3 > n:
            raise RewriteError("tls.sni.incomplete_server_name")
        name_type = block[pos]
        if name_type != 0x00:
            raise RewriteError(f"tls.sni.name_type_{name_type:#04x}")
        name_len = int.from_bytes(block[pos + 1:pos + 3], "big")
        name_end = pos + 3 + name_len
        if name_end > n:
            raise RewriteError("tls.sni.name_overflow")
        name_data = block[pos + 3:name_end]

        if old_ip not in name_data:
            output.extend(block[pos:name_end])
            pos = name_end
            continue

        new_name = name_data.replace(old_ip, new_ip)
        if len(new_name) >= (1 << 16):
            raise RewriteError("tls.sni.name_too_long_after_replace")
        output.append(name_type)
        output.extend(len(new_name).to_bytes(2, "big"))
        output.extend(new_name)
        pos = name_end
    return bytes(output)


class TLSClientHelloSNIHandler(ProtocolHandler):
    """TLS ClientHello SNI 改写处理器。"""

    name = "tls.sni"

    def detect(self, payload, ctx):
        """TCP 且 payload 为完整 TLS record 序列时命中。"""
        return ctx.proto_name == "TCP" and looks_like_tls(payload)

    def rewrite(self, payload, ctx):
        """
        TLS 只有明文 ClientHello SNI 中有可能出现 IP 文本。
        不含旧 IP 则跳过，含则调用 replace_in_tls 进行结构化替换。
        """
        if ctx.old_ip not in payload:
            return RewriteResult(True, False, payload, self.name)
        new_payload = replace_in_tls(payload, ctx.old_ip, ctx.new_ip)
        return RewriteResult(True, new_payload != payload, new_payload, self.name)
