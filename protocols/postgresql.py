# -*- coding: utf-8 -*-
"""
PostgreSQL 协议改写。

支持 StartupMessage、Simple Query(Q)、Extended Query 的 Parse(P)/Bind(B)，
以及响应 DataRow(D) 中带长度字段的文本值。无法安全解析且含旧 IP 时拒绝，
避免 handler 命中后静默漏改。
"""

from core.context import RewriteError, RewriteResult, is_port
from core.dispatcher import ProtocolHandler
from core.utils import contains_ip_text_boundary, replace_ip_text_boundary
from config import POSTGRES_PORT, PG_QUERY_MESSAGE


PG_PARSE_MESSAGE = ord("P")
PG_BIND_MESSAGE = ord("B")
PG_DATA_ROW_MESSAGE = ord("D")
PG_SSL_REQUEST = 80877103
PG_CANCEL_REQUEST = 80877102
PG_PROTOCOL_3 = 196608


def read_cstring(data, pos, limit, label):
    """读取 null-terminated PostgreSQL 字符串。"""
    end = data.find(b"\x00", pos, limit)
    if end < 0:
        raise RewriteError(f"postgresql.{label}.missing_null")
    return data[pos:end], end + 1


def put_message(msg_type, body):
    """构造 type + length + body 格式的 PostgreSQL message。"""
    return bytes([msg_type]) + (len(body) + 4).to_bytes(4, "big") + body


def rewrite_query_body(body, ctx):
    """改写 Simple Query SQL。"""
    if not body.endswith(b"\x00"):
        raise RewriteError("postgresql.query.missing_null")
    sql, changed = replace_ip_text_boundary(body[:-1], ctx.old_ip, ctx.new_ip)
    return sql + b"\x00", changed


def rewrite_parse_body(body, ctx):
    """改写 Parse(P) message 中的 statement name 和 SQL query。"""
    statement, pos = read_cstring(body, 0, len(body), "parse.statement")
    query, pos = read_cstring(body, pos, len(body), "parse.query")
    new_statement, statement_changed = replace_ip_text_boundary(statement, ctx.old_ip, ctx.new_ip)
    new_query, query_changed = replace_ip_text_boundary(query, ctx.old_ip, ctx.new_ip)
    return (
        new_statement + b"\x00" + new_query + b"\x00" + body[pos:],
        statement_changed or query_changed,
    )


def param_format(formats, index):
    """读取 Bind 参数格式：0=text，1=binary。"""
    if not formats:
        return 0
    if len(formats) == 1:
        return formats[0]
    return formats[index] if index < len(formats) else 0


def rewrite_bind_body(body, ctx):
    """改写 Bind(B) message 中 text-format 参数值。"""
    portal, pos = read_cstring(body, 0, len(body), "bind.portal")
    statement, pos = read_cstring(body, pos, len(body), "bind.statement")
    if pos + 2 > len(body):
        raise RewriteError("postgresql.bind.format_count_incomplete")
    format_count = int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    formats = []
    for _ in range(format_count):
        if pos + 2 > len(body):
            raise RewriteError("postgresql.bind.format_incomplete")
        formats.append(int.from_bytes(body[pos:pos + 2], "big"))
        pos += 2
    if pos + 2 > len(body):
        raise RewriteError("postgresql.bind.param_count_incomplete")
    param_count = int.from_bytes(body[pos:pos + 2], "big")
    pos += 2

    new_portal, portal_changed = replace_ip_text_boundary(portal, ctx.old_ip, ctx.new_ip)
    new_statement, statement_changed = replace_ip_text_boundary(statement, ctx.old_ip, ctx.new_ip)
    out = bytearray(new_portal + b"\x00" + new_statement + b"\x00")
    out.extend(format_count.to_bytes(2, "big"))
    for fmt in formats:
        out.extend(fmt.to_bytes(2, "big"))
    out.extend(param_count.to_bytes(2, "big"))

    changed = portal_changed or statement_changed
    for index in range(param_count):
        if pos + 4 > len(body):
            raise RewriteError("postgresql.bind.param_len_incomplete")
        value_len = int.from_bytes(body[pos:pos + 4], "big", signed=True)
        pos += 4
        if value_len == -1:
            out.extend((-1).to_bytes(4, "big", signed=True))
            continue
        if value_len < -1 or pos + value_len > len(body):
            raise RewriteError("postgresql.bind.param_overflow")
        value = body[pos:pos + value_len]
        pos += value_len
        if param_format(formats, index) == 0:
            new_value, value_changed = replace_ip_text_boundary(value, ctx.old_ip, ctx.new_ip)
            changed = changed or value_changed
        else:
            if contains_ip_text_boundary(value, ctx.old_ip):
                raise RewriteError("postgresql.bind.binary_param_with_ip")
            new_value = value
        out.extend(len(new_value).to_bytes(4, "big", signed=True))
        out.extend(new_value)

    out.extend(body[pos:])
    return bytes(out), changed or len(out) != len(body)


def rewrite_data_row_body(body, ctx):
    """改写 DataRow(D) 中每列的长度前缀文本值。"""
    if len(body) < 2:
        raise RewriteError("postgresql.datarow.column_count_incomplete")
    column_count = int.from_bytes(body[:2], "big")
    pos = 2
    out = bytearray(body[:2])
    changed = False
    for _ in range(column_count):
        if pos + 4 > len(body):
            raise RewriteError("postgresql.datarow.value_len_incomplete")
        value_len = int.from_bytes(body[pos:pos + 4], "big", signed=True)
        pos += 4
        if value_len == -1:
            out.extend((-1).to_bytes(4, "big", signed=True))
            continue
        if value_len < -1 or pos + value_len > len(body):
            raise RewriteError("postgresql.datarow.value_overflow")
        value = body[pos:pos + value_len]
        pos += value_len
        new_value, value_changed = replace_ip_text_boundary(value, ctx.old_ip, ctx.new_ip)
        out.extend(len(new_value).to_bytes(4, "big", signed=True))
        out.extend(new_value)
        changed = changed or value_changed
    if pos != len(body):
        raise RewriteError("postgresql.datarow.trailing_bytes")
    return bytes(out), changed or len(out) != len(body)


def startup_message_kind(payload, pos, n):
    """识别无 type 前缀的 Startup/SSL/Cancel request。"""
    if pos + 8 > n:
        return None
    msg_len = int.from_bytes(payload[pos:pos + 4], "big")
    if msg_len < 8 or pos + msg_len > n:
        return None
    code = int.from_bytes(payload[pos + 4:pos + 8], "big")
    if code == PG_SSL_REQUEST:
        return "ssl"
    if code == PG_CANCEL_REQUEST:
        return "cancel"
    if code == PG_PROTOCOL_3 or code >> 16 == 3:
        return "startup"
    return None


def rewrite_startup_message(payload, pos, ctx):
    """改写 StartupMessage 参数区域。"""
    msg_len = int.from_bytes(payload[pos:pos + 4], "big")
    end = pos + msg_len
    code = int.from_bytes(payload[pos + 4:pos + 8], "big")
    message = payload[pos:end]
    if code in (PG_SSL_REQUEST, PG_CANCEL_REQUEST):
        if contains_ip_text_boundary(message, ctx.old_ip):
            raise RewriteError("postgresql.startup.control_with_ip")
        return message, end, False, "startup.control"
    params, changed = replace_ip_text_boundary(message[8:], ctx.old_ip, ctx.new_ip)
    rewritten = (len(params) + 8).to_bytes(4, "big") + message[4:8] + params
    return rewritten, end, changed or len(rewritten) != len(message), "startup"


def rewrite_typed_message(msg_type, body, ctx):
    """按 PostgreSQL message type 改写 body。"""
    if msg_type == PG_QUERY_MESSAGE:
        new_body, changed = rewrite_query_body(body, ctx)
        return put_message(msg_type, new_body), changed, "query"
    if msg_type == PG_PARSE_MESSAGE:
        new_body, changed = rewrite_parse_body(body, ctx)
        return put_message(msg_type, new_body), changed, "parse"
    if msg_type == PG_BIND_MESSAGE:
        new_body, changed = rewrite_bind_body(body, ctx)
        return put_message(msg_type, new_body), changed, "bind"
    if msg_type == PG_DATA_ROW_MESSAGE:
        new_body, changed = rewrite_data_row_body(body, ctx)
        return put_message(msg_type, new_body), changed, "datarow"
    if contains_ip_text_boundary(body, ctx.old_ip):
        raise RewriteError(f"postgresql.msg_{chr(msg_type)!r}_with_ip_not_supported")
    return put_message(msg_type, body), False, "unchanged"


class PostgreSQLHandler(ProtocolHandler):
    """PostgreSQL 协议改写处理器。"""

    name = "postgresql"

    def detect(self, payload, ctx):
        """TCP 且端口=5432，或首字节为已支持 message type 时命中。"""
        if ctx.proto_name != "TCP" or not payload:
            return False
        if is_port(ctx, POSTGRES_PORT):
            return True
        return len(payload) >= 6 and payload[0] in {
            PG_QUERY_MESSAGE,
            PG_PARSE_MESSAGE,
            PG_BIND_MESSAGE,
            PG_DATA_ROW_MESSAGE,
        }

    def rewrite(self, payload, ctx):
        out = bytearray()
        labels = []
        pos = 0
        changed = False
        n = len(payload)

        try:
            while pos < n:
                kind = startup_message_kind(payload, pos, n)
                if kind is not None:
                    message, pos, msg_changed, label = rewrite_startup_message(payload, pos, ctx)
                    out.extend(message)
                    changed = changed or msg_changed
                    labels.append(label)
                    continue

                if pos + 5 > n:
                    tail = payload[pos:]
                    if contains_ip_text_boundary(tail, ctx.old_ip):
                        raise RewriteError("postgresql.trailing_incomplete_with_ip")
                    out.extend(tail)
                    break

                msg_type = payload[pos]
                msg_len = int.from_bytes(payload[pos + 1:pos + 5], "big")
                if msg_len < 4:
                    tail = payload[pos:]
                    if contains_ip_text_boundary(tail, ctx.old_ip):
                        raise RewriteError("postgresql.invalid_length_with_ip")
                    out.extend(tail)
                    break
                end = pos + 1 + msg_len
                if end > n:
                    tail = payload[pos:]
                    if contains_ip_text_boundary(tail, ctx.old_ip):
                        raise RewriteError("postgresql.incomplete_message_with_ip")
                    out.extend(tail)
                    break

                message, msg_changed, label = rewrite_typed_message(msg_type, payload[pos + 5:end], ctx)
                out.extend(message)
                changed = changed or msg_changed
                labels.append(label)
                pos = end
        except RewriteError as exc:
            return RewriteResult(False, False, payload, self.name, str(exc))

        suffix = "+".join(labels) if labels else "unchanged"
        return RewriteResult(True, changed, bytes(out), f"postgresql.{suffix}")
