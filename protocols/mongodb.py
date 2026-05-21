# -*- coding: utf-8 -*-
"""
MongoDB Wire Protocol 改写。

支持未压缩 MongoDB message 中 BSON string/symbol/code/cstring 字段的 IPv4 文本
替换，并同步更新 BSON document length 与 MongoDB message length。压缩消息、
未知 BSON 类型或含旧 IP 的二进制字段会拒绝，避免破坏二进制协议。
"""

from core.context import RewriteError, RewriteResult
from core.dispatcher import ProtocolHandler
from core.utils import has_old_material
from config import (
    MONGODB_PORTS,
    MONGO_OPCODES,
    MONGO_OP_REPLY,
    MONGO_OP_UPDATE,
    MONGO_OP_INSERT,
    MONGO_OP_QUERY,
    MONGO_OP_GET_MORE,
    MONGO_OP_DELETE,
    MONGO_OP_KILL_CURSORS,
    MONGO_OP_COMMAND,
    MONGO_OP_COMMANDREPLY,
    MONGO_OP_COMPRESSED,
    MONGO_OP_MSG,
)


BSON_FIXED_LENGTHS = {
    0x01: 8,    # double
    0x07: 12,   # ObjectId
    0x08: 1,    # bool
    0x09: 8,    # UTC datetime
    0x10: 4,    # int32
    0x11: 8,    # timestamp
    0x12: 8,    # int64
    0x13: 16,   # decimal128
}
BSON_ZERO_LENGTHS = {0x06, 0x0A, 0xFF, 0x7F}
BSON_STRING_TYPES = {0x02, 0x0D, 0x0E}  # string, JavaScript, symbol
MAX_BSON_DEPTH = 50


def is_mongo_port(ctx):
    """判断当前 TCP 端口是否为常见 MongoDB 端口。"""
    return ctx.sport() in MONGODB_PORTS or ctx.dport() in MONGODB_PORTS


def int32_le(data, pos):
    """读取 little-endian int32。"""
    return int.from_bytes(data[pos:pos + 4], "little", signed=True)


def uint32_le(data, pos):
    """读取 little-endian uint32。"""
    return int.from_bytes(data[pos:pos + 4], "little", signed=False)


def put_int32_le(value):
    """写入 little-endian int32。"""
    return int(value).to_bytes(4, "little", signed=True)


def looks_like_mongo(payload):
    """粗略判断 payload 是否像 MongoDB wire message。"""
    if len(payload) < 16:
        return False
    try:
        msg_len = int32_le(payload, 0)
        opcode = int32_le(payload, 12)
    except (TypeError, ValueError):
        return False
    return 16 <= msg_len <= len(payload) and opcode in MONGO_OPCODES


def read_cstring(data, pos, limit, label):
    """读取 BSON/MongoDB cstring。"""
    end = data.find(b"\x00", pos, limit)
    if end < 0:
        raise RewriteError(f"mongodb.{label}.missing_null")
    return data[pos:end], end + 1


def replace_cstring(data, pos, limit, ctx, label):
    """读取并替换 cstring 中的旧 IP 文本。"""
    value, new_pos = read_cstring(data, pos, limit, label)
    new_value = value.replace(ctx.old_ip, ctx.new_ip)
    if b"\x00" in new_value:
        raise RewriteError(f"mongodb.{label}.cstring_null_after_replace")
    return new_value + b"\x00", new_pos, new_value != value


def rewrite_bson_string(data, pos, limit, ctx, label):
    """读取并重写 BSON string-like value。"""
    if pos + 4 > limit:
        raise RewriteError(f"mongodb.bson.{label}.string_len_incomplete")
    strlen = int32_le(data, pos)
    end = pos + 4 + strlen
    if strlen < 1 or end > limit:
        raise RewriteError(f"mongodb.bson.{label}.string_overflow")
    if data[end - 1:end] != b"\x00":
        raise RewriteError(f"mongodb.bson.{label}.string_missing_null")
    value = data[pos + 4:end - 1]
    new_value = value.replace(ctx.old_ip, ctx.new_ip)
    rewritten = put_int32_le(len(new_value) + 1) + new_value + b"\x00"
    return rewritten, end, new_value != value


def rewrite_bson_document(data, pos, ctx, depth=0):
    """递归改写 BSON document，并更新 document length。"""
    if depth > MAX_BSON_DEPTH:
        raise RewriteError("mongodb.bson.max_depth")
    if pos + 4 > len(data):
        raise RewriteError("mongodb.bson.document_len_incomplete")
    doc_len = int32_le(data, pos)
    end = pos + doc_len
    if doc_len < 5 or end > len(data):
        raise RewriteError("mongodb.bson.document_overflow")
    if data[end - 1:end] != b"\x00":
        raise RewriteError("mongodb.bson.document_missing_null")

    out = bytearray()
    p = pos + 4
    changed = False
    while p < end - 1:
        element_type = data[p]
        p += 1
        key_bytes, p, key_changed = replace_cstring(data, p, end, ctx, "bson.key")
        value_bytes, p, value_changed = rewrite_bson_value(element_type, data, p, end, ctx, depth)
        out.append(element_type)
        out.extend(key_bytes)
        out.extend(value_bytes)
        changed = changed or key_changed or value_changed

    new_doc = put_int32_le(len(out) + 5) + bytes(out) + b"\x00"
    return new_doc, end, changed or len(new_doc) != doc_len


def rewrite_bson_value(element_type, data, pos, limit, ctx, depth):
    """按 BSON 类型改写一个 value。"""
    if element_type in BSON_STRING_TYPES:
        return rewrite_bson_string(data, pos, limit, ctx, "string")

    if element_type in (0x03, 0x04):  # embedded document / array
        return rewrite_bson_document(data, pos, ctx, depth + 1)

    if element_type == 0x05:  # binary
        if pos + 5 > limit:
            raise RewriteError("mongodb.bson.binary_incomplete")
        blob_len = int32_le(data, pos)
        blob_start = pos + 5
        blob_end = blob_start + blob_len
        if blob_len < 0 or blob_end > limit:
            raise RewriteError("mongodb.bson.binary_overflow")
        subtype = data[pos + 4:pos + 5]
        blob = data[blob_start:blob_end]
        if blob_len == 4 and blob == ctx.old_ip_bin:
            rewritten = put_int32_le(4) + subtype + ctx.new_ip_bin
            return rewritten, blob_end, True
        if ctx.old_ip in blob or ctx.old_ip_bin in blob:
            raise RewriteError("mongodb.bson.binary_with_ip_not_supported")
        return data[pos:blob_end], blob_end, False

    if element_type == 0x0B:  # regex: pattern cstring + options cstring
        pattern, next_pos, pattern_changed = replace_cstring(data, pos, limit, ctx, "bson.regex_pattern")
        options, next_pos, options_changed = replace_cstring(data, next_pos, limit, ctx, "bson.regex_options")
        return pattern + options, next_pos, pattern_changed or options_changed

    if element_type == 0x0C:  # DBPointer: string + ObjectId
        string_bytes, next_pos, string_changed = rewrite_bson_string(data, pos, limit, ctx, "dbpointer")
        end = next_pos + 12
        if end > limit:
            raise RewriteError("mongodb.bson.dbpointer_objectid_incomplete")
        return string_bytes + data[next_pos:end], end, string_changed

    if element_type == 0x0F:  # JavaScript code with scope
        if pos + 4 > limit:
            raise RewriteError("mongodb.bson.code_scope_len_incomplete")
        total_len = int32_le(data, pos)
        end = pos + total_len
        if total_len < 14 or end > limit:
            raise RewriteError("mongodb.bson.code_scope_overflow")
        code, after_code, code_changed = rewrite_bson_string(data, pos + 4, end, ctx, "code_scope")
        scope, after_scope, scope_changed = rewrite_bson_document(data, after_code, ctx, depth + 1)
        if after_scope != end:
            raise RewriteError("mongodb.bson.code_scope_length_mismatch")
        body = code + scope
        return put_int32_le(len(body) + 4) + body, end, code_changed or scope_changed

    if element_type in BSON_FIXED_LENGTHS:
        size = BSON_FIXED_LENGTHS[element_type]
        end = pos + size
        if end > limit:
            raise RewriteError(f"mongodb.bson.type_{element_type:#x}_incomplete")
        return data[pos:end], end, False

    if element_type in BSON_ZERO_LENGTHS:
        return b"", pos, False

    raise RewriteError(f"mongodb.bson.type_{element_type:#x}_not_supported")


def rewrite_docs_until_end(data, pos, ctx):
    """从 pos 开始连续改写 BSON document 直到 data 结束。"""
    out = bytearray()
    changed = False
    while pos < len(data):
        doc, pos, doc_changed = rewrite_bson_document(data, pos, ctx)
        out.extend(doc)
        changed = changed or doc_changed
    return bytes(out), changed


def rewrite_op_msg(body, ctx):
    """改写 OP_MSG body。"""
    if len(body) < 4:
        raise RewriteError("mongodb.op_msg.flags_incomplete")
    flags = uint32_le(body, 0)
    if flags & 0x01:  # checksumPresent
        if has_old_material(body, ctx):
            raise RewriteError("mongodb.op_msg.checksum_not_supported_with_ip")
        return body, False

    out = bytearray(body[:4])
    pos = 4
    changed = False
    while pos < len(body):
        section_kind = body[pos]
        pos += 1
        out.append(section_kind)

        if section_kind == 0:
            doc, pos, doc_changed = rewrite_bson_document(body, pos, ctx)
            out.extend(doc)
            changed = changed or doc_changed
            continue

        if section_kind == 1:
            if pos + 4 > len(body):
                raise RewriteError("mongodb.op_msg.section_size_incomplete")
            section_size = int32_le(body, pos)
            section_end = pos + section_size
            if section_size < 5 or section_end > len(body):
                raise RewriteError("mongodb.op_msg.section_overflow")
            identifier, doc_pos, id_changed = replace_cstring(body, pos + 4, section_end, ctx, "op_msg.identifier")
            docs, docs_changed = rewrite_docs_until_end(body[:section_end], doc_pos, ctx)
            section_body = identifier + docs
            out.extend(put_int32_le(len(section_body) + 4))
            out.extend(section_body)
            changed = changed or id_changed or docs_changed or len(section_body) + 4 != section_size
            pos = section_end
            continue

        rest = body[pos - 1:]
        if has_old_material(rest, ctx):
            raise RewriteError(f"mongodb.op_msg.section_{section_kind:#x}_with_ip_not_supported")
        out.extend(rest)
        break

    return bytes(out), changed


def rewrite_op_query(body, ctx):
    """改写 OP_QUERY body。"""
    if len(body) < 12:
        raise RewriteError("mongodb.op_query.too_short")
    out = bytearray(body[:4])
    collection, pos, coll_changed = replace_cstring(body, 4, len(body), ctx, "op_query.collection")
    if pos + 8 > len(body):
        raise RewriteError("mongodb.op_query.fixed_fields_incomplete")
    out.extend(collection)
    out.extend(body[pos:pos + 8])
    pos += 8
    query, pos, query_changed = rewrite_bson_document(body, pos, ctx)
    out.extend(query)
    changed = coll_changed or query_changed
    if pos < len(body):
        selector, pos, selector_changed = rewrite_bson_document(body, pos, ctx)
        out.extend(selector)
        changed = changed or selector_changed
    if pos != len(body):
        raise RewriteError("mongodb.op_query.trailing_bytes")
    return bytes(out), changed


def rewrite_op_reply(body, ctx):
    """改写 OP_REPLY body。"""
    if len(body) < 20:
        raise RewriteError("mongodb.op_reply.too_short")
    docs, changed = rewrite_docs_until_end(body, 20, ctx)
    return body[:20] + docs, changed


def rewrite_op_insert(body, ctx):
    """改写 OP_INSERT body。"""
    if len(body) < 5:
        raise RewriteError("mongodb.op_insert.too_short")
    out = bytearray(body[:4])
    collection, pos, coll_changed = replace_cstring(body, 4, len(body), ctx, "op_insert.collection")
    docs, docs_changed = rewrite_docs_until_end(body, pos, ctx)
    out.extend(collection)
    out.extend(docs)
    return bytes(out), coll_changed or docs_changed


def rewrite_op_update_or_delete(body, ctx, opcode):
    """改写 OP_UPDATE / OP_DELETE body。"""
    label = "op_update" if opcode == MONGO_OP_UPDATE else "op_delete"
    min_len = 9
    if len(body) < min_len:
        raise RewriteError(f"mongodb.{label}.too_short")
    out = bytearray(body[:4])
    collection, pos, coll_changed = replace_cstring(body, 4, len(body), ctx, f"{label}.collection")
    if pos + 4 > len(body):
        raise RewriteError(f"mongodb.{label}.flags_incomplete")
    out.extend(collection)
    out.extend(body[pos:pos + 4])
    pos += 4
    first_doc, pos, first_changed = rewrite_bson_document(body, pos, ctx)
    out.extend(first_doc)
    changed = coll_changed or first_changed
    if opcode == MONGO_OP_UPDATE:
        second_doc, pos, second_changed = rewrite_bson_document(body, pos, ctx)
        out.extend(second_doc)
        changed = changed or second_changed
    if pos != len(body):
        raise RewriteError(f"mongodb.{label}.trailing_bytes")
    return bytes(out), changed


def rewrite_op_get_more(body, ctx):
    """改写 OP_GET_MORE 的 namespace cstring。"""
    if len(body) < 17:
        raise RewriteError("mongodb.op_get_more.too_short")
    out = bytearray(body[:4])
    collection, pos, coll_changed = replace_cstring(body, 4, len(body), ctx, "op_get_more.collection")
    if pos + 12 != len(body):
        raise RewriteError("mongodb.op_get_more.length_mismatch")
    out.extend(collection)
    out.extend(body[pos:])
    return bytes(out), coll_changed


def rewrite_op_command(body, ctx):
    """改写 deprecated OP_COMMAND body。"""
    database, pos, db_changed = replace_cstring(body, 0, len(body), ctx, "op_command.database")
    command, pos, cmd_changed = replace_cstring(body, pos, len(body), ctx, "op_command.command")
    docs, docs_changed = rewrite_docs_until_end(body, pos, ctx)
    return database + command + docs, db_changed or cmd_changed or docs_changed


def rewrite_op_command_reply(body, ctx):
    """改写 deprecated OP_COMMANDREPLY body。"""
    docs, changed = rewrite_docs_until_end(body, 0, ctx)
    return docs, changed


def rewrite_mongo_body(opcode, body, ctx):
    """按 MongoDB opcode 改写 body。"""
    if opcode == MONGO_OP_MSG:
        return rewrite_op_msg(body, ctx)
    if opcode == MONGO_OP_QUERY:
        return rewrite_op_query(body, ctx)
    if opcode == MONGO_OP_REPLY:
        return rewrite_op_reply(body, ctx)
    if opcode == MONGO_OP_INSERT:
        return rewrite_op_insert(body, ctx)
    if opcode in (MONGO_OP_UPDATE, MONGO_OP_DELETE):
        return rewrite_op_update_or_delete(body, ctx, opcode)
    if opcode == MONGO_OP_GET_MORE:
        return rewrite_op_get_more(body, ctx)
    if opcode == MONGO_OP_COMMAND:
        return rewrite_op_command(body, ctx)
    if opcode == MONGO_OP_COMMANDREPLY:
        return rewrite_op_command_reply(body, ctx)
    if opcode in (MONGO_OP_KILL_CURSORS, MONGO_OP_COMPRESSED):
        if has_old_material(body, ctx):
            reason = "compressed" if opcode == MONGO_OP_COMPRESSED else "kill_cursors"
            raise RewriteError(f"mongodb.{reason}_with_ip_not_supported")
        return body, False
    if has_old_material(body, ctx):
        raise RewriteError(f"mongodb.opcode_{opcode}_with_ip_not_supported")
    return body, False


def rewrite_mongo_message(message, ctx):
    """改写单个 MongoDB wire message，并更新 messageLength。"""
    if len(message) < 16:
        raise RewriteError("mongodb.message_header_incomplete")
    opcode = int32_le(message, 12)
    if opcode not in MONGO_OPCODES:
        if has_old_material(message, ctx):
            raise RewriteError(f"mongodb.opcode_{opcode}_with_ip_not_supported")
        return message, False

    new_body, changed = rewrite_mongo_body(opcode, message[16:], ctx)
    new_message = put_int32_le(16 + len(new_body)) + message[4:16] + new_body
    if ctx.old_ip not in ctx.new_ip and ctx.old_ip in new_message:
        raise RewriteError("mongodb.ip_remains_after_replace")
    return new_message, changed or len(new_message) != len(message)


def rewrite_mongo_stream(payload, ctx):
    """逐 message 改写 MongoDB TCP stream。"""
    out = bytearray()
    pos = 0
    changed = False
    while pos < len(payload):
        if pos + 16 > len(payload):
            tail = payload[pos:]
            if has_old_material(tail, ctx):
                raise RewriteError("mongodb.trailing_incomplete_message_with_ip")
            out.extend(tail)
            break
        msg_len = int32_le(payload, pos)
        end = pos + msg_len
        if msg_len < 16 or end > len(payload):
            tail = payload[pos:]
            if has_old_material(tail, ctx):
                raise RewriteError("mongodb.incomplete_message_with_ip")
            out.extend(tail)
            break
        new_message, msg_changed = rewrite_mongo_message(payload[pos:end], ctx)
        out.extend(new_message)
        changed = changed or msg_changed
        pos = end
    return bytes(out), changed


class MongoDBHandler(ProtocolHandler):
    """MongoDB Wire Protocol 改写处理器。"""

    name = "mongodb"

    def detect(self, payload, ctx):
        if ctx.proto_name != "TCP" or not payload:
            return False
        return is_mongo_port(ctx) or looks_like_mongo(payload)

    def rewrite(self, payload, ctx):
        try:
            new_payload, changed = rewrite_mongo_stream(payload, ctx)
        except RewriteError:
            if has_old_material(payload, ctx):
                raise
            return RewriteResult(True, False, payload, "mongodb.unparsed_without_ip")
        return RewriteResult(True, changed, new_payload, "mongodb" if changed else "mongodb.unchanged")
