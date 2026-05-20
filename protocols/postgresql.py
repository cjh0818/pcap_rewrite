# -*- coding: utf-8 -*-
"""
PostgreSQL 协议改写：仅替换 Query(Q) 消息的 SQL 文本中的 IPv4。
逐 message 解析并更新 message length 字段。
"""

from core.context import RewriteError, RewriteResult, is_port
from core.dispatcher import ProtocolHandler
from config import POSTGRES_PORT, PG_QUERY_MESSAGE


class PostgreSQLHandler(ProtocolHandler):
    """PostgreSQL 协议改写处理器。"""

    name = "postgresql"

    def detect(self, payload, ctx):
        """TCP 且端口=5432，或首字节为 'Q'(Query) 时命中。"""
        if ctx.proto_name != "TCP" or not payload:
            return False
        if is_port(ctx, POSTGRES_PORT):
            return True
        # 非标准端口只识别 Query message（1 字节 type + 4 字节 len）
        return len(payload) >= 6 and payload[0] == PG_QUERY_MESSAGE

    def rewrite(self, payload, ctx):
        """
        逐 message 解析 PostgreSQL 前端消息：
        - 消息格式: 1 字节 type + 4 字节大端长度(含自身) + body
        - Query(Q): body 是 null-terminated SQL，替换 SQL 后更新长度
        - 其他消息类型：含旧 IP 则拒绝
        """
        out = bytearray()
        pos = 0
        changed = False
        n = len(payload)

        while pos < n:
            if pos + 5 > n:
                tail = payload[pos:]
                if ctx.old_ip in tail:
                    raise RewriteError("postgresql.trailing_incomplete_message_with_ip")
                out.extend(tail)
                break

            msg_type = payload[pos]
            msg_len = int.from_bytes(payload[pos + 1:pos + 5], "big")
            if msg_len < 4:
                if ctx.old_ip in payload[pos:]:
                    raise RewriteError("postgresql.invalid_message_length_with_ip")
                out.extend(payload[pos:])
                break
            end = pos + 1 + msg_len
            if end > n:
                tail = payload[pos:]
                if ctx.old_ip in tail:
                    raise RewriteError("postgresql.incomplete_message_with_ip")
                out.extend(tail)
                break

            body = payload[pos + 5:end]
            if msg_type == PG_QUERY_MESSAGE:
                if not body.endswith(b"\x00"):
                    raise RewriteError("postgresql.query_without_null_terminator")
                # SQL 文本 = body 去掉末尾 null 终止符
                sql = body[:-1]
                new_sql = sql.replace(ctx.old_ip, ctx.new_ip)
                new_body = new_sql + b"\x00"
                new_len = len(new_body) + 4  # +4 是长度字段自身
                out.append(msg_type)
                out.extend(new_len.to_bytes(4, "big"))
                out.extend(new_body)
                if new_body != body:
                    changed = True
            else:
                if ctx.old_ip in body:
                    raise RewriteError(f"postgresql.msg_type_{chr(msg_type)!r}_with_ip_not_supported")
                out.extend(payload[pos:end])
            pos = end

        label = "postgresql.query" if changed else "postgresql.unchanged"
        return RewriteResult(True, changed, bytes(out), label)
