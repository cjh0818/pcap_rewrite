# -*- coding: utf-8 -*-
"""
PostgreSQL 协议改写：仅替换 Query(Q) 消息的 SQL 文本中的 IPv4。
逐 message 解析并更新 message length 字段。

策略：
- Query(Q): 替换 null-terminated SQL 文本中的 IPv4，并更新 4 字节大端 message length。
- 非 Query 消息：即使 body 中包含旧 IP，也不盲改；原样保留并标记 skip，不抛异常回滚整条 TCP stream。
- 畸形消息（长度无效 / 无 null 终止符 / 不完整）：含旧 IP 时原样保留并标记 skip，继续处理后续消息。
"""

from core.context import RewriteResult, is_port
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
        - 其他消息类型：不解析、不改写；即使含旧 IP 也原样保留，避免回滚整条 TCP stream
        - 畸形 / 不完整消息：原样保留并标记 skip，不抛异常
        """
        out = bytearray()
        pos = 0
        changed = False
        skipped_unsupported_with_ip = False
        skipped_incomplete_with_ip = False
        n = len(payload)

        while pos < n:
            if pos + 5 > n:
                tail = payload[pos:]
                if ctx.old_ip in tail:
                    skipped_incomplete_with_ip = True
                out.extend(tail)
                break

            msg_type = payload[pos]
            msg_len = int.from_bytes(payload[pos + 1:pos + 5], "big")
            if msg_len < 4:
                if ctx.old_ip in payload[pos:]:
                    skipped_incomplete_with_ip = True
                out.extend(payload[pos:])
                break
            end = pos + 1 + msg_len
            if end > n:
                tail = payload[pos:]
                if ctx.old_ip in tail:
                    skipped_incomplete_with_ip = True
                out.extend(tail)
                break

            body = payload[pos + 5:end]
            if msg_type == PG_QUERY_MESSAGE:
                if not body.endswith(b"\x00"):
                    # 畸形 Query 消息缺少 null 终止符，跳过而非抛异常
                    if ctx.old_ip in body:
                        skipped_unsupported_with_ip = True
                    out.extend(payload[pos:end])
                    pos = end
                    continue
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
                # 非 Query 消息不安全解析：不盲改，但也不抛异常回滚整条 TCP stream。
                if ctx.old_ip in body:
                    skipped_unsupported_with_ip = True
                out.extend(payload[pos:end])
            pos = end

        if changed and skipped_unsupported_with_ip:
            label = "postgresql.query+unsupported_skipped"
        elif changed and skipped_incomplete_with_ip:
            label = "postgresql.query+incomplete_skipped"
        elif changed:
            label = "postgresql.query"
        elif skipped_unsupported_with_ip:
            label = "postgresql.unsupported_skipped"
        elif skipped_incomplete_with_ip:
            label = "postgresql.incomplete_skipped"
        else:
            label = "postgresql.unchanged"

        return RewriteResult(True, changed, bytes(out), label)
