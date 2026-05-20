# -*- coding: utf-8 -*-
"""
MySQL 协议改写：仅替换 COM_QUERY(0x03) 命令的 SQL 文本中的 IPv4。
逐 packet 解析并更新 payload 长度字段。
"""

from core.context import RewriteError, RewriteResult, is_port
from core.dispatcher import ProtocolHandler
from config import MYSQL_PORT, MYSQL_CMD_QUERY


def parse_mysql_payload_len(header):
    """
    解析 MySQL packet header 中的 payload 长度（3 字节小端）。
    :param header: 前 3 字节
    """
    return header[0] | (header[1] << 8) | (header[2] << 16)


def build_mysql_packet(sequence_id, payload):
    """
    构造 MySQL packet：3 字节小端长度 + 1 字节 seq_id + payload。
    :param sequence_id: packet sequence id
    :param payload: 协议负载字节串
    """
    payload_len = len(payload)
    if payload_len >= (1 << 24):
        raise RewriteError("mysql.packet_too_large_after_replace")
    header = bytes([
        payload_len & 0xFF,
        (payload_len >> 8) & 0xFF,
        (payload_len >> 16) & 0xFF,
        sequence_id,
    ])
    return header + payload


class MySQLHandler(ProtocolHandler):
    """MySQL 协议改写处理器。"""

    name = "mysql"

    def detect(self, payload, ctx):
        """TCP 且端口=3306，或首包为 COM_QUERY 结构时命中。"""
        if ctx.proto_name != "TCP" or not payload:
            return False
        if is_port(ctx, MYSQL_PORT):
            return True
        # 非 3306 端口时只做非常保守的 COM_QUERY 结构判断
        if len(payload) >= 5:
            plen = parse_mysql_payload_len(payload[:3])
            return plen + 4 <= len(payload) and payload[4] == MYSQL_CMD_QUERY
        return False

    def rewrite(self, payload, ctx):
        """
        逐 packet 解析：
        - COM_QUERY(0x03): 替换 SQL 文本中的 IP，重新构造 packet
        - 其他命令：含旧 IP 则拒绝，不含则原样保留
        """
        out = bytearray()
        pos = 0
        changed = False
        n = len(payload)

        while pos < n:
            # 至少需要 4 字节 packet header
            if pos + 4 > n:
                tail = payload[pos:]
                if ctx.old_ip in tail:
                    raise RewriteError("mysql.trailing_incomplete_packet_with_ip")
                out.extend(tail)
                break

            packet_len = parse_mysql_payload_len(payload[pos:pos + 3])
            seq_id = payload[pos + 3]
            end = pos + 4 + packet_len
            if packet_len == 0 or end > n:
                tail = payload[pos:]
                if ctx.old_ip in tail:
                    raise RewriteError("mysql.incomplete_packet_with_ip")
                out.extend(tail)
                break

            packet_payload = payload[pos + 4:end]
            if not packet_payload:
                out.extend(payload[pos:end])
                pos = end
                continue

            cmd = packet_payload[0]
            if cmd == MYSQL_CMD_QUERY:
                # COM_QUERY: 命令字节后的部分是 SQL 文本
                sql = packet_payload[1:]
                new_sql = sql.replace(ctx.old_ip, ctx.new_ip)
                new_packet_payload = bytes([cmd]) + new_sql
                if new_packet_payload != packet_payload:
                    changed = True
                out.extend(build_mysql_packet(seq_id, new_packet_payload))
            else:
                # 非 COM_QUERY 命令含旧 IP 时拒绝（二进制协议不安全）
                if ctx.old_ip in packet_payload:
                    raise RewriteError(f"mysql.command_{cmd:#04x}_with_ip_not_supported")
                out.extend(payload[pos:end])
            pos = end

        label = "mysql.query" if changed else "mysql.unchanged"
        return RewriteResult(True, changed, bytes(out), label)
