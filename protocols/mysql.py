# -*- coding: utf-8 -*-
"""
MySQL 协议改写：仅替换 COM_QUERY(0x03) 命令的 SQL 文本中的 IPv4。

安全边界：
- classic uncompressed MySQL protocol
- no TLS
- no compression
- no CLIENT_QUERY_ATTRIBUTES
- 仅在已拿到完整 MySQL packet 时解析/改写
    - 非 COM_QUERY 或无法完整解析的 payload 中含旧 IP 时拒绝整条流，
      避免 handler 命中后静默漏改。
"""

from core.context import RewriteError, RewriteResult, is_port
from core.dispatcher import ProtocolHandler
from core.utils import contains_ip_text_boundary, replace_ip_text_boundary
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
        解析 MySQL packet stream：
        - COM_QUERY(0x03): 替换 SQL 文本中的 IP，重新构造 packet 并更新 3 字节长度
        - 其他命令：不安全解析；即使含旧 IP，也原样保留并继续处理后续 packet
        - 不完整 packet：原样保留，不做盲替换
        """
        old_ip = ctx.old_ip
        new_ip = ctx.new_ip

        out = bytearray()
        pos = 0
        changed = False
        skipped_unsupported_with_ip = False
        skipped_incomplete_with_ip = False
        n = len(payload)

        while pos < n:
            # 至少需要 4 字节 packet header；不足则不能安全解析，原样保留。
            if pos + 4 > n:
                tail = payload[pos:]
                if contains_ip_text_boundary(tail, old_ip):
                    skipped_incomplete_with_ip = True
                out.extend(tail)
                break

            packet_len = parse_mysql_payload_len(payload[pos:pos + 3])
            seq_id = payload[pos + 3]
            end = pos + 4 + packet_len

            # packet_len==0 不一定值得强行改写；保持保守，原样保留。
            if packet_len == 0 or end > n:
                tail = payload[pos:]
                if contains_ip_text_boundary(tail, old_ip):
                    skipped_incomplete_with_ip = True
                out.extend(tail)
                break

            packet_payload = payload[pos + 4:end]
            if not packet_payload:
                out.extend(payload[pos:end])
                pos = end
                continue

            cmd = packet_payload[0]
            if cmd == MYSQL_CMD_QUERY:
                # 当前测试范围：无 CLIENT_QUERY_ATTRIBUTES，命令字节后的部分就是 SQL 文本。
                sql = packet_payload[1:]
                new_sql, _ = replace_ip_text_boundary(sql, old_ip, new_ip)
                new_packet_payload = bytes([cmd]) + new_sql
                if new_packet_payload != packet_payload:
                    changed = True
                out.extend(build_mysql_packet(seq_id, new_packet_payload))
            else:
                # 非 COM_QUERY 属于不支持的命令类型；含旧 IP 时后续统一拒绝。
                if contains_ip_text_boundary(packet_payload, old_ip):
                    skipped_unsupported_with_ip = True
                out.extend(payload[pos:end])

            pos = end

        if skipped_unsupported_with_ip or skipped_incomplete_with_ip:
            reason = "unsupported_with_ip" if skipped_unsupported_with_ip else "incomplete_with_ip"
            return RewriteResult(False, False, payload, "mysql.skipped_with_ip", reason)

        label = "mysql.query" if changed else "mysql.unchanged"

        return RewriteResult(True, changed, bytes(out), label)
