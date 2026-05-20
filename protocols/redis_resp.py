# -*- coding: utf-8 -*-
"""
Redis RESP 协议改写：递归解析 RESP 元素，替换 SimpleString(+)、Error(-)、
BulkString($) 中的 IPv4 文本。更新 BulkString 的长度前缀。
"""

from core.context import RewriteError, RewriteResult, is_port
from core.dispatcher import ProtocolHandler
from config import REDIS_PORT


def read_resp_line(data, pos):
    """
    读取 Redis RESP 中以 \\r\\n 结尾的一行。
    :return: (行内容, 下一偏移)
    """
    end = data.find(b"\r\n", pos)
    if end < 0:
        raise RewriteError("redis.incomplete_line")
    return data[pos:end], end + 2


def rewrite_resp_element(data, pos, ctx):
    """
    递归改写单个 Redis RESP 元素。
    支持 SimpleString(+)、Error(-)、Integer(:)、BulkString($)、Array(*)。
    :return: (新元素字节串, 下一偏移, 是否变化)
    """
    if pos >= len(data):
        raise RewriteError("redis.empty_element")
    prefix = data[pos:pos + 1]

    # SimpleString(+)、Error(-)、Integer(:)：读取一行，只对 + 和 - 做文本替换
    if prefix in (b"+", b"-", b":"):
        line, new_pos = read_resp_line(data, pos + 1)
        new_line = line.replace(ctx.old_ip, ctx.new_ip) if prefix in (b"+", b"-") else line
        return prefix + new_line + b"\r\n", new_pos, new_line != line

    # BulkString($): 读取长度行 + 数据块，替换后更新长度
    if prefix == b"$":
        len_line, data_start = read_resp_line(data, pos + 1)
        try:
            bulk_len = int(len_line)
        except ValueError as exc:
            raise RewriteError("redis.invalid_bulk_len") from exc
        if bulk_len == -1:  # Null Bulk String
            return b"$-1\r\n", data_start, False
        if bulk_len < -1:
            raise RewriteError("redis.invalid_negative_bulk_len")
        data_end = data_start + bulk_len
        if data_end + 2 > len(data):
            raise RewriteError("redis.incomplete_bulk_data")
        if data[data_end:data_end + 2] != b"\r\n":
            raise RewriteError("redis.bulk_missing_crlf")
        bulk_data = data[data_start:data_end]
        new_bulk = bulk_data.replace(ctx.old_ip, ctx.new_ip)
        rewritten = (
            b"$" + str(len(new_bulk)).encode("ascii") + b"\r\n"
            + new_bulk + b"\r\n"
        )
        return rewritten, data_end + 2, new_bulk != bulk_data

    # Array(*): 读取元素个数，递归处理每个子元素
    if prefix == b"*":
        count_line, elem_pos = read_resp_line(data, pos + 1)
        try:
            count = int(count_line)
        except ValueError as exc:
            raise RewriteError("redis.invalid_array_len") from exc
        if count == -1:  # Null Array
            return b"*-1\r\n", elem_pos, False
        if count < -1:
            raise RewriteError("redis.invalid_negative_array_len")
        out = bytearray(b"*" + str(count).encode("ascii") + b"\r\n")
        changed = False
        for _ in range(count):
            new_elem, elem_pos, elem_changed = rewrite_resp_element(data, elem_pos, ctx)
            out.extend(new_elem)
            changed = changed or elem_changed
        return bytes(out), elem_pos, changed

    raise RewriteError(f"redis.unknown_prefix_{prefix!r}")


class RedisRESPHandler(ProtocolHandler):
    """Redis RESP 协议改写处理器。"""

    name = "redis"

    def detect(self, payload, ctx):
        """TCP 且端口=6379，或首字节为 RESP 类型前缀时命中。"""
        if ctx.proto_name != "TCP" or not payload:
            return False
        if is_port(ctx, REDIS_PORT):
            return True
        return payload[:1] in (b"*", b"$", b"+", b"-", b":")

    def rewrite(self, payload, ctx):
        """
        递归解析整个 payload 中的 RESP 元素序列。
        如果解析失败且 payload 不含旧 IP，安全跳过；
        含旧 IP 则抛出异常（交给上层 fallback）。
        """
        out = bytearray()
        pos = 0
        changed = False
        try:
            while pos < len(payload):
                elem, pos, elem_changed = rewrite_resp_element(payload, pos, ctx)
                out.extend(elem)
                changed = changed or elem_changed
        except RewriteError:
            if ctx.old_ip in payload:
                raise
            return RewriteResult(True, False, payload, "redis.unparsed_without_ip")
        label = "redis.resp" if changed else "redis.unchanged"
        return RewriteResult(True, changed, bytes(out), label)
