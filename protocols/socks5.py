# -*- coding: utf-8 -*-
"""
SOCKS5 协议改写：替换请求中的 IPv4 地址（ATYP=0x01）和域名（ATYP=0x03）中的 IP 文本。
支持 Greeting 和 Request 消息的识别。

安全边界：
- 传入的是完整 TCP 单方向字节流，逐消息解析
- 握手后的代理流量重新交给 TCP dispatcher 识别内层协议
- 不支持的 ATYP（IPv6 / 未知类型）或畸形消息中含旧 IP 时拒绝，避免静默漏改
"""

from core.context import RewriteError, RewriteResult, is_port
from core.dispatcher import ProtocolHandler
from core.utils import contains_ip_text_boundary, replace_ip_text_boundary
from config import HTTP_REQUEST_RE, HTTP_RESPONSE_RE, SOCKS_PORT
from protocols.http1 import rewrite_http1_stream_safe


class SOCKS5Handler(ProtocolHandler):
    """SOCKS5 协议改写处理器。"""

    name = "socks5"
    REQUEST_ATYPS = {0x01, 0x03, 0x04}

    def detect(self, payload, ctx):
        """TCP 且端口=1080 或首字节为 0x05(SOCKS5 VER)。"""
        if ctx.proto_name != "TCP" or len(payload) < 2:
            return False
        if is_port(ctx, SOCKS_PORT):
            return True
        return payload[0] == 0x05 and len(payload) >= 3

    def rewrite(self, payload, ctx):
        """
        Greeting 无地址字段直接跳过。
        Request 按 ATYP 分别处理：
        - 0x01(IPv4): 等长替换 4 字节二进制 IP
        - 0x03(Domain): 在域名中替换 IP 文本，更新域名长度
        - 0x04(IPv6): 不支持，含旧 IP 时跳过而非抛异常
        - 未知 ATYP: 含旧 IP 时跳过而非抛异常
        """
        buf = bytearray(payload)
        pos = 0
        changed = False
        labels = []
        requires_stream_merge = None

        while pos < len(buf):
            if buf[pos] != 0x05:
                tail = bytes(buf[pos:])
                result = self._rewrite_tunnel_tail(tail, ctx)
                if not result.ok:
                    return RewriteResult(False, False, payload, f"socks5.tail.{result.label}", result.reason)
                buf[pos:] = result.payload
                changed = changed or result.changed
                requires_stream_merge = result.requires_stream_merge
                labels.append(f"tail.{result.label}")
                break

            parsed = self._rewrite_request_message(buf, pos, ctx)
            if parsed is not None:
                msg_changed, pos, label = parsed
                changed = changed or msg_changed
                if msg_changed and len(buf) != len(payload):
                    # SOCKS5 域名型请求可变长；变长后不应强行保留旧 TCP segment 边界。
                    requires_stream_merge = True
                labels.append(label)
                continue

            parsed = self._skip_greeting_message(buf, pos)
            if parsed is not None:
                pos, label = parsed
                labels.append(label)
                continue

            parsed = self._skip_method_selection_message(buf, pos)
            if parsed is not None:
                pos, label = parsed
                labels.append(label)
                continue

            labels.append(self._unsupported_or_incomplete_label(bytes(buf[pos:]), ctx))
            break

        return RewriteResult(
            True,
            changed,
            bytes(buf),
            self._label(labels),
            requires_stream_merge=requires_stream_merge,
        )

    def _rewrite_tunnel_tail(self, tail, ctx):
        """SOCKS 握手后的 HTTP/WebSocket 流量必须走 HTTP 流级安全入口。"""
        ws_state = ctx.tcp_state()
        if (
            HTTP_REQUEST_RE.match(tail)
            or HTTP_RESPONSE_RE.match(tail)
            or ws_state.get("websocket_pending")
            or ws_state.get("websocket_established")
        ):
            result = rewrite_http1_stream_safe(tail, ctx, ctx.args)
            result.requires_stream_merge = True
            return result
        from protocols import TCP_DISPATCHER
        handler = TCP_DISPATCHER.select_handler(tail, ctx, exclude={SOCKS5Handler})
        result = TCP_DISPATCHER.rewrite(tail, ctx, exclude={SOCKS5Handler})
        inner_requires_merge = bool(getattr(handler, "requires_stream_merge", False))
        # 内层协议要求合并，或 tunnel tail 发生变长改写时，把策略冒泡给外层 SOCKS5 流。
        result.requires_stream_merge = inner_requires_merge or len(result.payload) != len(tail)
        return result

    def _rewrite_request_message(self, buf, pos, ctx):
        """改写单个 Request/Reply 消息；不是该消息时返回 None。"""
        if len(buf) < pos + 4 or buf[pos + 2] != 0x00:
            return None

        atyp = buf[pos + 3]
        if atyp not in self.REQUEST_ATYPS:
            return None

        addr_pos = pos + 4

        if atyp == 0x01:  # IPv4 二进制，固定 4 字节
            end = addr_pos + 4 + 2
            if len(buf) < end:
                if contains_ip_text_boundary(bytes(buf[pos:]), ctx.old_ip):
                    raise RewriteError("socks5.ipv4_incomplete_with_ip")
                label = "socks5.ipv4_incomplete"
                return False, len(buf), label
            addr = bytes(buf[addr_pos:addr_pos + 4])
            changed = False
            if addr == ctx.old_ip_bin:
                # 等长替换 packed IPv4
                buf[addr_pos:addr_pos + 4] = ctx.new_ip_bin
                changed = True
            label = "socks5.ipv4" if changed else "socks5.ipv4.unchanged"
            return changed, end, label

        if atyp == 0x03:  # 域名：1 字节长度 + 域名 + 2 字节端口
            if len(buf) < addr_pos + 1:
                if contains_ip_text_boundary(bytes(buf[pos:]), ctx.old_ip):
                    raise RewriteError("socks5.domain_missing_len_with_ip")
                label = "socks5.domain_missing_len"
                return False, len(buf), label
            dom_len = buf[addr_pos]
            dom_start = addr_pos + 1
            dom_end = dom_start + dom_len
            end = dom_end + 2
            if len(buf) < end:
                if contains_ip_text_boundary(bytes(buf[pos:]), ctx.old_ip):
                    raise RewriteError("socks5.domain_incomplete_with_ip")
                label = "socks5.domain_incomplete"
                return False, len(buf), label
            domain = bytes(buf[dom_start:dom_end])
            new_domain, domain_changed = replace_ip_text_boundary(domain, ctx.old_ip, ctx.new_ip)
            if len(new_domain) > 255:
                if contains_ip_text_boundary(bytes(buf[pos:end]), ctx.old_ip):
                    raise RewriteError("socks5.domain_too_long_with_ip")
                label = "socks5.domain_too_long"
                return False, end, label
            changed = False
            if domain_changed:
                buf[addr_pos] = len(new_domain)
                buf[dom_start:dom_end] = new_domain
                end = dom_start + len(new_domain) + 2
                changed = True
            label = "socks5.domain" if changed else "socks5.domain.unchanged"
            return changed, end, label

        if atyp == 0x04:  # IPv6 — 不支持，跳过而非抛异常
            end = addr_pos + 16 + 2
            if len(buf) < end:
                if contains_ip_text_boundary(bytes(buf[pos:]), ctx.old_ip):
                    raise RewriteError("socks5.ipv6_incomplete_with_ip")
                label = "socks5.ipv6_incomplete"
                return False, len(buf), label
            if contains_ip_text_boundary(bytes(buf[pos:end]), ctx.old_ip):
                raise RewriteError("socks5.ipv6_with_ip_not_supported")
            label = "socks5.ipv6.unchanged"
            return False, end, label

        return None

    def _skip_greeting_message(self, buf, pos):
        """跳过 Greeting: VER(1) + NMETHODS(1) + METHODS(N)。"""
        if len(buf) < pos + 2:
            return None
        if buf[pos + 1] == 0:
            return None
        end = pos + 2 + buf[pos + 1]
        if len(buf) < end:
            return None
        return end, "socks5.greeting"

    def _skip_method_selection_message(self, buf, pos):
        """跳过 Server Method Selection: VER(1) + METHOD(1)。"""
        if len(buf) < pos + 2:
            return None
        end = pos + 2
        return end, "socks5.method_selection"

    def _unsupported_or_incomplete_label(self, payload, ctx):
        """保留旧逻辑：未知 ATYP 或畸形消息中含旧 IP 时只跳过。"""
        if len(payload) >= 4 and payload[0] == 0x05 and payload[2] == 0x00:
            atyp = payload[3]
            if contains_ip_text_boundary(payload, ctx.old_ip):
                raise RewriteError(f"socks5.atyp_{atyp:#x}_with_ip_not_supported")
            return "socks5.unchanged"
        return self._unrecognized_label(payload, ctx)

    def _unrecognized_label(self, payload, ctx):
        if contains_ip_text_boundary(payload, ctx.old_ip):
            raise RewriteError("socks5.unrecognized_with_ip")
        return "socks5.unrecognized_without_ip"

    def _label(self, labels):
        if not labels:
            return "socks5.empty"
        if len(labels) == 1:
            return labels[0]
        suffix = "+".join(label.replace("socks5.", "") for label in labels)
        if len(suffix) > 120:
            suffix = f"{len(labels)}messages"
        return f"socks5.stream.{suffix}"
