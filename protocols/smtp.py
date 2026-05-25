# -*- coding: utf-8 -*-
"""
SMTP 明文协议改写。

SMTP control 与 DATA 都是 CRLF 文本流，不带应用层总长度字段；这里仅做
ASCII IPv4 文本替换。SMTPS/STARTTLS 之后的加密内容不在本 handler 中改写。
"""

import re

from core.context import RewriteResult
from core.dispatcher import ProtocolHandler
from core.utils import contains_ip_text_boundary, replace_ip_text_boundary
from config import SMTP_PORTS


SMTP_COMMAND_RE = re.compile(
    rb"^(?:EHLO|HELO|MAIL|RCPT|DATA|RSET|VRFY|EXPN|HELP|NOOP|QUIT|STARTTLS|AUTH|"
    rb"BDAT|SIZE)(?:\s|$)",
    re.IGNORECASE,
)
SMTP_RESPONSE_RE = re.compile(rb"^[245][0-9]{2}(?:[ -]|\r\n)")


def is_smtp_port(ctx):
    """判断当前 TCP 端口是否为常见 SMTP 明文端口。"""
    return ctx.sport() in SMTP_PORTS or ctx.dport() in SMTP_PORTS


def looks_like_smtp(payload):
    """判断 payload 是否像 SMTP 命令或响应。"""
    if not payload:
        return False
    first_line = payload.split(b"\r\n", 1)[0]
    return bool(SMTP_COMMAND_RE.match(first_line) or SMTP_RESPONSE_RE.match(first_line))


class SMTPHandler(ProtocolHandler):
    """SMTP 明文协议改写处理器。"""

    name = "smtp"

    def detect(self, payload, ctx):
        return ctx.proto_name == "TCP" and payload and (is_smtp_port(ctx) or looks_like_smtp(payload))

    def rewrite(self, payload, ctx):
        if not contains_ip_text_boundary(payload, ctx.old_ip):
            return RewriteResult(True, False, payload, "smtp.unchanged")
        new_payload, _ = replace_ip_text_boundary(payload, ctx.old_ip, ctx.new_ip)
        return RewriteResult(True, True, new_payload, "smtp.ascii")
