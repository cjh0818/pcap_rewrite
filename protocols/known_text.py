# -*- coding: utf-8 -*-
"""
已知明文协议识别但不替换：SSH / FTP / SMTP / POP3 / IMAP。
这些协议的 banner 中包含明文，但没有实现结构化替换，
含旧 IP 时拒绝，不含时安全跳过。
"""

from core.context import RewriteResult
from core.dispatcher import ProtocolHandler
from config import SSH_BANNER_RE, FTP_GREETING_RE, SMTP_GREETING_RE, POP3_GREETING_RE, IMAP_GREETING_RE


class KnownUnsupportedTextHandler(ProtocolHandler):
    """已知明文协议但未实现结构化替换，统一拒绝。"""

    name = "known_text.reject"

    patterns = (
        ("ssh", SSH_BANNER_RE),
        ("ftp", FTP_GREETING_RE),
        ("smtp", SMTP_GREETING_RE),
        ("pop3", POP3_GREETING_RE),
        ("imap", IMAP_GREETING_RE),
    )

    def detect(self, payload, ctx):
        """TCP 且匹配任一已知明文协议 banner 正则时命中。"""
        if ctx.proto_name != "TCP":
            return False
        return any(regex.match(payload) for _, regex in self.patterns)

    def rewrite(self, payload, ctx):
        """
        确定具体协议名称后：含旧 IP 则拒绝（未实现结构化替换），
        否则安全跳过。
        """
        label = "known_text"
        for name, regex in self.patterns:
            if regex.match(payload):
                label = name
                break
        if ctx.old_ip in payload:
            return RewriteResult(False, False, payload, f"{label}.not_supported", f"{label}.with_ip")
        return RewriteResult(True, False, payload, f"{label}.unchanged")
