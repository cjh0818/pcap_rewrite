# -*- coding: utf-8 -*-
"""
FTP 控制连接改写。

FTP control 是 CRLF 文本协议，没有消息长度字段。除 dotted IPv4 外，
也处理 PORT/PASV/EPRT 中常见的逗号分隔 IPv4 表示。
"""

import re

from core.context import RewriteResult, is_port
from core.dispatcher import ProtocolHandler
from core.utils import IP_COMMA_BOUNDARY_BYTES, replace_ip_text_boundary
from config import FTP_CONTROL_PORT, SMTP_PORTS


FTP_COMMAND_RE = re.compile(
    rb"^(?:USER|PASS|ACCT|CWD|CDUP|SMNT|QUIT|REIN|PORT|PASV|TYPE|STRU|MODE|"
    rb"RETR|STOR|STOU|APPE|ALLO|REST|RNFR|RNTO|ABOR|DELE|RMD|MKD|PWD|LIST|"
    rb"NLST|SITE|SYST|STAT|HELP|NOOP|FEAT|OPTS|AUTH|PBSZ|PROT|EPSV|EPRT)"
    rb"(?:\s|$)",
    re.IGNORECASE,
)
FTP_RESPONSE_RE = re.compile(rb"^[1-5][0-9]{2}(?:[ -]|\r\n)")


def looks_like_ftp_control(payload):
    """判断 payload 是否像 FTP 控制连接文本。"""
    if not payload:
        return False
    first_line = payload.split(b"\r\n", 1)[0]
    if FTP_COMMAND_RE.match(first_line):
        return True
    if not FTP_RESPONSE_RE.match(first_line):
        return False
    upper = first_line.upper()
    return b"FTP" in upper or first_line.startswith((b"227", b"229"))


def rewrite_ftp_payload(payload, ctx):
    """替换 dotted IPv4 和逗号分隔 IPv4。"""
    new_payload = payload
    labels = []
    new_payload, ascii_changed = replace_ip_text_boundary(new_payload, ctx.old_ip, ctx.new_ip)
    if ascii_changed:
        labels.append("ascii")

    old_comma = ctx.args.old_ip.replace(".", ",").encode("ascii")
    new_comma = ctx.args.new_ip.replace(".", ",").encode("ascii")
    new_payload, comma_changed = replace_ip_text_boundary(
        new_payload, old_comma, new_comma, boundary_bytes=IP_COMMA_BOUNDARY_BYTES,
    )
    if comma_changed:
        labels.append("comma")

    return new_payload, new_payload != payload, "+".join(labels) if labels else "unchanged"


class FTPHandler(ProtocolHandler):
    """FTP 控制连接改写处理器。"""

    name = "ftp"

    def detect(self, payload, ctx):
        if ctx.proto_name != "TCP" or not payload:
            return False
        ftp_port = is_port(ctx, FTP_CONTROL_PORT)
        if not ftp_port and (ctx.sport() in SMTP_PORTS or ctx.dport() in SMTP_PORTS):
            return False
        return ftp_port or looks_like_ftp_control(payload)

    def rewrite(self, payload, ctx):
        new_payload, changed, label = rewrite_ftp_payload(payload, ctx)
        return RewriteResult(True, changed, new_payload, f"ftp.{label}")
