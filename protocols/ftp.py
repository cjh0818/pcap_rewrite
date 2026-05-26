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


def has_ftp_port_tail(payload, pos):
    """
    判断 comma IPv4 之后是否紧跟 FTP host-port 的 ",p1,p2"。
    通用边界函数会把这个逗号当作 IP 继续字符，但在 FTP PORT/PASV 中它是端口分隔符。
    """
    if pos >= len(payload) or payload[pos] != ord(","):
        return False
    pos += 1
    first_start = pos
    while pos < len(payload) and payload[pos:pos + 1].isdigit() and pos - first_start < 3:
        pos += 1
    if pos == first_start or pos >= len(payload) or payload[pos] != ord(","):
        return False
    pos += 1
    second_start = pos
    while pos < len(payload) and payload[pos:pos + 1].isdigit() and pos - second_start < 3:
        pos += 1
    if pos == second_start:
        return False
    return pos == len(payload) or payload[pos] not in IP_COMMA_BOUNDARY_BYTES


def replace_ftp_comma_ipv4(payload, old_comma, new_comma):
    """
    替换 FTP 的 h1,h2,h3,h4 形式 IPv4，同时支持后接 ,p1,p2 的 host-port。
    """
    if not old_comma:
        return payload, False
    out = bytearray()
    pos = 0
    old_len = len(old_comma)
    changed = False
    while True:
        match = payload.find(old_comma, pos)
        if match < 0:
            out.extend(payload[pos:])
            break
        right = match + old_len
        left_ok = match == 0 or payload[match - 1] not in IP_COMMA_BOUNDARY_BYTES
        right_ok = (
            right == len(payload)
            or payload[right] not in IP_COMMA_BOUNDARY_BYTES
            or has_ftp_port_tail(payload, right)
        )
        if left_ok and right_ok:
            out.extend(payload[pos:match])
            out.extend(new_comma)
            changed = True
        else:
            out.extend(payload[pos:right])
        pos = right
    return bytes(out), changed


def rewrite_ftp_payload(payload, ctx):
    """替换 dotted IPv4 和逗号分隔 IPv4。"""
    new_payload = payload
    labels = []
    new_payload, ascii_changed = replace_ip_text_boundary(new_payload, ctx.old_ip, ctx.new_ip)
    if ascii_changed:
        labels.append("ascii")

    old_comma = ctx.args.old_ip.replace(".", ",").encode("ascii")
    new_comma = ctx.args.new_ip.replace(".", ",").encode("ascii")
    new_payload, comma_changed = replace_ftp_comma_ipv4(new_payload, old_comma, new_comma)
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
