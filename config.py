# -*- coding: utf-8 -*-
"""
全局常量配置：TCP/UDP 阈值、正则表达式、端口号等。
所有模块按需从此处导入，避免硬编码散落各处。
"""

import re

# =============================================================================
# TCP/UDP 最大 payload 与链路层帧长限制
# =============================================================================

DEFAULT_TCP_MAX_PAYLOAD = 1460
DEFAULT_UDP_MAX_PAYLOAD = 1472
DEFAULT_MAX_FRAME_LEN = 1514

# =============================================================================
# TCP 标志位（用于 SYN/FIN/RST/PSH/ACK 判断）
# =============================================================================

TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10

# TCP 序列号是 32 位环形空间，流重组和 ACK 映射都依赖这两个边界。
TCP_SEQ_MOD = 2 ** 32
TCP_SEQ_HALF = 2 ** 31

# =============================================================================
# TLS 相关常量
# =============================================================================

# TLS record content-type：ChangeCipherSpec、Alert、Handshake、ApplicationData。
TLS_CONTENT_TYPES = (0x14, 0x15, 0x16, 0x17)
TLS_MINOR_VERSIONS = (0x00, 0x01, 0x02, 0x03, 0x04)
TLS_MAX_RECORD_LEN = 16384 + 2048

# =============================================================================
# QUIC 与 DTLS 相关
# =============================================================================

COMMON_QUIC_PORTS = {443, 8443}

# =============================================================================
# HTTP 相关
# =============================================================================

HTTP_HEADER_END = b"\r\n\r\n"
HTTP2_CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

HTTP_REQUEST_RE = re.compile(
    rb"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE|"
    rb"PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|REPORT) "
    rb"[\x21-\x7e]+ HTTP/[12]\.[0-9]\r\n"
)
HTTP_RESPONSE_RE = re.compile(
    rb"HTTP/[12]\.[0-9] [1-5][0-9]{2}(?: [\x20-\x7e]*)?\r\n"
)

HTTP1_REQUEST_LINE_RE = re.compile(
    rb"^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE|"
    rb"PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|REPORT) "
    rb"[\x21-\x7e]+ HTTP/1\.[01]$"
)
HTTP1_RESPONSE_LINE_RE = re.compile(
    rb"^HTTP/1\.[01] [1-5][0-9]{2}(?: [\x20-\x7e]*)?$"
)

# =============================================================================
# 已知明文协议 banner 正则（用于识别但不实现结构化替换）
# =============================================================================

SSH_BANNER_RE = re.compile(rb"SSH-[12]\.[0-9]+-[\x20-\x7e]+\r?\n")
FTP_GREETING_RE = re.compile(rb"220[ -][\x20-\x7e]*?FTP[\x20-\x7e]*\r\n", re.IGNORECASE)
SMTP_GREETING_RE = re.compile(rb"220[ -][\x20-\x7e]*?E?SMTP[\x20-\x7e]*\r\n", re.IGNORECASE)
POP3_GREETING_RE = re.compile(rb"\+OK[\x20-\x7e]*POP3[\x20-\x7e]*\r\n", re.IGNORECASE)
IMAP_GREETING_RE = re.compile(rb"\* OK [\x20-\x7e]*IMAP[\x20-\x7e]*\r\n", re.IGNORECASE)

# =============================================================================
# 数据库 / 代理默认端口
# =============================================================================

MYSQL_PORT = 3306
POSTGRES_PORT = 5432
REDIS_PORT = 6379
SOCKS_PORT = 1080

# =============================================================================
# MySQL / PostgreSQL 命令标识
# =============================================================================

MYSQL_CMD_QUERY = 0x03
PG_QUERY_MESSAGE = ord("Q")
