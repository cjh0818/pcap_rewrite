# -*- coding: utf-8 -*-
"""
协议模块：注册所有应用层协议 handler 并构造 TCP/UDP 分发器。

注册顺序非常重要：越结构化、越安全的 handler 越靠前；raw 必须最后。
"""

from core.dispatcher import HandlerDispatcher
from protocols.websocket import WebSocketHandler
from protocols.tls_sni import TLSClientHelloSNIHandler
from protocols.http2 import HTTP2RejectHandler
from protocols.http1 import HTTP1Handler
from protocols.mysql import MySQLHandler
from protocols.postgresql import PostgreSQLHandler
from protocols.redis_resp import RedisRESPHandler
from protocols.socks5 import SOCKS5Handler
from protocols.known_text import KnownUnsupportedTextHandler
from protocols.tcp_raw import RawTCPHandler
from protocols.dtls import DTLSRejectHandler
from protocols.quic import QUICRejectHandler
from protocols.udp_raw import RawUDPHandler

# WebSocketHandler 依赖 HTTP Upgrade 状态，必须在 raw 之前，但在 HTTP 相关 handler 之后。

TCP_DISPATCHER = HandlerDispatcher([
    WebSocketHandler(),
    TLSClientHelloSNIHandler(),
    HTTP2RejectHandler(),
    HTTP1Handler(),
    MySQLHandler(),
    PostgreSQLHandler(),
    RedisRESPHandler(),
    SOCKS5Handler(),
    KnownUnsupportedTextHandler(),
    RawTCPHandler(),
])

UDP_DISPATCHER = HandlerDispatcher([
    DTLSRejectHandler(),
    QUICRejectHandler(),
    RawUDPHandler(),
])
