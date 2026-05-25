# -*- coding: utf-8 -*-
"""
应用层协议 handler 基类与分发器。

handler 的顺序即协议优先级：结构化协议先处理，raw fallback 最后兜底。
"""

import traceback
import zlib
from abc import ABC, abstractmethod
from loguru import logger
from .context import RewriteError, RewriteResult


class ProtocolHandler(ABC):
    """
    应用层协议 handler 抽象基类。

    设计约束:
        - detect 只回答"当前 payload 是否属于我"，不修改数据包。
        - rewrite 只处理当前协议的结构和长度字段，不关心 TCP 重分段。
        - handler 之间不能互相调用，避免 HTTP/TLS/DB 协议逻辑耦合。

    流级合并控制:
        - requires_stream_merge=False（默认）：保留原始 TCP segment 边界，
          使用 map_offset 按 edits 映射每个 segment 的 new_stream 份额。
          适用于 FTP/SMTP/Telnet/MySQL/Pg/Redis/DNS/SOCKS5/WebSocket 等
          request-response 或交互式协议。
        - requires_stream_merge=True：将 new_stream 按 MTU 重新切包，
          不保留原始 segment 边界。适用于 HTTP body、MongoDB BSON 等可能
          跨多个 TCP segment 的协议，或 RawTCP 无结构兜底。
    """

    name = "base"
    requires_stream_merge: bool = False

    @abstractmethod
    def detect(self, payload, ctx):
        """
        判断当前 handler 是否负责这段 payload。
        :param payload: 协议负载字节串
        :param ctx: RewriteContext 改写上下文
        """
        raise NotImplementedError

    @abstractmethod
    def rewrite(self, payload, ctx):
        """
        在 handler 自己的协议边界内执行 payload 改写。
        :param payload: 协议负载字节串
        :param ctx: RewriteContext 改写上下文
        :return: RewriteResult
        """
        raise NotImplementedError


class HandlerDispatcher:
    """
    按优先级选择唯一应用层 handler，并把异常归一化为 RewriteResult。

    分发策略:
        - detect 从上到下执行，先命中的 handler 拥有当前 payload。
        - detect 阶段异常通常代表误判或半包，记录 debug 后继续分发。
        - rewrite 阶段异常代表"已命中协议但不能安全修改"，返回失败。
        - RawTCPHandler/RawUDPHandler 放在最后，实现字节级 fallback。
    """

    def __init__(self, handlers):
        """
        :param handlers: 按优先级排列的协议 handler 实例列表
        """
        # tuple 防止运行中被外部代码意外增删 handler。
        self.handlers = tuple(handlers)

    def rewrite(self, payload, ctx, exclude=None):
        """
        对单段应用层 payload 执行"选择 handler -> 改写 -> 返回"。
        :param payload: 协议负载字节串
        :param ctx: RewriteContext
        :return: RewriteResult
        """
        # 每个 payload 只交给一个 handler，避免 HTTP body 被 raw fallback 二次替换。
        handler = self._select_handler(payload, ctx, exclude=exclude)
        if handler is None:
            return RewriteResult(True, False, payload, "none")
        return self._rewrite_with_handler(handler, payload, ctx)

    def select_handler(self, payload, ctx, exclude=None):
        """
        仅执行 detect 阶段，返回命中的 handler 或 None。
        供上层在调用 rewrite 之前判断 handler 的元属性（如 requires_stream_merge）。
        """
        return self._select_handler(payload, ctx, exclude=exclude)

    def _select_handler(self, payload, ctx, exclude=None):
        """
        从 handler 列表中选择第一个声明可处理当前 payload 的 handler。
        :param payload: 协议负载字节串
        :param ctx: RewriteContext
        :return: 命中的 ProtocolHandler 或 None
        """
        exclude = exclude or set()
        for handler in self.handlers:
            if handler.name in exclude or handler.__class__ in exclude:
                continue
            try:
                if handler.detect(payload, ctx):
                    return handler
            except RewriteError as exc:
                logger.debug(f"{handler.name}.detect 跳过: {exc}")
            except (AttributeError, IndexError, TypeError, ValueError) as exc:
                logger.debug(f"{handler.name}.detect 异常，继续 fallback: {exc}")
        return None

    def _rewrite_with_handler(self, handler, payload, ctx):
        """
        执行已选 handler，并保留拒绝原因，避免上层丢失协议上下文。
        :param handler: 已命中的 ProtocolHandler
        :param payload: 协议负载字节串
        :param ctx: RewriteContext
        :return: RewriteResult
        """
        try:
            return handler.rewrite(payload, ctx)
        except RewriteError as exc:
            return RewriteResult(False, False, payload, handler.name, str(exc))
        except (
            AttributeError,
            EOFError,
            IndexError,
            OSError,
            TypeError,
            ValueError,
            zlib.error,
        ) as exc:
            logger.debug(traceback.format_exc())
            return RewriteResult(False, False, payload, handler.name, f"unexpected_error:{exc}")
