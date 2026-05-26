# -*- coding: utf-8 -*-
"""
核心数据类：改写上下文、结果对象、TCP 流状态、重分段计划。
"""

from dataclasses import dataclass, field
from collections import defaultdict


class RewriteError(Exception):
    """协议级改写无法安全继续时抛出的业务异常。"""


@dataclass
class RewriteResult:
    """
    统一承载应用层 handler 的处理结果，避免每个协议用不同返回格式。
    :param ok: True 表示 handler 已安全完成；False 表示命中协议但拒绝改写。
    :param changed: True 表示 payload 或协议内部长度字段发生了变化。
    :param payload: handler 输出的协议负载字节串，失败时通常等于输入字节串。
    :param label: 协议标签，用于日志定位具体处理器和子路径。
    :param reason: 拒绝或失败原因，便于批处理不中断时追踪风险包。
    :param requires_stream_merge: 动态覆盖 handler 的 TCP 重分段策略；None 表示使用静态属性。
    """
    ok: bool
    changed: bool
    payload: bytes
    label: str
    reason: str = ""
    requires_stream_merge: object = None


@dataclass
class RewriteContext:
    """
    为一次应用层改写传递稳定上下文，避免 handler 直接依赖全局变量。
    :param args: 命令行参数对象，包含 old_ip、new_ip、阈值和开关配置。
    :param ip_layer: Scapy IP 层对象，handler 可读取方向和地址。
    :param transport_layer: Scapy TCP 或 UDP 层对象，用于读取端口和 TCP 状态。
    :param proto_name: 传输层协议名称（TCP 或 UDP），用于限制 handler 适用范围。
    :param packet_index: 当前包在 PCAP 中的帧号，日志定位时使用。
    :param flow_key: 当前单方向 TCP 流标识，用于重组流级处理。
    :param conn_key: 当前 TCP 连接标识，用于两个方向共享 WebSocket 等状态。
    :param flow_state: 跨方向共享状态表，避免协议切换状态写入全局变量。
    """
    args: object
    ip_layer: object
    transport_layer: object
    proto_name: str
    packet_index: int
    flow_key: object = None
    conn_key: object = None
    flow_state: object = None

    @property
    def old_ip(self):
        """读取旧 IPv4 文本字节。"""
        return self.args.old_ip_bytes

    @property
    def new_ip(self):
        """读取新 IPv4 文本字节。"""
        return self.args.new_ip_bytes

    @property
    def old_ip_bin(self):
        """读取旧 IPv4 packed 二进制值。"""
        return self.args.old_ip_bin

    @property
    def new_ip_bin(self):
        """读取新 IPv4 packed 二进制值。"""
        return self.args.new_ip_bin

    def sport(self):
        """读取当前传输层源端口。"""
        return int(self.transport_layer.sport)

    def dport(self):
        """读取当前传输层目的端口。"""
        return int(self.transport_layer.dport)

    def tcp_state(self):
        """读取或创建当前连接共享状态。"""
        # UDP 或包级处理没有 TCP 连接上下文，返回临时空字典即可。
        if self.flow_state is None or self.conn_key is None:
            return {}
        # setdefault 让同一 TCP 连接的两个方向共享 WebSocket 等跨包状态。
        return self.flow_state.setdefault(self.conn_key, {})


def is_port(ctx, port):
    """
    判断当前上下文的源端口或目的端口是否命中指定端口。
    :param ctx: 协议改写上下文
    :param port: 需要匹配的 TCP/UDP 端口号
    """
    return ctx.sport() == port or ctx.dport() == port


@dataclass
class SegmentMeta:
    """
    记录一个 TCP payload 片段在原始单向字节流中的位置。
    :param index: 当前包在 packets 列表中的 0 基索引，用于回写原始包。
    :param seq: 当前包原始 TCP 绝对序列号。
    :param old_start: 当前 TCP payload 在 old_stream 中的起始偏移。
    :param old_end: 当前 TCP payload 在 old_stream 中的结束偏移。
    :param old_payload: 当前包原始 TCP payload 字节。
    :param primary: True 表示该包至少贡献了一个主重组字节。
    :param contributed: 当前包写入主重组流的字节数。
    """
    index: int
    seq: int
    old_start: int
    old_end: int
    old_payload: bytes
    primary: bool
    contributed: int


@dataclass
class TcpFlowState:
    """
    保存单方向 TCP 流从重组、改写到重分段所需的全部状态。
    :param key: 单方向 TCP 流标识，包含连接 ID 和四元组方向。
    :param packet_indices: 当前 TCP 流包含的原始包索引列表。
    :param base_seq: 当前方向的重组基准序列号。
    :param old_stream: 按 SEQ 重组出的原始单方向 TCP payload 字节流。
    :param new_stream: 协议 handler 改写后的目标 TCP payload 字节流。
    :param edits: old_stream 到 new_stream 的编辑区间列表。
    :param segments: 包索引到 SegmentMeta 的映射。
    :param packet_starts: 主片在 old_stream 中的起始偏移，用于诊断包边界。
    :param label: handler 返回的协议处理标签。
    :param conflicts: 重叠 TCP 片段中字节不一致的数量。
    :param holes: 重组区间内未被任何 payload 覆盖的字节数。
    :param packet_new_seq: 重分段阶段为特定包分配的精确新 SEQ，避免二次映射。
    """
    key: object
    packet_indices: list
    base_seq: int
    old_stream: bytes
    new_stream: bytes = b""
    edits: list = field(default_factory=list)
    segments: dict = field(default_factory=dict)
    packet_starts: list = field(default_factory=list)
    label: str = ""
    conflicts: int = 0
    holes: int = 0
    packet_new_seq: dict = field(default_factory=dict, init=False)
    # 标记是否需要保留原始 TCP segment 边界（由 handler.requires_stream_merge 取反得到）
    preserve_boundaries: bool = False
    # per-segment 模式下每个包改写后的新 payload（key=包索引）
    segment_payloads: dict = field(default_factory=dict, init=False)

    @property
    def old_len(self):
        """返回原始 TCP 流字节长度。"""
        return len(self.old_stream)


@dataclass
class TcpRewritePlan:
    """
    保存 TCP 重分段后的输出计划，不直接负责修改包列表。
    :param insert_after: 原始包索引到新增包列表的映射。
    :param deleted_indices: 被删除的原始包索引集合。
    :param changed_indices: payload 或 seq 已被修改的原始包索引集合。
    :param ack_overrides: 原始 ACK 包索引到强制 ack 值的映射。
    :param modified_flows: 发生改写的 TCP 流状态表。
    """
    insert_after: object = field(default_factory=lambda: defaultdict(list))
    deleted_indices: set = field(default_factory=set)
    changed_indices: set = field(default_factory=set)
    ack_overrides: dict = field(default_factory=dict)
    modified_flows: dict = field(default_factory=dict)
