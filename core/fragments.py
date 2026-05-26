# -*- coding: utf-8 -*-
"""
IPv4 分片重组与回写。

在 L4 handler 之前，把完整的 UDP/TCP IPv4 分片组重组为等价的非分片包；
在写出前，再按可用的原始分片槽位切回 IPv4 分片。
"""

from dataclasses import dataclass, field
import uuid

from loguru import logger
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from core.utils import clear_autofields, sync_packet_wirelen


_IP_FLAG_MF = 0x1
_IP_FLAG_DF = 0x2
_PROTO_TCP = 6
_PROTO_UDP = 17
_DEFAULT_MTU = 1500


class FragmentSlot:
    """原始续片槽位占位符，用于在输出阶段把新分片放回原帧位置。"""

    __slots__ = ("marker", "ordinal")

    def __init__(self, marker, ordinal):
        self.marker = marker
        self.ordinal = ordinal

    def __contains__(self, _layer):
        return False


@dataclass
class FragmentInfo:
    index: int
    offset: int
    payload: bytes
    mf: bool
    packet: object


@dataclass
class FragmentRecord:
    proto: int
    original_sizes: list
    slot_packets: list
    emitted: list = field(default_factory=list)


class FragmentGroup:
    """一个正在收集的 IPv4 分片数据报。"""

    def __init__(self, key):
        self.key = key
        self.fragments = []

    def add(self, fragment):
        self.fragments.append(fragment)

    @property
    def has_first(self):
        return any(fragment.offset == 0 for fragment in self.fragments)

    @property
    def last_end(self):
        ends = [
            fragment.offset + len(fragment.payload)
            for fragment in self.fragments
            if not fragment.mf
        ]
        return min(ends) if ends else None

    def completion_error(self):
        """返回 None 表示完整且可安全重组，否则返回原因。"""
        if not self.has_first:
            return "missing_first"
        last_ends = [
            fragment.offset + len(fragment.payload)
            for fragment in self.fragments
            if not fragment.mf
        ]
        if not last_ends:
            return "missing_last"
        if len(set(last_ends)) != 1:
            return "multiple_last_fragments"
        expected_end = last_ends[0]

        unique = {}
        for fragment in self.fragments:
            if fragment.mf and len(fragment.payload) % 8 != 0:
                return "non_last_fragment_not_8_byte_aligned"
            previous = unique.get(fragment.offset)
            if previous is None:
                unique[fragment.offset] = fragment
                continue
            if previous.payload != fragment.payload:
                return "overlap_or_duplicate_offset"

        cursor = 0
        for offset, fragment in sorted(unique.items()):
            if offset < cursor:
                return "overlap"
            if offset > cursor:
                return "hole"
            cursor = offset + len(fragment.payload)
            if cursor >= expected_end:
                break
        if cursor < expected_end:
            return "hole"
        return None

    def unique_fragments(self):
        unique = {}
        for fragment in self.fragments:
            unique.setdefault(fragment.offset, fragment)
        return [unique[offset] for offset in sorted(unique)]


class FragmentManager:
    """IPv4 分片重组管理器。"""

    def __init__(self):
        self._records = {}
        self._completed_fragments = {}

    def reassemble(self, packets):
        """
        将完整的 UDP/TCP IPv4 分片组替换为虚拟非分片包。

        首片位置放虚拟包，其他原始分片位置放 FragmentSlot。缺片、重叠、
        非 UDP/TCP、无法解析 L4 头的分片组保持原样。
        """
        active = {}
        blocked_keys = set()
        reassembled = 0
        skipped = 0

        for index, packet in enumerate(packets):
            info = self._fragment_info(packet, index)
            if info is None:
                continue

            key = self._fragment_group_key(packet)
            if self._is_completed_duplicate(key, info):
                # 重组完成后仍可能在抓包里看到同一 IP datagram 的重传分片。
                # 这些分片已由虚拟包统一改写并回切，原样输出会造成漏改。
                packets[index] = None
                continue
            if key in blocked_keys:
                continue
            group = active.get(key)
            if group is not None and info.offset == 0 and group.has_first:
                logger.warning(f"分片组 {key} 在完成前出现新的首片，旧组保持原样")
                del active[key]
                blocked_keys.add(key)
                skipped += 1
                continue

            if group is None:
                group = FragmentGroup(key)
                active[key] = group
            group.add(info)

            error = group.completion_error()
            if error is not None:
                continue

            virtual = self._assemble(group)
            if virtual is None:
                skipped += 1
                del active[key]
                continue

            marker = uuid.uuid4()
            virtual._fragment_marker = marker
            virtual._is_fragment_reassembly = True

            original_slots = sorted(group.fragments, key=lambda fragment: fragment.index)
            original_by_offset = group.unique_fragments()
            self._completed_fragments[key] = {
                fragment.offset: (fragment.payload, fragment.mf)
                for fragment in original_by_offset
            }
            self._records[marker] = FragmentRecord(
                proto=key[2],
                original_sizes=[len(fragment.payload) for fragment in original_by_offset],
                slot_packets=[fragment.packet for fragment in original_slots],
            )

            first_index = original_slots[0].index
            packets[first_index] = virtual
            for ordinal, fragment in enumerate(original_slots[1:], start=1):
                packets[fragment.index] = FragmentSlot(marker, ordinal)

            del active[key]
            reassembled += 1

        for key, group in active.items():
            logger.warning(
                f"分片组 {key} 不完整，保持原样: {group.completion_error() or 'unknown'}"
            )
            skipped += 1

        if reassembled or skipped:
            logger.info(f"IPv4 分片重组: 成功 {reassembled} 组, 跳过 {skipped} 组")

    def refragment(self, output_packets):
        """把虚拟重组包切回 IPv4 分片，并放回 FragmentSlot 占位位置。"""
        if not self._records:
            return

        result = []
        pending_extra = {}
        deferred_after_slots = {}
        consumed_markers = set()
        extra_inserted = set()

        for item in output_packets:
            if isinstance(item, FragmentSlot):
                fragments = pending_extra.get(item.marker)
                if fragments is None:
                    continue
                if item.ordinal < len(fragments):
                    result.append(fragments[item.ordinal])
                record = self._records.get(item.marker)
                original_slot_count = len(record.slot_packets) if record is not None else 0
                if (
                    record is not None
                    and item.ordinal == original_slot_count - 1
                    and item.marker not in extra_inserted
                    and len(fragments) > original_slot_count
                ):
                    result.extend(fragments[original_slot_count:])
                    extra_inserted.add(item.marker)
                if (
                    record is not None
                    and item.ordinal == original_slot_count - 1
                    and item.marker in deferred_after_slots
                ):
                    result.extend(deferred_after_slots.pop(item.marker))
                continue

            marker = getattr(item, "_fragment_marker", None)
            record = self._records.get(marker)
            if marker is None or record is None:
                result.append(item)
                continue

            if marker in consumed_markers:
                deferred_after_slots.setdefault(marker, []).extend(
                    self._split(item, record, preserve_slot_templates=False)
                )
                continue

            fragments = self._split(item, record, preserve_slot_templates=True)
            record.emitted = fragments
            pending_extra[marker] = fragments
            consumed_markers.add(marker)
            if fragments:
                result.append(fragments[0])
            if len(record.slot_packets) == 1 and len(fragments) > 1:
                result.extend(fragments[1:])
                extra_inserted.add(marker)
            if len(record.slot_packets) == 1 and marker in deferred_after_slots:
                result.extend(deferred_after_slots.pop(marker))

        for fragments in deferred_after_slots.values():
            result.extend(fragments)

        output_packets[:] = result

    @staticmethod
    def is_fragment_slot(packet):
        return isinstance(packet, FragmentSlot)

    @staticmethod
    def is_reassembled_fragment(packet):
        return bool(getattr(packet, "_is_fragment_reassembly", False))

    def _is_completed_duplicate(self, key, info):
        completed = self._completed_fragments.get(key)
        if not completed:
            return False
        expected = completed.get(info.offset)
        if expected is None:
            return False
        payload, mf = expected
        return payload == info.payload and mf == info.mf

    @staticmethod
    def _clear_marker(packet):
        for name in ("_fragment_marker", "_is_fragment_reassembly"):
            try:
                delattr(packet, name)
            except (AttributeError, TypeError):
                pass

    @classmethod
    def _fragment_info(cls, packet, index):
        if packet is None or IP not in packet:
            return None
        ip = packet[IP]
        try:
            offset = int(ip.frag) * 8
            flags = int(ip.flags)
        except (TypeError, ValueError):
            return None
        if offset == 0 and not (flags & _IP_FLAG_MF):
            return None
        try:
            proto = int(ip.proto)
        except (TypeError, ValueError):
            return None
        if proto not in {_PROTO_TCP, _PROTO_UDP}:
            return None
        return FragmentInfo(
            index=index,
            offset=offset,
            payload=cls._ip_payload_bytes(packet),
            mf=bool(flags & _IP_FLAG_MF),
            packet=packet,
        )

    @staticmethod
    def _fragment_group_key(packet):
        ip = packet[IP]
        return (ip.src, ip.dst, int(ip.proto), int(ip.id))

    @staticmethod
    def _ip_payload_bytes(packet):
        ip = packet[IP]
        payload = bytes(ip.payload)
        try:
            if ip.len is None or ip.ihl is None:
                return payload
            payload_len = int(ip.len) - int(ip.ihl) * 4
        except (TypeError, ValueError):
            return payload
        if payload_len <= 0:
            return b""
        return payload[:payload_len]

    @classmethod
    def _assemble(cls, group):
        fragments = group.unique_fragments()
        datagram_len = group.last_end
        if datagram_len is None:
            return None

        assembled = bytearray(datagram_len)
        for fragment in fragments:
            end = min(fragment.offset + len(fragment.payload), datagram_len)
            assembled[fragment.offset:end] = fragment.payload[:end - fragment.offset]
        transport_datagram = bytes(assembled)

        first = next(fragment for fragment in fragments if fragment.offset == 0)
        first_ip = first.packet[IP]
        proto = int(first_ip.proto)
        if proto == _PROTO_UDP:
            transport = cls._build_udp(transport_datagram, group.key)
        elif proto == _PROTO_TCP:
            transport = cls._build_tcp(transport_datagram, group.key)
        else:
            return None
        if transport is None:
            return None

        ip_layer = cls._copy_ip_header(first_ip)
        ip_layer.frag = 0
        ip_layer.flags = cls._base_flags(first_ip)
        ip_layer.add_payload(transport)

        virtual = cls._replace_ip_layer(first.packet, ip_layer)
        clear_autofields(
            virtual,
            virtual[IP],
            virtual[UDP] if UDP in virtual else virtual[TCP] if TCP in virtual else None,
        )
        if UDP in virtual:
            virtual[UDP].len = len(transport_datagram)
        return virtual

    @staticmethod
    def _build_udp(datagram, key):
        if len(datagram) < 8:
            logger.warning(f"分片组 {key} UDP 头不足 8 字节，保持原样")
            return None
        udp_len = int.from_bytes(datagram[4:6], "big")
        if udp_len < 8 or udp_len != len(datagram):
            logger.warning(
                f"分片组 {key} UDP 长度异常 udp.len={udp_len}, ip_payload={len(datagram)}，保持原样"
            )
            return None
        udp = UDP(
            sport=int.from_bytes(datagram[0:2], "big"),
            dport=int.from_bytes(datagram[2:4], "big"),
            len=udp_len,
            chksum=int.from_bytes(datagram[6:8], "big"),
        )
        if len(datagram) > 8:
            udp.add_payload(Raw(datagram[8:]))
        return udp

    @staticmethod
    def _build_tcp(datagram, key):
        if len(datagram) < 20:
            logger.warning(f"分片组 {key} TCP 头不足 20 字节，保持原样")
            return None
        dataofs = datagram[12] >> 4
        header_len = dataofs * 4
        if dataofs < 5 or header_len > len(datagram):
            logger.warning(
                f"分片组 {key} TCP 头长度异常 dataofs={dataofs}, ip_payload={len(datagram)}，保持原样"
            )
            return None
        return TCP(datagram)

    @staticmethod
    def _copy_ip_header(ip):
        copied = IP(
            version=ip.version,
            ihl=ip.ihl,
            tos=ip.tos,
            id=ip.id,
            flags=ip.flags,
            frag=ip.frag,
            ttl=ip.ttl,
            proto=ip.proto,
            src=ip.src,
            dst=ip.dst,
            options=ip.options,
        )
        return copied

    @staticmethod
    def _base_flags(ip):
        try:
            return int(ip.flags) & ~_IP_FLAG_MF
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _replace_ip_layer(template_packet, ip_layer):
        packet = template_packet.copy()
        ip_copy = packet[IP]
        underlayer = ip_copy.underlayer
        if underlayer is None:
            ip_layer.time = getattr(packet, "time", None)
            return ip_layer
        underlayer.remove_payload()
        underlayer.add_payload(ip_layer)
        return packet

    @classmethod
    def _split(cls, packet, record, preserve_slot_templates):
        transport_datagram = cls._serialized_ip_payload(packet)
        if not transport_datagram:
            return []

        ip_layer = packet[IP]
        boundaries = cls._split_boundaries(
            total_len=len(transport_datagram),
            original_sizes=record.original_sizes,
            max_payload=cls._max_fragment_payload(ip_layer),
        )
        fragments = []
        base_flags = cls._base_flags(ip_layer) & ~_IP_FLAG_DF
        for ordinal, (start, end) in enumerate(boundaries):
            chunk = transport_datagram[start:end]
            is_last = end >= len(transport_datagram)
            frag_ip = cls._copy_ip_header(ip_layer)
            frag_ip.flags = base_flags | (0 if is_last else _IP_FLAG_MF)
            frag_ip.frag = start // 8
            frag_ip.remove_payload()
            frag_ip.add_payload(Raw(chunk))
            clear_autofields(frag_ip, frag_ip, None)

            if preserve_slot_templates:
                template = record.slot_packets[min(ordinal, len(record.slot_packets) - 1)]
            else:
                template = packet
            frag_packet = cls._replace_ip_layer(template, frag_ip)
            original_time = getattr(template, "time", None)
            if original_time is not None:
                frag_packet.time = original_time
            sync_packet_wirelen(frag_packet)
            fragments.append(frag_packet)
        return fragments

    @staticmethod
    def _serialized_ip_payload(packet):
        ip = packet[IP]
        clear_autofields(
            packet,
            ip,
            packet[UDP] if UDP in packet else packet[TCP] if TCP in packet else None,
        )
        raw_ip = bytes(ip)
        if not raw_ip:
            return b""
        ihl = (raw_ip[0] & 0x0F) * 4
        total_len = int.from_bytes(raw_ip[2:4], "big")
        return raw_ip[ihl:total_len]

    @staticmethod
    def _max_fragment_payload(ip_layer):
        try:
            header_len = int(ip_layer.ihl) * 4 if ip_layer.ihl else 20
        except (TypeError, ValueError):
            header_len = 20
        max_payload = ((_DEFAULT_MTU - header_len) // 8) * 8
        return max_payload if max_payload > 0 else 1480

    @classmethod
    def _split_boundaries(cls, total_len, original_sizes, max_payload):
        """
        生成回切边界。

        等长改写保留原始分片节奏；长度变化时按当前 MTU 重切，避免把
        中间链路造成的分片节奏当成源端协议特征长期保留。
        """
        if sum(original_sizes) == total_len and len(original_sizes) > 1:
            boundaries = []
            pos = 0
            for size in original_sizes:
                boundaries.append((pos, pos + size))
                pos += size
            return boundaries

        if total_len <= max_payload:
            return [(0, total_len)]

        boundaries = []
        fragment_payload = (max_payload // 8) * 8
        if fragment_payload <= 0:
            fragment_payload = 1480
        pos = 0
        while pos < total_len:
            remaining = total_len - pos
            if remaining <= max_payload:
                boundaries.append((pos, total_len))
                break
            end = pos + fragment_payload
            boundaries.append((pos, end))
            pos = end
        return boundaries
