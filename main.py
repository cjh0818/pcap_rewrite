#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap_rewrite - PCAP/PCAPNG 批量 IP 改写工具
用法:
    python main.py <input_dir> <old_ip> <new_ip> [选项]
示例:
    python main.py /data/pcaps 10.0.0.1 192.168.1.100 -o /output
"""

import argparse
import traceback
import time
from pathlib import Path
from loguru import logger
try:
    from scapy.error import Scapy_Exception
    from scapy.utils import PcapReader, PcapWriter
except ImportError as exc:
    raise SystemExit("缺少依赖 scapy，请先执行: pip install scapy") from exc
from stats import PacketStats, merge_stats
from core.context import RewriteError
from core.pipeline import rewrite_l2_l3_udp_pass, rewrite_tcp_pass, build_output_packets
from core.utils import validate_ipv4, attach_ip_material


def output_path_for(input_file, input_dir, output_dir):
    """根据输入文件路径和输出目录生成输出 PCAP 路径。"""
    relative = input_file.relative_to(input_dir)
    return output_dir / relative.parent / f"{input_file.stem}_iprewrite-{int(time.time())}.pcap"


def iter_pcap_files(input_dir, output_dir):
    """
    递归遍历输入目录中的 .pcap/.pcapng 文件。
    自动跳过位于输出目录内的文件，避免二次处理。
    """
    iterator = input_dir.rglob("*")
    output_dir_resolved = output_dir.resolve()
    for path in sorted(iterator):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".pcap", ".pcapng"}:
            continue
        try:
            path.resolve().relative_to(output_dir_resolved)
            continue
        except ValueError:
            yield path


def process_pcap_file(input_file, output_file, args):
    """
    处理单个 PCAP 文件：
      1. 读取全部数据包
      2. L2/L3/ICMP/UDP 包级改写
      3. TCP 流级改写
      4. 写出结果
    :return: PacketStats
    """
    logger.info(f"读取: {input_file}")
    with PcapReader(str(input_file)) as reader:
        packets = list(reader)
    stats = PacketStats()
    # 非 TCP 协议的包级改写
    rewrite_l2_l3_udp_pass(packets, args, stats)
    # TCP 流重组 → 协议改写 → 重分段 → SEQ/ACK 修正
    plan = rewrite_tcp_pass(packets, args, stats)
    # 生成最终输出
    output_packets = build_output_packets(packets, plan, stats)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    writer = PcapWriter(str(output_file), append=False, sync=True)
    try:
        for packet in output_packets:
            writer.write(packet)
    finally:
        writer.close()

    logger.info(
        f"写出: {output_file} | 输入帧={stats.total_in}, 输出帧={stats.total_out}, "
        f"ARP={stats.arp_changed}, IPv4={stats.ipv4_changed}, ICMP={stats.icmp_changed}, "
        f"UDP={stats.udp_changed}, TCP流={stats.tcp_stream_changed}, "
        f"TCP改包={stats.tcp_packets_changed}, TCP新增={stats.tcp_inserted}, "
        f"TCP删除={stats.tcp_deleted}, failures={stats.failures}"
    )
    return stats


def process_directory(args):
    """
    批量处理输入目录下的所有 PCAP 文件。
    """
    input_dir = Path(args.input_dir).resolve()
    if not input_dir.is_dir():
        raise NotADirectoryError(f"输入必须是目录: {input_dir}")

    output_dir = (
        Path(args.output_dir).resolve()
        if args.output_dir
        else input_dir / "iprewrite_output"
    )
    files = list(iter_pcap_files(input_dir, output_dir))
    logger.info(
        f"批量处理目录: {input_dir}; 文件数={len(files)}; 输出目录={output_dir}; "
        f"替换={args.old_ip}->{args.new_ip}"
    )
    if not files:
        logger.warning("未找到 .pcap/.pcapng 文件")
        return

    total = PacketStats()
    processed = 0
    for input_file in files:
        output_file = output_path_for(input_file, input_dir, output_dir)
        try:
            # 对每个文件执行完整的读取、替换ip、重新写出pcap，并统计结果
            stats = process_pcap_file(input_file, output_file, args)
            merge_stats(total, stats)
            processed += 1
        except (OSError, Scapy_Exception, RewriteError, ValueError) as exc:
            total.failures += 1
            logger.error(f"文件处理失败: {input_file}: {exc}")
            logger.debug(traceback.format_exc())
            if args.fail_fast:
                raise
        except Exception as exc:
            total.failures += 1
            logger.exception(f"文件处理出现未归类异常: {input_file}: {exc}")
            if args.fail_fast:
                raise

    logger.info(
        f"批量完成: 文件={processed}/{len(files)}, 输入帧={total.total_in}, "
        f"输出帧={total.total_out}, "
        f"ARP={total.arp_changed}, IPv4={total.ipv4_changed}, ICMP={total.icmp_changed}, "
        f"UDP={total.udp_changed}, TCP流={total.tcp_stream_changed}, "
        f"TCP新增={total.tcp_inserted}, TCP删除={total.tcp_deleted}, failures={total.failures}"
    )


def parse_args(argv=None):
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(
        description="批量替换 PCAP/PCAPNG 中 L2/L3/L4/应用层 的 IPv4 字符串/二进制值，并修正 TCP seq/ack/SACK。"
    )
    parser.add_argument("input_dir", help="输入目录路径，递归处理其中所有 .pcap/.pcapng 文件")
    parser.add_argument("old_ip", help="待替换的旧 IPv4，例如 1.1.1.1")
    parser.add_argument("new_ip", help="替换后的新 IPv4，例如 192.168.100.200")
    parser.add_argument("-o", "--output-dir", help="输出目录；默认在输入目录下创建 iprewrite_output")
    parser.add_argument("--log-file", help="可选日志文件")
    parser.add_argument("--fail-fast", action="store_true", help="单文件失败时立即停止批处理")
    args = parser.parse_args(argv)

    validate_ipv4(args.old_ip, "old_ip")
    validate_ipv4(args.new_ip, "new_ip")
    attach_ip_material(args)
    return args


def main(argv=None):
    """脚本入口。"""
    args = parse_args(argv)
    if args.log_file:
        logger.add(args.log_file, level="INFO", encoding="utf-8")
    process_directory(args)


if __name__ == "__main__":
    main()
