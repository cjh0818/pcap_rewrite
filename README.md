# pcap_rewrite — PCAP/PCAPNG 批量 IP 改写工具

对 `.pcap` / `.pcapng` 文件中的 IPv4 地址进行**协议感知**的批量替换，覆盖
L2（ARP）、L3（IP header）、L4（ICMP/TCP/UDP）以及常见明文应用层协议（HTTP、TLS SNI、
WebSocket、MySQL、PostgreSQL、Redis、SOCKS5、FTP、SMTP、Telnet），同时对 TCP 流进行完整的
**SEQ/ACK/SACK 修正**。

---

## 目录结构

```
pcap_rewrite/
├── __init__.py                   # 包标识
├── main.py                       # 程序入口（参数解析 + 批处理调度）
├── config.py                     # 全局常量：正则、端口号、TCP 标志位等
├── stats.py                      # PacketStats 统计类（单文件 / 批量累加）
├── requirements.txt              # 依赖：scapy + loguru
│
├── core/                         # 核心引擎（协议无关）
│   ├── __init__.py
│   ├── context.py                # RewriteContext / RewriteResult / TcpFlowState / TcpRewritePlan
│   ├── dispatcher.py             # ProtocolHandler 抽象基类 + HandlerDispatcher 分发器
│   ├── utils.py                  # 工具函数（IP 校验、checksum 清理、偏移映射、edits 计算）
│   ├── flow.py                   # TCP 五元组标识、按 SYN 分代、字节流重组
│   ├── resegment.py              # TCP 重分段（流级合并 / 保留边界）、ACK 克隆、SEQ/ACK/SACK 修正
│   └── pipeline.py               # 流程调度：L2/L3/ICMP/UDP 包级 + TCP 流级（含双模式分流）
│
└── protocols/                    # 各协议的具体 IP 替换逻辑
    ├── __init__.py                # 组装 TCP_DISPATCHER / UDP_DISPATCHER
    ├── arp.py                    # ARP（psrc / pdst）
    ├── ipv4.py                   # IPv4 header（src / dst）
    ├── icmp.py                   # ICMP payload + IPerror 差错报文（traceroute 支持）
    ├── dhcp.py                   # DHCP/BOOTP（ciaddr/yiaddr/siaddr/giaddr + options）
    ├── dns.py                    # DNS（UDP + TCP length-prefixed，仅 A 记录 rdata）
    ├── tcp_raw.py                # RawTCPHandler（TCP 兜底字节替换，requires_stream_merge）
    ├── udp_raw.py                # RawUDPHandler（UDP 兜底字节替换）
    ├── http1.py                  # HTTP/1.x（CL / chunked / gzip / deflate + WS upgrade，requires_stream_merge）
    ├── http2.py                  # HTTP/2 拒绝处理器（二进制帧检测 + 拒绝）
    ├── websocket.py              # WebSocket frame mask + text 替换
    ├── tls_sni.py                # TLS ClientHello SNI 扩展
    ├── mongodb.py                # MongoDB Wire Protocol（BSON 递归替换，requires_stream_merge）
    ├── mysql.py                  # MySQL COM_QUERY
    ├── postgresql.py             # PostgreSQL Query message
    ├── redis_resp.py             # Redis RESP（递归）
    ├── socks5.py                 # SOCKS5（IPv4 / domain 地址）
    ├── ftp.py                    # FTP 控制连接（dotted + comma-separated IPv4）
    ├── smtp.py                   # SMTP 明文（命令/响应/DATA 文本替换）
    ├── telnet.py                 # Telnet 文本替换（IAC 协商字节检测）
    ├── rdp.py                    # RDP/TPKT 识别拒绝
    ├── known_text.py             # SSH/FTP-banner/SMTP-banner/POP3/IMAP 识别拒绝
    ├── dtls.py                   # DTLS 识别拒绝
    └── quic.py                   # QUIC 识别拒绝
```

---

## 运行方式

```bash
# 基本用法
python3 main.py <input_dir> <old_ip> <new_ip>

# 完整示例
python3 main.py /data/pcaps 10.0.0.1 192.168.1.100 \
    -o /data/output
```

### 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `input_dir` | 输入目录（递归处理 `.pcap`/`.pcapng`） | 必填 |
| `old_ip` | 待替换的旧 IPv4 | 必填 |
| `new_ip` | 替换后的新 IPv4 | 必填 |
| `-o`, `--output-dir` | 输出目录 | `input_dir/iprewrite_output` |
| `--log-file` | 日志文件路径 | 仅控制台 |
| `--fail-fast` | 单文件失败立即停止 | 继续处理 |

> **注意**：`--tcp-max`、`--udp-max`、`--max-frame-len`、`--no-raw`、`--no-binary-raw`、`--suffix` 等参数已移除，MTU 和容量限制使用 `config.py` 中的默认常量。

---

## 整体处理流程

```
输入 PCAP 文件
    │
    ▼
┌─────────────────────────────────────────┐
│ 阶段一：包级改写（非 TCP）               │
│   ARP → IPv4 Header → ICMP → UDP       │
│   每个包只命中一条路径                    │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 阶段二：TCP 流级改写                     │
│  1. 五元组分流 + SYN 分代                │
│  2. 按 SEQ 重组单向字节流                │
│  3. 协议识别 → 结构化替换                 │
│  4. 探测 handler.requires_stream_merge  │
│  5. 双模式分流：                         │
│     ├─ preserve=True  → resegment_preserve（零增删包）  │
│     └─ preserve=False → resegment_tcp_flow（流级合并）   │
│  6. 统一修正 SEQ / ACK / SACK            │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 阶段三：生成输出包序列                    │
│  删除旧包 + 插入克隆包 + 写出 PCAP        │
└─────────────────────────────────────────┘
```

---

## 协议 Handler 分类与分发

### TCP_DISPATCHER 优先级（从上到下先命中即停）

```
WebSocketHandler       ← HTTP Upgrade 后的 WS 帧
TLSClientHelloSNIHandler ← TLS SNI extension
HTTP2RejectHandler     ← PRI * HTTP/2.0 拒绝
HTTP1Handler           ← 结构化 HTTP/1.x（流级合并）
DNSHandler             ← TCP DNS（2 字节长度前缀）
MongoDBHandler         ← BSON 递归替换（流级合并）
MySQLHandler           ← COM_QUERY → SQL
PostgreSQLHandler      ← Query(Q) → SQL
RedisRESPHandler       ← RESP 递归替换
SOCKS5Handler          ← ATYP 替换
FTPHandler             ← FTP control CRLF
SMTPHandler            ← SMTP CRLF
TelnetHandler          ← Telnet text
RDPRejectHandler       ← RDP 拒绝
KnownUnsupportedTextHandler ← SSH/POP3/IMAP banner 拒绝
RawTCPHandler          ← ASCII 兜底替换（流级合并）
```

### UDP_DISPATCHER 优先级

```
DHCPHandler            ← DHCP/BOOTP 结构化替换
DNSHandler             ← DNS（UDP）A 记录 rdata
DTLSRejectHandler      ← DTLS 拒绝
QUICRejectHandler      ← QUIC 拒绝
RawUDPHandler          ← ASCII + packed 二进制兜底
```

### 流级合并 vs 保留边界

| 属性 | `requires_stream_merge=True` | `requires_stream_merge=False`（默认） |
|------|------|------|
| 重分段策略 | `resegment_tcp_flow()` — 按 MTU 重切包 | `resegment_preserve()` — 用 `map_offset` 按原始边界写回 |
| 增删包 | 可能删包、克隆新包、克隆 ACK | 零增删包 |
| flags 分布 | 仅末片继承 PSH/FIN | 完全保留原始 flags |
| 适用协议 | HTTP1 / MongoDB / RawTCP | FTP / SMTP / Telnet / MySQL / Pg / Redis / DNS / SOCKS5 / WS |
| 降级条件 | 无 | payload 超过 MTU → 自动降级为流级合并 |

---

## 各协议 IP 替换实现逻辑

### ARP（`protocols/arp.py`）

直接修改 Scapy ARP 层的 `psrc` 和 `pdst` 字段（字符串赋值），无需修改长度或校验和。

### IPv4 Header（`protocols/ipv4.py`）

修改 Scapy IP 层的 `src` / `dst` 字段后，调用 `clear_autofields()` 删除 `len`、`chksum` 等派生字段，让 Scapy 在写出时自动重算。

### ICMP（`protocols/icmp.py`）

- **差错报文（IPerror）**：修改被引用的原始 IP 头中的 `src`/`dst`，重算嵌入 IP checksum 和 ICMP checksum
- **其他 ICMP（如 Echo Request/Reply）**：对 payload 做 ASCII 文本 + packed 二进制的兜底替换
- **Traceroute 支持**：正确处理 ICMP TTL Exceeded 中携带的原始 IP 头

### DHCP / BOOTP（`protocols/dhcp.py`）

结构化替换 BOOTP 固定头和 DHCP options：

- **固定字段**：`ciaddr`、`yiaddr`、`siaddr`、`giaddr` 四个 IPv4 地址字段
- **DHCP Options**：递归遍历 option 值，替换 router、name_server 等多地址 option 中的 IPv4 字符串
- 替换后校验新旧 payload，确保旧 IP 已完全消除

### DNS（`protocols/dns.py`）

UDP 和 TCP DNS 统一处理：

- **UDP**：直接 Scapy `DNS()` 解析，替换 A 记录（type=1）的 `rdata` 字段（4 字节 packed IPv4），删除 `rdlen` 派生字段
- **TCP**：逐 2 字节长度前缀的 DNS message 解析后再同上处理，更新每个 message 的长度前缀
- DNS name、TXT、EDNS 等字段含旧 IP 时拒绝

### HTTP/1.x（`protocols/http1.py`，`requires_stream_merge=True`）

完整的 HTTP/1.x 消息解析器，逐消息处理：

1. **头部替换**：start-line 和所有 header value 中的 IP 文本直接 `.replace()`
2. **Body 定界方式**：
   - **Content-Length**：读固定长度 body → 替换 → 更新 Content-Length 头
   - **Chunked**：解析 chunk-size 行（十六进制）→ 重组 body → 替换 → 重新编码 chunk
   - **Close-delimited**（响应无长度头）：剩余全部视为 body
3. **Content-Encoding 处理**：
   - `identity`：直接替换
   - `gzip`：解压 → 替换 → 稳定重压缩（mtime=0）
   - `deflate`：支持标准 zlib 和 raw deflate 两种模式
   - `br`/`zstd` 等不支持：含 IP 时拒绝改写
4. **WebSocket Upgrade 检测**：识别 `Upgrade: websocket` + `101` 响应，在连接状态表中标记 `websocket_established`

### TLS SNI（`protocols/tls_sni.py`）

逐层解析 TLS 结构并仅在 SNI 扩展中替换：

```
TLS Record → Handshake → ClientHello → Extensions → SNI → ServerName
```

- **安全约束**：只有 `record_type=0x16`（Handshake）+ `msg_type=0x01`（ClientHello）+ `ext_type=0x0000`（SNI）才执行替换
- 其他 TLS 结构中出现 IP 时**拒绝改写**（防止破坏加密数据）
- 替换后更新所有层级的长度字段

### WebSocket（`protocols/websocket.py`）

解析 WebSocket frame 结构，仅对 text(opcode=0x1) 且 fin=1（未分片）的帧替换 IP：

1. **Frame header**：fin / rsv / opcode / mask / payload length（变长编码）
2. **Unmask**：客户端→服务端帧用 4 字节 mask key 做 XOR 解密
3. **替换** → 重新 mask → 更新 payload length 字段
4. **permessage-deflate** 压缩扩展启用时拒绝替换

### MongoDB（`protocols/mongodb.py`，`requires_stream_merge=True`）

递归解析 BSON document 并替换 string-like 字段中的 IP：

- **BSON 类型支持**：string(0x02)、JavaScript(0x0D)、symbol(0x0E)、cstring、DBPointer、regex pattern
- **Binary 字段**：subtype=0 且长度=4 时做 packed IPv4 等长替换
- **压缩消息**：含旧 IP 时拒绝（`mongodb.compressed_with_ip_not_supported`）
- 更新 BSON document length 和 MongoDB message length
- 最大递归深度 50 层，防止恶意文档栈溢出

### MySQL（`protocols/mysql.py`）

逐 packet 解析 MySQL 协议：

- 每个 packet = 3 字节小端长度 + 1 字节 seq_id + payload
- 仅对 `COM_QUERY`（`0x03`）命令的 SQL 文本替换 IP
- 替换后重新构造 packet header（更新 payload 长度）
- 非 COM_QUERY 含旧 IP → 跳过不拒绝（不抛错回滚整条流）

### PostgreSQL（`protocols/postgresql.py`）

逐 message 解析 PostgreSQL 前端协议：

- 消息格式：1 字节 type + 4 字节大端长度（含自身）+ body
- 仅对 `Query`（`'Q'`）消息的 null-terminated SQL 文本替换 IP
- 替换后更新 message length 字段

### Redis RESP（`protocols/redis_resp.py`）

递归解析 RESP 元素：

- **SimpleString / Error**（`+` / `-`）：文本直接替换
- **BulkString**（`$`）：替换 → 更新长度前缀
- **Array**（`*`）：递归处理每个子元素

### SOCKS5（`protocols/socks5.py`）

- **Greeting**（无地址字段）：直接跳过
- **Request**：按 ATYP 分别处理 — IPv4 等长替换、Domain 替换文本+更新长度、IPv6 拒绝

### FTP（`protocols/ftp.py`）

FTP 控制连接文本协议，处理两种 IPv4 格式：

- **dotted IPv4**：`192.168.1.1` 直接文本替换
- **comma-separated**：`192,168,1,1`（PORT/PASV/EPRT 命令中）→ `203,0,113,200`
- 防御性检测：SMTP 端口上不做 FTP 识别

### SMTP（`protocols/smtp.py`）

SMTP 明文文本协议：

- 命令/响应/DATA 正文全部做 ASCII IP 文本替换
- 无长度字段需要更新

### Telnet（`protocols/telnet.py`）

Telnet 交互式文本协议：

- 通过 IAC（`0xFF`）协商字节识别
- 全局 ASCII 文本替换

### RDP（`protocols/rdp.py`）

基于 TPKT/X.224，通常升级到 TLS 加密：

- 含旧 IP → 拒绝改写
- 不含 → 安全跳过

### 已知明文协议（`protocols/known_text.py`）

SSH / FTP-banner / SMTP-banner / POP3 / IMAP 的 banner 通过正则识别：

- 含旧 IP → 拒绝改写（防止 raw fallback 破坏二进制协议）
- 不含 → 安全跳过

### HTTP/2（`protocols/http2.py`）

二进制帧协议，HEADERS 使用 HPACK 压缩：

- 验证 HTTP/2 帧结构（connection preface + SETTINGS frame）
- 含旧 IP → 拒绝改写

### DTLS / QUIC（`protocols/dtls.py` / `quic.py`）

UDP 加密协议，无法安全替换：

- 含旧 IP → 拒绝改写
- 不含 → 安全跳过

### Raw 兜底（`protocols/tcp_raw.py` / `udp_raw.py`）

当所有结构化 handler 都无法识别时，执行字节级替换：

- ASCII 文本（`b"10.0.0.1"`）→ 文本替换
- packed 二进制（4 字节大端 IP）→ 等长替换

---

## TCP 流处理关键逻辑

### 1. 五元组分流 + SYN 分代（`core/flow.py`）

```
对于每个 TCP 包：
  - 提取 (src_ip, src_port, dst_ip, dst_port) 作为"端点对"
  - 排序端点对，消除方向差异，形成"连接 ID"
  - 检测 SYN（无 ACK）事件：同一连接 ID 每次 SYN 递增"分代"编号
  - 最终 FlowKey = (连接 ID, 分代, src_ip, src_port, dst_ip, dst_port)
```

**为什么需要分代**：同一对 IP:Port 可能被 TIME_WAIT 后的新连接复用，分代保证不同连接的数据不会被错误重组到同一个流。

### 2. 按 SEQ 重组字节流（`core/flow.py` — `build_stream_state()`）

```
以该方向最小 SEQ 为基准序列号 (base_seq)
所有包的绝对 SEQ 转为相对偏移: offset = (seq - base_seq) % 2^32
按 (offset, -len) 排序 → 长片段优先写入
```

**冲突处理**：
- 首次写入某位置 → 标记为主片（primary）
- 重传覆盖但字节相同 → 忽略
- 重传覆盖且字节不同 → 计数 conflict +1，不覆盖（保留首次写入）
- 未被覆盖的位置 → 计数 hole +1（可能缺包）

### 3. 计算 edits（`core/utils.py` — `compute_edits()`）

使用 `difflib.SequenceMatcher` 计算 `old_stream → new_stream` 的编辑区间。用于后续将旧的 SEQ/ACK 映射到新流坐标。

### 4. 双模式重分段（`core/resegment.py`）

#### 流级合并 — `resegment_tcp_flow()`

**阶段 A — 填充已有包**：
- 按主片顺序遍历，每个旧包从 `new_stream[cursor]` 切出 `capacity` 字节
- 更新 `TCP.seq = base_seq + cursor`
- 多余旧包（new_stream 已分配完毕）加入删除队列
- 找到紧随的反向 ACK 并覆盖其确认号

**阶段 B — 克隆新增包**：
- 以最后一个旧主片为模板 `copy.deepcopy()`
- 每个新增片之间插入克隆的 ACK 包
- IP.id 递增避免 ID 冲突
- 新包时间戳均匀插入在前后真实包之间（Decimal 精度）

#### 保留边界 — `resegment_preserve()`

- 用 `map_offset(meta.old_start/old_end, edits)` 将每个主片的旧偏移映射为新偏移
- 从 `new_stream` 取对应片段直接写回原包
- **零增删包**、不克隆 ACK、不修改 flags
- 某 segment 超过 MTU → 自动降级为流级合并

### 5. SEQ/ACK/SACK 修正（`core/resegment.py` — `adjust_seq_ack()`）

**SEQ 映射**：
```
offset = (old_seq - base_seq) % 2^32
new_seq = base_seq + map_offset(offset, edits)
```

**ACK 映射**：使用反方向流的 base_seq + edits 做同样映射（ACK 确认的是反方向已接收的数据）。

**SACK 修正**：SACK option 各区间指向反方向流，逐区间用 `map_offset` 映射。

### 6. 重传片映射（`core/resegment.py` — `remap_retransmissions()`）

非主片的重传包：用 `map_offset` 映射坐标后取 `new_stream` 对应片段。超出单包容量时分片。

---

## 关键设计决策

| 决策 | 原因 |
|------|------|
| 流级改写而非包级 | 需要完整 HTTP 消息边界才能安全处理 Content-Length / chunked |
| 先重组再替换 | 避免 IP 跨 TCP 分片时只替换了一部分 |
| handler detect 失败继续 fallback | 误判（如半包）不应中断整条流 |
| raw handler 放在 dispatcher 最末 | 只在无结构化协议匹配时兜底 |
| 删除 IP/checksum 派生字段而非手算 | Scapy 自动重算比手动计算更可靠 |
| `requires_stream_merge` 标记 | 交互式协议（FTP/SMTP/Telnet）保留原始包边界，数据流协议（HTTP/MongoDB）按 MTU 重切 |
| 超过 MTU 自动降级 | per-segment 模式下 payload 增长不会产生畸形大包 |
| Decimal 精度时间戳分配 | float 精度不足导致多克隆包时间戳相同 |

---

## 注意事项

1. **加密协议限制**：TLS 1.2/1.3 的 ApplicationData 已加密，无法替换其中的 IP。工具仅处理 TLS 明文的 ClientHello SNI。

2. **HTTP/2 / QUIC / DTLS / RDP**：均为二进制/加密协议，含旧 IP 时会被拒绝（`reject`），请检查日志确认。

3. **TCP 缺包**：如果抓包不完整，重组流中会有 holes（未覆盖字节），日志会 warning 提示。

4. **输出目录嵌套**：工具自动跳过位于输出目录内的文件，避免重复处理已生成的 PCAP。

5. **大文件**：所有数据包读入内存处理，单文件过大时建议先分割 PCAP。

6. **保留边界模式**：FTP/SMTP/Telnet/MySQL/Pg/Redis/DNS/SOCKS5/WebSocket 默认不走流级合并，输出包数和交互节奏与输入完全一致。
