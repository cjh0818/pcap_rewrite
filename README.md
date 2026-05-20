# pcap_rewrite — PCAP/PCAPNG 批量 IP 改写工具

对 `.pcap` / `.pcapng` 文件中的 IPv4 地址进行**协议感知**的批量替换，覆盖
L2（ARP）、L3（IP header）、L4（ICMP/TCP/UDP）以及常见明文应用层协议（HTTP、TLS SNI、
WebSocket、MySQL、PostgreSQL、Redis、SOCKS5），同时对 TCP 流进行完整的
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
│   ├── context.py                # RewriteContext / RewriteResult / 流状态数据类
│   ├── dispatcher.py             # ProtocolHandler 抽象基类 + HandlerDispatcher 分发器
│   ├── utils.py                  # 工具函数（校验、checksum 清理、偏移映射）
│   ├── flow.py                   # TCP 五元组标识、按 SYN 分代、字节流重组
│   ├── resegment.py              # TCP 重分段、ACK 克隆、SEQ/ACK/SACK 修正
│   └── pipeline.py               # 流程调度：L2/L3/ICMP/UDP 包级 + TCP 流级
│
└── protocols/                    # 各协议的具体 IP 替换逻辑
    ├── __init__.py                # 组装 TCP_DISPATCHER / UDP_DISPATCHER
    ├── arp.py                    # ARP（psrc / pdst）
    ├── ipv4.py                   # IPv4 header（src / dst）
    ├── icmp.py                   # ICMP payload + IPerror 差错报文
    ├── tcp_raw.py                # RawTCPHandler（TCP 兜底字节替换）
    ├── udp_raw.py                # RawUDPHandler（UDP 兜底字节替换）
    ├── http1.py                  # HTTP/1.x（CL / chunked / gzip / deflate + WS upgrade）
    ├── http2.py                  # HTTP/2 拒绝处理器
    ├── websocket.py              # WebSocket frame mask + text 替换
    ├── tls_sni.py                # TLS ClientHello SNI 扩展
    ├── mysql.py                  # MySQL COM_QUERY
    ├── postgresql.py             # PostgreSQL Query message
    ├── redis_resp.py             # Redis RESP（递归）
    ├── socks5.py                 # SOCKS5（IPv4 / domain 地址）
    ├── known_text.py             # SSH/FTP/SMTP/POP3/IMAP 识别拒绝
    ├── dtls.py                   # DTLS 识别拒绝
    └── quic.py                   # QUIC 识别拒绝
```

---

## 运行方式

```bash
# 基本用法
python3 -m main <input_dir> <old_ip> <new_ip>

# 完整示例
python3 -m main /data/pcaps 10.0.0.1 192.168.1.100 \
    -o /data/output \
    --tcp-max 1400 \
    --udp-max 1400 \
    --max-frame-len 1514 \
    --suffix _rewritten
```

### 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `input_dir` | 输入目录（递归处理 `.pcap`/`.pcapng`） | 必填 |
| `old_ip` | 待替换的旧 IPv4 | 必填 |
| `new_ip` | 替换后的新 IPv4 | 必填 |
| `-o`, `--output-dir` | 输出目录 | `input_dir/iprewrite_output` |
| `--suffix` | 输出文件后缀 | `_pipeline_iprewrite` |
| `--no-recursive` | 仅处理顶层目录 | 递归 |
| `--tcp-max` | TCP 单段最大 payload | 1460 |
| `--udp-max` | UDP 最大 payload | 1472 |
| `--max-frame-len` | 链路层最大帧长 | 1514 |
| `--no-raw` | 禁用 ASCII 文本兜底替换 | 启用 |
| `--no-binary-raw` | 禁用 packed 二进制兜底替换 | 启用 |
| `--log-file` | 日志文件路径 | 仅控制台 |
| `--fail-fast` | 单文件失败立即停止 | 继续处理 |

---

## 整体处理流程

```
输入 PCAP 文件
    │
    ▼
┌─────────────────────────────────────┐
│ 阶段一：包级改写（非 TCP）           │
│   ARP → IPv4 Header → ICMP → UDP   │
│   每个包只命中一条路径                │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 阶段二：TCP 流级改写                 │
│  1. 五元组分流 + SYN 分代            │
│  2. 按 SEQ 重组单向字节流            │
│  3. 协议识别 → 结构化替换             │
│  4. 计算 edits（新旧流差异）          │
│  5. 重分段（resegment）              │
│  6. 修正 SEQ / ACK / SACK           │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ 阶段三：生成输出包序列                │
│  删除旧包 + 插入克隆包 + 写出 PCAP    │
└─────────────────────────────────────┘
```

---

## 各协议 IP 替换实现逻辑

### ARP（`protocols/arp.py`）

直接修改 Scapy ARP 层的 `psrc` 和 `pdst` 字段（字符串赋值），无需修改长度或校验和。

### IPv4 Header（`protocols/ipv4.py`）

修改 Scapy IP 层的 `src` / `dst` 字段后，调用 `clear_autofields()` 删除 `len`、`chksum` 等派生字段，让 Scapy 在写出时自动重算。

### ICMP（`protocols/icmp.py`）

- **差错报文（IPerror）**：修改被引用的原始 IP 头中的 `src`/`dst`
- **其他 ICMP**：对 payload 做 ASCII 文本 + packed 二进制的兜底替换

### HTTP/1.x（`protocols/http1.py`）

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
- 替换后更新所有层级的长度字段（record length → handshake length → extension length → name length）

### WebSocket（`protocols/websocket.py`）

解析 WebSocket frame 结构：

1. **Frame header**：FIN / RSV / opcode / MASK / payload length（变长编码 7 / 7+16 / 7+64 位）
2. **Unmask**：客户端→服务端帧用 4 字节 mask key 做 XOR 解密
3. **替换约束**：仅对 `opcode=0x1`（text）且 `fin=1`（未分片）的帧执行替换
4. **permessage-deflate**：压缩扩展启用时拒绝替换
5. 替换后重新 mask（如需要）并更新 payload length 字段

### MySQL（`protocols/mysql.py`）

逐 packet 解析 MySQL 协议：

- 每个 packet = 3 字节小端长度 + 1 字节 seq_id + payload
- 仅对 `COM_QUERY`（`0x03`）命令的 SQL 文本替换 IP
- 其他命令（result set / prepared statement 等二进制协议）含 IP 时拒绝
- 替换后重新构造 packet header（更新 payload 长度）

### PostgreSQL（`protocols/postgresql.py`）

逐 message 解析 PostgreSQL 前端协议：

- 消息格式：1 字节 type + 4 字节大端长度（含自身）+ body
- 仅对 `Query`（`'Q'`）消息的 null-terminated SQL 文本替换 IP
- 替换后更新 message length 字段

### Redis RESP（`protocols/redis_resp.py`）

递归解析 RESP（REdis Serialization Protocol）元素：

- **SimpleString / Error**（`+` / `-`）：文本直接替换
- **Integer**（`:`）：不替换（纯数字不含 IP）
- **BulkString**（`$`）：读取长度行 + 数据块 → 替换 → 更新长度前缀
- **Array**（`*`）：读取元素个数 → 递归处理每个子元素
- 解析失败且含 IP 时抛出异常，让 raw fallback 兜底

### SOCKS5（`protocols/socks5.py`）

- **Greeting**（无地址字段）：直接跳过
- **Request**：按 ATYP（地址类型）分别处理：
  - `0x01`（IPv4）：等长替换 4 字节 packed 二进制 IP
  - `0x03`（Domain）：在域名中替换 IP 文本，更新域名长度字段
  - `0x04`（IPv6）：拒绝

### 已知明文协议（`protocols/known_text.py`）

SSH / FTP / SMTP / POP3 / IMAP 的 banner 通过正则识别，但**不实现结构化替换**：
- 含旧 IP → 拒绝改写（返回失败）
- 不含 → 安全跳过

### DTLS / QUIC（`protocols/dtls.py` / `quic.py`）

加密协议，无法安全替换：
- 含旧 IP → 拒绝改写
- 不含 → 安全跳过

### Raw 兜底（`protocols/tcp_raw.py` / `udp_raw.py`）

当所有结构化 handler 都无法识别时，执行字节级替换：先 ASCII 文本（`b"10.0.0.1"`），再 packed 二进制（4 字节大端 IP）。

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

### 3. 协议识别与改写（`core/dispatcher.py`）

Handler 按优先级从上到下执行 `detect()`，**先命中的获得该 payload**：

```
TCP: WebSocket → TLS SNI → HTTP/2 → HTTP/1 → MySQL → PostgreSQL
     → Redis → SOCKS5 → KnownText → RawTCP（兜底）
UDP: DTLS → QUIC → RawUDP（兜底）
```

每个 payload 只交给**一个** handler，避免 HTTP body 被 raw fallback 二次替换。detect 失败继续往下走，rewrite 失败返回错误结果。

### 4. 计算 edits（`core/utils.py` — `compute_edits()`）

使用 `difflib.SequenceMatcher` 计算 `old_stream → new_stream` 的编辑区间：

```
edits = [(old_start, old_end, replacement_bytes), ...]
```

用于后续将旧的 SEQ/ACK 映射到新流坐标。

### 5. 重分段（`core/resegment.py` — `resegment_tcp_flow()`）

两阶段策略：

**阶段 A — 填充已有包**：
- 按主片顺序遍历，每个旧包从 `new_stream[cursor]` 切出 `capacity` 字节
- 更新 `TCP.seq = base_seq + cursor`
- 多余旧包（new_stream 已分配完毕）加入删除队列

**阶段 B — 克隆新增包**：
- 以最后一个旧主片为模板 `copy.deepcopy()`
- 按 `last_capacity` 切片 new_stream，逐片生成新包
- 每个新增片之间插入克隆的 ACK 包
- IP.id 递增避免 ID 冲突
- 新包时间戳均匀插入在前后真实包之间（Decimal 精度）

### 6. ACK 克隆（`core/resegment.py` — `clone_response_ack()`）

从反方向最近的纯 ACK 包 deepcopy 模板，修改 `TCP.ack` 为 `base_seq + cursor`。让新增 TCP 分片的确认节奏接近真实 TCP 交互，减少 Wireshark 告警。

### 7. SEQ/ACK/SACK 修正（`core/resegment.py` — `adjust_seq_ack()`）

**SEQ 映射**：
```
offset = (old_seq - base_seq) % 2^32
new_seq = base_seq + map_offset(offset, edits)
```
`map_offset` 遍历 edits，累加新旧流的长度差，将旧流偏移映射到新流偏移。

**ACK 映射**：
```
使用反方向流的 base_seq + edits 做同样映射
```
因为 ACK 确认的是反方向已接收的数据。

**SACK 修正**（`adjust_sack_options()`）：
SACK option 各区间指向反方向流的字节范围，需要用反向流的 edits 逐一映射。

### 8. 重传片映射（`core/resegment.py` — `remap_retransmissions()`）

非主片的重传包：用 `map_offset(old_start/old_end, edits)` 将旧流坐标映射到新流坐标，取 `new_stream` 对应片段。超出单包容量时分片。

---

## 关键设计决策

| 决策 | 原因 |
|------|------|
| 流级改写而非包级 | 需要完整 HTTP 消息边界才能安全处理 Content-Length / chunked |
| 先重组再替换 | 避免 IP 跨 TCP 分片时只替换了一部分 |
| handler detect 失败继续 fallback | 误判（如半包）不应中断整条流 |
| raw handler 放在 dispatcher 最末 | 只在无结构化协议匹配时兜底 |
| 删除 IP/checksum 派生字段而非手算 | Scapy 自动重算比手动计算更可靠 |
| `--no-raw` / `--no-binary-raw` 开关 | 加密协议误命中 raw 替换会破坏数据 |
| Decimal 精度时间戳分配 | float 精度不足导致多克隆包时间戳相同 |

---

## 注意事项

1. **加密协议限制**：TLS 1.2/1.3 的应用数据（ApplicationData）已加密，无法替换其中的 IP。工具仅处理 TLS 明文的 ClientHello SNI。

2. **HTTP/2 / QUIC / DTLS**：均为二进制/加密协议，含旧 IP 时会被拒绝（`reject`），需检查日志确认。

3. **TCP 缺包**：如果抓包不完整，重组流中会有 holes（未覆盖字节），日志会 warning 提示。此时替换结果可能受影响。

4. **输出目录嵌套**：工具自动跳过位于输出目录内的文件，避免重复处理已生成的 PCAP。

5. **大文件**：所有数据包读入内存处理。单文件过大时建议先分割 PCAP。
