# 协议 IP 替换汇总

以下表格汇总了当前项目支持处理的所有协议的 IP 替换行为。

| 协议 | 传输层 | 是否替换IP | 替换IP结构类型 | 处理方式 |
|------|--------|-----------|---------------|---------|
| **IPv4** | —（网络层） | ✅ 是 | IP Header src / dst | 直接替换 `packet[IP].src` / `.dst`，修改后清除 IP len/chksum 及 L4 派生字段，交由 Scapy 重算 |
| **ARP** | —（链路层） | ✅ 是 | ARP psrc / pdst（协议源/目的 IPv4 地址） | 直接替换 `arp.psrc` / `arp.pdst`，无校验和字段，无需额外处理 |
| **ICMPv4** | —（网络层） | ✅ 是 | IPerror 差错报文中引用的原始 IPv4 Header（src/dst）；非差错 ICMP 的 payload 文本 | IPerror：替换引用 IP 头 src/dst → 删除 len/chksum → 重算嵌入 IPv4 + 外层 ICMP checksum；非差错：ASCII + packed 二进制兜底替换，重算 ICMP checksum |
| **DHCP/BOOTP** | UDP | ✅ 是 | BOOTP 固定字段（ciaddr / yiaddr / siaddr / giaddr）+ DHCP options 中已解析为 IPv4 字符串的选项值（如 router / name_server 等多地址 option） | 结构化替换 BOOTP 头和 DHCP option 中的 IPv4 字段；不支持替换的字段含旧 IP 则拒绝；替换后校验新旧 payload 确保旧 IP 已完全消除 |
| **DNS** | UDP / TCP | ✅ 是（仅 A 记录） | DNS RR 中 type=A 的 rdata（4 字节 packed IPv4） | UDP：直接 Scapy DNS 解析，替换 A 记录 rdata → 删除 rdlen 派生字段；TCP：逐 length-prefixed message 解析后再同上处理。DNS name / TXT / EDNS 等字段含旧 IP 则拒绝 |
| **TLS ClientHello SNI** | TCP | ✅ 是（仅 SNI extension） | TLS Record → Handshake → ClientHello → Extensions → SNI(ext_type=0x0000) 的 server_name 字段 | 递归解析 TLS Record / Handshake / ClientHello / Extensions 层次结构，仅在 SNI extension 中做 ASCII IP 文本替换；非 Handshake record 或非 ClientHello 消息含旧 IP 时拒绝；替换后更新 TLS Record 长度和 Extensions 总长度 |
| **HTTP/1.x** | TCP | ✅ 是 | 请求行/响应行、Headers、Body（Content-Length / chunked / gzip / deflate 编码）中的 ASCII IP 文本 | 解析 HTTP header 块 → 判断编码方式（CL / chunked / 压缩）→ 解码 body → 全局字符串替换（`old_ip` → `new_ip`）→ 重新编码 → 更新 Content-Length / chunk-size 等长度字段。同时处理 WebSocket Upgrade（101 Switching Protocols）状态切换 |
| **HTTP/2** | TCP | ❌ 否（拒绝） | — | 二进制帧协议，HEADERS 使用 HPACK/QPACK 压缩，不支持裸文本替换。含旧 IP 时明确拒绝（`http2.not_supported_with_ip`），不含时安全跳过 |
| **WebSocket** | TCP | ✅ 是（仅 text opcode=0x1） | WebSocket Frame：text(opcode=0x1) 消息的 payload 文本 | 解析 frame header（fin/rsv/opcode/mask/length）→ 解 mask → 替换 text payload 中的 IP → 重新 mask → 更新 frame length 字段。仅支持 fin=1 的 text 帧；分片消息、二进制帧、permessage-deflate 压缩模式含旧 IP 则拒绝 |
| **MySQL** | TCP | ✅ 是（仅 COM_QUERY） | COM_QUERY(0x03) 命令的 SQL 文本中的 ASCII IP | 逐 packet 解析：COM_QUERY 时替换 SQL 中的 IP 文本 → 重新构造 MySQL packet（更新 3 字节小端 payload length）；其他命令类型含旧 IP 则拒绝 |
| **PostgreSQL** | TCP | ✅ 是（仅 Query 'Q'） | Query(Q) 消息的 SQL 文本中的 ASCII IP | 逐 message 解析：Query 消息中替换 null-terminated SQL 文本中的 IP → 更新 4 字节大端 message length（含自身）；其他消息类型含旧 IP 则拒绝 |
| **MongoDB** | TCP | ✅ 是（有限支持） | BSON string/symbol/JavaScript(0x02/0x0D/0x0E) 字段、cstring（含 key）、regex pattern、DBPointer 中的 ASCII IP；BSON binary（subtype 0）中的 4 字节 packed IPv4 | 递归解析 BSON document → 替换 string-like 字段和 cstring 中的 IP 文本 → 更新 BSON string length 前缀和 document length；binary 字段中 4 字节 packed IP 做等长替换；压缩消息、未知 BSON 类型含旧 IP 则拒绝 |
| **Redis RESP** | TCP | ✅ 是 | SimpleString(+)、Error(-)、BulkString($) 中的 ASCII IP 文本 | 递归解析 RESP 元素 → 对 + / - / $ 类型做 IP 文本替换 → 更新 BulkString 的长度前缀；Integer(:) 不做替换；Array(*) 递归处理子元素 |
| **SOCKS5** | TCP | ✅ 是 | ATYP=0x01（IPv4 地址）：4 字节 packed IPv4；ATYP=0x03（域名）：域名中的 ASCII IP 文本 | IPv4 场景：等长替换 4 字节 packed IP（`old_ip_bin` → `new_ip_bin`）；域名场景：替换域名中的 IP 文本，更新域名长度字节；ATYP=0x04(IPv6) 含旧 IP 则拒绝；Greeting 消息无地址字段直接跳过 |
| **FTP** | TCP | ✅ 是 | FTP 控制连接文本中的 dotted IPv4（如 `1.2.3.4`）和逗号分隔 IPv4（如 `1,2,3,4`，用于 PORT/PASV/EPRT 命令） | 纯文本协议，全局字符串替换 dotted 和 comma 两种 IPv4 表示；无长度字段需要更新 |
| **SMTP** | TCP | ✅ 是 | SMTP 命令/响应/DATA 正文中的 ASCII IP 文本 | 纯文本协议，全局字符串替换（`old_ip` → `new_ip`）；无长度字段需要更新；SMTPS/STARTTLS 加密后的内容由 DTLS/TLS handler 处理 |
| **Telnet** | TCP | ✅ 是 | Telnet 数据流中的 ASCII IP 文本 | 纯文本协议，全局字符串替换；IAC 协商字节不影响文本替换；无长度字段需要更新 |
| **RDP** | TCP | ❌ 否（拒绝） | — | 基于 TPKT/X.224，通常升级到 TLS/CredSSP 加密。含旧 IP 时明确拒绝，避免 raw fallback 破坏二进制协议 |
| **DTLS** | UDP | ❌ 否（拒绝） | — | UDP 加密协议，无法安全替换。含旧 IP 时拒绝（`dtls.with_ip_not_supported`），不含时安全跳过 |
| **QUIC** | UDP | ❌ 否（拒绝） | — | UDP 加密协议（基于 TLS 1.3），无法安全替换。含旧 IP 时拒绝（`quic.with_ip_not_supported`），不含时安全跳过 |
| **SSH / FTP-banner / SMTP-banner / POP3 / IMAP** | TCP | ❌ 否（拒绝） | — | 已知明文协议但未实现结构化替换（banner 识别）。含旧 IP 时拒绝，不含时安全跳过 |
| **TCP Raw（兜底）** | TCP | ✅ 是 | TCP payload 中任意位置的 ASCII IP 文本 | 当所有结构化协议 handler 都无法识别时，对 TCP payload 执行全局 ASCII 字符串替换（`old_ip` → `new_ip`）+ packed 4 字节二进制替换 |
| **UDP Raw（兜底）** | UDP | ✅ 是 | UDP payload 中任意位置的 ASCII IP 文本 | 当 DHCP / DNS(UDP) / DTLS / QUIC handler 都无法识别时，对 UDP payload 执行全局 ASCII 字符串替换 + packed 4 字节二进制替换 |

---

> **说明**：以上表格中"替换IP结构类型"列描述的是该协议中 IP 地址出现的**具体字段或数据结构**，而非 IP 地址的表现形式（dotted ASCII / packed 4 字节 / 逗号分隔等）。处理方式列则详细说明了具体的替换策略和校验和/长度字段的修正方法。
