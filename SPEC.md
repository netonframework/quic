# quic — 规格说明（SPEC）

> Kotlin/Native 的 QUIC（RFC 9000 / 9001 / 9002，另含 RFC 9221 数据报、DPLPMTUD、ACK Frequency 草案）协议库，建在 `com.netonstream:io` 之上。
> 坐标 `com.netonstream:quic`，包 `neton.quic`。仓库 `quic`。
> 状态：草案 v0（2026-09-27，待评审；评审通过前不写代码）。

## 0. 依据与范围

- **建设方法**：neton-io SPEC §28.14。首版复刻参考实现的全部能力，并按 neton.io 与 Kotlin 协程落地。
- **参考实现**：`~/projects/reference/rust/quinn-0.11.12`（只读，版本与提交号见 `~/projects/reference/rust/README.md`）。该仓库包含三部分：
  - `quinn-proto` 0.11.18：无 I/O 的协议状态机。
  - `quinn` 0.11.12：异步运行时集成。
  - `quinn-udp`：UDP I/O，含 GSO / GRO / ECN / PKTINFO。
  - 下文 `$R/…` 指该仓库根目录。
- **能力盘点**：2026-09-27 逐项阅读源码所得。
- **标注**：
  - ✅ 对等：与参考实现一致。
  - ⚖️ 有意不同：附理由。
  - ⛔ 不适用：附理由。
- **参考实现本身的边界**（首版照此记录，不擅自扩展）：
  - 只支持 QUIC v1 与 draft 29–34（`DEFAULT_SUPPORTED_VERSIONS`）；无 QUIC v2（RFC 9369），无多路径。
  - 流与连接的流量控制窗口固定，没有自动调节；只有"何时发送窗口更新"的阈值会随窗口变化。
  - 客户端不迁移到服务端的首选地址，只保存该地址的连接 ID。
  - 握手期间到达的短头包直接丢弃，不缓存（代码中有 TODO）。
- **不在本库**：
  - TLS 1.3 本身（§4 列出本库对它的要求，实现方式待决）。
  - UDP 系统调用层：由 neton-io 数据报层提供（§9）。
  - HTTP/3：在 `http` 仓库的 `neton.http.h3`，建在本库之上。

## 1. 分层

```
neton.quic（本库）
   ├── neton.quic.proto：无 I/O、不读系统时间的协议状态机（复刻 quinn-proto；输入数据报 / 时间 / 应用命令，输出待发数据报 / 计时器 / 事件）
   └── neton.quic：协程驱动（复刻 quinn 的 Endpoint / Connection / 流 API），在 neton-io 数据报层上运行 proto
        ↓                                    ↓
TLS 1.3（QUIC 接口，§4，待决）       com.netonstream:io（反应器、数据报层 §9、计时）
```

- **proto 层是确定性的**（`$R/quinn-proto/src/lib.rs` 文档原话）：
  - 时间以参数传入。
  - 随机数由可设种子的生成器提供（`EndpointConfig.rngSeed`，每个连接一个派生种子）。
  - 因此参考实现的 109 个双端模拟测试（虚拟时间、可配延迟与 MTU）可以逐条移植并确定性复现。
- **驱动层**：
  - 参考实现用运行时抽象（`$R/quinn/src/runtime.rs`：定时器、spawn、UDP 套接字包装）同时支持 tokio / smol / async-std。
  - 本库不设运行时抽象 ⛔，直接使用 neton-io 的反应器、计时与数据报层。

## 2. proto 层对等清单

### 2.1 端点（`$R/quinn-proto/src/endpoint.rs`）
- **输入**：`handle(now, remote, localIp, ecn, datagram, buf) -> DatagramEvent?` ✅。事件有三种：`ConnectionEvent`、`NewConnection(Incoming)`、`Response(Transmit)`。
- **端点事件**：`handleEvent(ch, EndpointEvent)` ✅，事件为 NeedIdentifiers、ResetToken、RetireConnectionId、Drained。
- **建立连接**：`connect(now, clientConfig, remote, serverName)` ✅。
- **对 `Incoming` 的处置**：`accept`、`refuse`、`retry`（仅当 `mayRetry`）、`ignore` ✅。
- **路由顺序**（988–1122 行）✅：
  1. 本地连接 ID 表。
  2. 初始目的连接 ID 表（Initial / 0-RTT 使用；由对端控制的键用抗碰撞哈希）。
  3. 零长度连接 ID 时，按四元组或远端地址。
  4. 末尾 16 字节匹配无状态重置令牌。
- **版本协商**：仅服务端、且数据报 ≥ 1200 字节时回复；回复中加入 GREASE 版本 ✅。
- **无状态重置**：按 `minResetInterval` 限速；总比触发它的包至少小 1 字节；随机填充；令牌为连接 ID 在 `resetKey` 下的 HMAC ✅。
- **首个 Initial 的处理** ✅：
  - 小于 1200 字节 → 丢弃。
  - 饱和（达到 `maxIncoming` 或连接 ID 耗尽）→ 静默丢弃。
  - 客户端选择的目的连接 ID 短于 8 字节 → 回 PROTOCOL_VIOLATION 的 Initial CONNECTION_CLOSE。
  - Retry 令牌无效 → INVALID_TOKEN。
  - 后续 Initial / 0-RTT 按 `Incoming` 缓存，上限为 `incomingBufferSize` 与 `incomingBufferSizeTotal`。
- **`accept`**（549–699 行）✅：
  - 年龄超过 `maxIdleTimeout` 的拒绝。
  - 解密 Initial。
  - 构造传输参数：重置令牌、`original_dst_cid`、`retry_src_cid`、首选地址及其连接 ID。
  - 启动 TLS 会话，回放缓存的数据报。
- **Retry**：令牌负载为 `Retry{address, origDstCid, issued}`，以 `tokenKey` 密封；Retry 标签来自 TLS 层（744–792 行）✅。
- **连接 ID 空间耗尽判定**：用去 3/4 即视为耗尽，只影响 ≤ 4 字节的连接 ID ✅。
- **地址验证令牌**（`token.rs`、`bloom_token_log.rs`、`token_memory_cache.rs`）✅：
  - 令牌负载 `Retry | Validation{ip, issued}`，用 HKDF 派生的 AEAD 密封，每个令牌带随机 nonce。
  - 服务端用 `TokenLog.checkAndInsert` 防重放；默认实现为布隆过滤器（10 MiB，预期 100 万次命中），另有 `NoneTokenLog`。
  - 客户端用 `TokenStore`，默认 `TokenMemoryCache(256 个服务端 × 2 个令牌)`。
  - 路径验证后发送 NEW_TOKEN，次数为 `validationToken.sent`。

### 2.2 连接状态机（`$R/quinn-proto/src/connection/mod.rs`）
- **状态**：`Handshake`、`Established`、`Closed{reason}`、`Draining`、`Drained` ✅。
- **包号空间**：Initial / Handshake / Data 三个；0-RTT 使用 Data 空间 ✅。
- **密钥丢弃时机** ✅：
  - 客户端发出第一个 Handshake 包时丢弃 Initial 密钥；服务端收到第一个 Handshake 包时丢弃。
  - 服务端完成握手时发送 HANDSHAKE_DONE 并丢弃 Handshake 密钥；客户端收到 HANDSHAKE_DONE 时丢弃。
- **Retry（客户端）**：用新连接 ID 重新派生 Initial 密钥，重新排队 ClientHello，重传全部 0-RTT 数据 ✅。
- **0-RTT** ✅：
  - 从会话票据中取出缓存的传输参数，并去掉连接 ID、重置令牌、`min_ack_delay`、`ack_delay_exponent`、`max_ack_delay`。
  - 被拒绝时丢弃待发数据，并通知流层。
  - 被接受时，检查对端的各项限值没有缩小。
- **传输参数中的连接 ID 认证**：`initial_src_cid`、`original_dst_cid`、`retry_src_cid` ✅。
- **密钥更新** ✅：
  - 第一次更新的间隔在 10..1000 个包之间随机取值（借鉴 quic-go，让第一次更新提早发生），之后为 `confidentialityLimit − 10000`。
  - 预先计算下一代密钥；旧密钥保留到 KeyDiscard 计时器（3 × PTO）触发。
  - 超过完整性上限 → AEAD_LIMIT_REACHED。
- **路径验证与迁移** ✅：
  - 只有服务端、且配置了 `migration`，才接受对端迁移。
  - 同一 IPv4 地址上的 NAT 重绑定保留 RTT 与拥塞状态；其余情况新建路径数据。
  - PATH_CHALLENGE 同时发往新路径与旧路径；验证计时器为 3 × max(新路径 PTO, 旧路径 PTO)；不在路径上的 PATH_RESPONSE 填充到 1200 字节。
  - 客户端 `localAddressChanged()` 时换用新的远端连接 ID 并发送 PING。
- **防放大**：未验证的路径发送量不超过接收量的 3 倍（`paths.rs:159`）；只要尚有额度就允许发送一个完整 MTU 的包 ✅。
- **空闲超时**：取双方的较小值，0 表示关闭；实际计时为 max(空闲超时, 3 × PTO) ✅。
- **关闭** ✅：
  - `close()` 进入 Closed，Close 计时器为 3 × PTO。
  - 握手期间在所有可用空间发送 CONNECTION_CLOSE；应用关闭在非 Data 空间改写为传输层的 APPLICATION_ERROR。
  - 收到 Close 进入 Draining；无状态重置或 AEAD 上限直接进入 Drained。
- **自旋位**：`allowSpin` 时以 7/8 的概率启用 ✅。
- **跳过包号**（防乐观 ACK）：第一次跳过的包号在 0..64 内，之后在 [2^n, 2^(n+1)) 内；对端确认了被跳过的包号 → PROTOCOL_VIOLATION ✅。
- **无 I/O 契约** ✅：
  - 输入：`handleEvent`、`handleTimeout(now)`、应用命令（流、数据报、`close`、`ping`、`forceKeyUpdate`、`pathChanged`、各项窗口设置、`setMaxConcurrentStreams`、`localAddressChanged`）。
  - 输出：`pollTransmit(now, maxDatagrams, buf)`、`pollTimeout()`、`pollEndpointEvents()`、`poll()`。
  - 应用事件：HandshakeDataReady、Connected、ConnectionLost、Stream、DatagramReceived、DatagramsUnblocked。
  - 建议的轮询顺序：待发数据 → 计时器 → 端点事件 → 应用事件；时间必须单调递增。
- **计时器**：单张表，九种：LossDetection、Idle、Close、KeyDiscard、PathValidation、KeepAlive、Pacing、PushNewCid、MaxAckDelay ✅。

### 2.3 流、流量控制、数据报
- **流 API**（`streams/mod.rs`）✅：
  - `open(dir)`、`accept(dir)`。
  - `SendStream`：`write`、`writeChunks`（零拷贝）、`finish`、`reset(code)`、`stopped()`、`setPriority(Int)`。
  - `RecvStream`：`read(ordered) -> Chunks`（`next(maxLen)` 与 `finalize`）、`stop(code)`、`receivedReset()`。
  - 流事件：Opened、Readable、Writable、Finished、Stopped、Available。
  - 状态与错误：发送侧 Ready / DataSent / ResetSent；接收侧 Recv / ResetRecvd；`WriteError{Blocked, Stopped, ClosedStream}`、`ReadError{Blocked, Reset}`、`ReadableError{ClosedStream, IllegalOrderedRead}`。
- **乱序读**：重组器最多 1024 个块，小于 128 字节的块会合并；一旦乱序读过，不能再有序读 ✅。
- **流量控制**（`streams/state.rs`、`recv.rs:112`）✅：
  - 连接级：`receiveWindow`；窗口缩小时记录欠额；增量 ≥ 窗口的 1/8 时发 MAX_DATA。
  - 流级：增量 ≥ `streamReceiveWindow` 的 1/8 时发 MAX_STREAM_DATA。
  - 发送侧：`writeLimit = min(对端额度, sendWindow − 已缓存)`，已确认但未释放的数据仍计入已缓存。
  - 发送 DATA_BLOCKED / STREAM_DATA_BLOCKED。
  - 无自动调节（与参考一致）。
- **流数限制**：增量超过 1/8 时发 MAX_STREAMS；可在运行中修改；收到 STREAMS_BLOCKED 只记录 ✅。
- **优先级**：按优先级的堆；`sendFairness`（默认 true）时同优先级的流轮转，否则按写入顺序 ✅。
- **RESET_STREAM / STOP_SENDING**：校验方向与流是否已打开；RESET_STREAM 被确认后释放流 ✅。
- **数据报（RFC 9221，`datagrams.rs`）** ✅：
  - `send(bytes, drop)`：`drop = true` 时挤掉最旧的；`drop = false` 时返回 Blocked，之后发 DatagramsUnblocked 事件。
  - `maxSize()`、`recv()`、`sendBufferSpace()`。
  - 错误：UnsupportedByPeer、Disabled、TooLarge、Blocked。
  - 帧类型 0x30 / 0x31。接收溢出时丢弃最旧的；MTU 下降或迁移后变得过大的已排队数据报被丢弃。

### 2.4 丢包检测、拥塞控制、pacing、ACK、MTU、GSO、ECN
- **RTT**（`paths.rs:290-356`）✅：
  - smoothed 按 7/8 加权，var 按 3/4 加权，另记 latest 与 min。
  - 只有 `min + ackDelay <= latest` 时才扣除 ACK 延迟。
  - `ptoBase = srtt + max(4·var, 1 ms)`。
- **丢包检测**（1695–1826 行）✅：
  - 包阈值 3，或时间阈值 max(9/8 × 保守 RTT, 1 ms)。
  - 持续拥塞：Data 空间 3 × PTO 内没有任何确认，且只在有了第一个 RTT 样本之后判定。
  - PTO 退避 2^min(n, 16)。
  - 每次 PTO 发 2 个探测包（受防放大限制时发 1 个）；探测包不受拥塞控制，但受 pacing，大小钳制在 1200 字节。
  - 握手期间没有在途数据时，也会发送防死锁的 PTO 探测。
- **拥塞控制器接口**（`congestion.rs`）✅：
  - 方法：`onSent`、`onAck`、`onEndAcks`、`onCongestionEvent`、`onMtuUpdate`、`window`、`metrics`、`initialWindow`。
  - 由 `ControllerFactory` 创建实例。
  - NewReno：初始窗口 12000 字节，丢包时减半。
  - Cubic（默认）：β = 0.7，C = 0.4，含 Reno 友好项。
  - BBR：参考标为实验性（移植自 quiche BBRv1，初始窗口 200 × 1200 字节）；本库同样标为实验性 ✅。
- **pacing**（`pacing.rs`）✅：
  - 令牌桶：容量为 cwnd × 2 ms / RTT，钳制在 10..256 × MTU；补充速率为每 RTT 1.25 × cwnd；返回的等待时间乘以 4/5。
  - cwnd 超过 u32 上限时关闭 pacing。
  - 需要亚毫秒级的计时，见 §9 对 neton-io 的要求。
- **ACK 策略**（`spaces.rs`）✅：
  - Initial / Handshake 空间立即确认。
  - Data 空间用 `max_ack_delay`（通告固定为 25 ms，`ack_delay_exponent` 为 3），并有 ack-eliciting 阈值。
  - 收到 CE 标记或乱序包时立即确认。
  - 未确认的非 ack-eliciting 包超过 10 个时强制确认。
  - 每个 ACK 帧最多 64 个区间。
  - ACK 捎带在其他帧上，每 `rtt + 对端 maxAckDelay + 1 ms` 最多一次。
  - 用 128 位滑动窗口检测重复包。
- **ACK Frequency**（`ack_frequency.rs`，draft-04）✅：
  - 总是通告 `min_ack_delay = 1 ms`。
  - 配置了 `ackFrequencyConfig` 时发送 ACK_FREQUENCY（0xaf）。
  - 在丢包探测、MTU 探测、PATH_CHALLENGE 应答中附带 IMMEDIATE_ACK（0x1f）。
- **DPLPMTUD**（`mtud.rs`）✅：
  - 在 `initialMtu` 与 min(`upperBound`, 对端 `max_udp_payload_size`) 之间二分查找；步长小于 `minimumChange` 时停止。
  - 每个探测尺寸最多重传 3 次；探测包为填充到目标尺寸的 PING（附 IMMEDIATE_ACK），不计入拥塞控制。
  - 可疑的丢包突发累计 3 次即判定为黑洞：退回 `minMtu`，冷却期后重新查找；每隔 `interval` 重新查找一次。
  - 只有数据报层报告"不会分片"（`!mayFragment`）时才启用。
- **GSO 批量**（460–1020 行）✅：
  - `pollTransmit` 最多打包 `maxDatagrams` 个等长分段；第一个包决定分段大小，其余填充到该大小。
  - 需要填充超过 16 字节，或包含丢包探测时，本批结束。
  - 预先为整批预留缓冲。
  - 剩余空间足够时合并 Initial / Handshake / 1-RTT 包。
  - 客户端的 Initial，以及服务端 ack-eliciting 的 Initial，填充到 1200 字节。
- **ECN**（1565–1612 行）✅：
  - 每条路径开始时发送 ECT(0)。
  - ACK 中缺少 ECN 计数或校验失败时停用 ECN。
  - CE 计数增加时触发一次拥塞事件（丢失字节数记为 0）。
  - 接收侧的 ECN 计数通过 ACK_ECN 回报。

### 2.5 帧与包编码
- **帧**（`frame.rs:108-139`）✅：PADDING、PING、ACK / ACK_ECN、RESET_STREAM、STOP_SENDING、CRYPTO、NEW_TOKEN、STREAM（0x08–0x0f）、MAX_DATA、MAX_STREAM_DATA、MAX_STREAMS（双向 / 单向）、DATA_BLOCKED、STREAM_DATA_BLOCKED、STREAMS_BLOCKED（双向 / 单向）、NEW_CONNECTION_ID、RETIRE_CONNECTION_ID、PATH_CHALLENGE、PATH_RESPONSE、CONNECTION_CLOSE（0x1c / 0x1d）、HANDSHAKE_DONE、ACK_FREQUENCY、IMMEDIATE_ACK、DATAGRAM。
- **帧的合法空间** ✅：Initial / Handshake 空间只允许 PADDING、PING、CRYPTO、ACK、CLOSE；0-RTT 禁止 CRYPTO 与应用层 CLOSE。
- **包**（`packet.rs`）✅：
  - 长头（Initial / Handshake / 0-RTT）、Retry、短头（自旋位、密钥阶段）、版本协商。
  - 合并包拆分。
  - 固定位 GREASE。
  - 包号编码 1–4 字节，按 RFC 9000 附录 A.3 解码。
- **头部保护与 AEAD**：先 AEAD 后头部保护（`packet_builder.rs`、`packet_crypto.rs`）✅。
- **varint**：1 / 2 / 4 / 8 字节 ✅。
- **帧的写出顺序**（3156–3439 行）✅：HANDSHAKE_DONE、PING、IMMEDIATE_ACK、ACK、ACK_FREQUENCY、PATH_CHALLENGE / PATH_RESPONSE、CRYPTO（按 2^14 以下切分）、流控制帧、NEW_CONNECTION_ID、RETIRE_CONNECTION_ID、DATAGRAM、NEW_TOKEN、STREAM、可选的捎带 ACK。
- **连接 ID 管理**：远端连接 ID 最多保存 5 个；本地连接 ID 支持 retire-prior-to，并按生存期轮换（PushNewCid 计时器）✅。
- **传输参数**（`transport_parameters.rs`）✅：
  - 支持的 21 个参数。
  - `active_connection_id_limit` 为 5（零长度连接 ID 时为 2）。
  - `max_datagram_frame_size` = min(接收缓冲, 65535)。
  - 附加 GreaseQuicBit、`min_ack_delay`、一个随机的保留参数；写出顺序打乱（防僵化）。

### 2.6 配置（全部选项与默认值）
**TransportConfig**（`config/transport.rs:363-406`，默认值按 100 Mbps、100 ms RTT 调校）✅：

| 选项 | 默认 |
|---|---|
| maxConcurrentBidiStreams / UniStreams | 100 / 100 |
| maxIdleTimeout | 30 s（null = 不超时） |
| streamReceiveWindow | 1,250,000 |
| receiveWindow | VarInt 最大值 |
| sendWindow | 10,000,000 |
| sendFairness | true |
| packetThreshold | 3 |
| timeThreshold | 1.125 |
| initialRtt | 333 ms |
| initialMtu / minMtu | 1200 / 1200（下限 1200） |
| mtuDiscoveryConfig | 默认启用 |
| padToMtu | false |
| ackFrequencyConfig | null |
| persistentCongestionThreshold | 3 |
| keepAliveInterval | null |
| cryptoBufferSize | 16 KiB |
| allowSpin | true |
| datagramReceiveBufferSize | 1,250,000 |
| datagramSendBufferSize | 1 MiB |
| congestionControllerFactory | Cubic |
| enableSegmentationOffload | true |
| qlogStream | 无（见 §8） |

- **MtuDiscoveryConfig** ✅：interval 600 s、upperBound 1452（上限 65527）、blackHoleCooldown 60 s、minimumChange 20。
- **AckFrequencyConfig** ✅：ackElicitingThreshold 1、maxAckDelay null（使用对端的值）、reorderingThreshold 2。

**EndpointConfig**（`config/mod.rs:37-191`）✅：

| 选项 | 默认 |
|---|---|
| resetKey | 随机 64 字节 HMAC-SHA256 密钥 |
| maxUdpPayloadSize | 1472（有效范围 1200..65527） |
| cidGenerator | 哈希式：8 字节 = 3 字节随机数 + 5 字节签名，可识别外来的连接 ID；可设生存期 |
| supportedVersions | v1 + draft 29–34 |
| greaseQuicBit | true |
| minResetInterval | 20 ms |
| rngSeed | null |

**ServerConfig**（`config/mod.rs:197-374`）✅：

| 选项 | 默认 |
|---|---|
| retryTokenLifetime | 15 s |
| migration | true |
| preferredAddressV4 / V6 | null |
| maxIncoming | 65536 |
| incomingBufferSize | 10 MiB |
| incomingBufferSizeTotal | 100 MiB |
| validationToken.lifetime | 2 周 |
| validationToken.log | 布隆过滤器 |
| validationToken.sent | 2 |
| tokenKey | 随机 |
| timeSource | 系统时间 |

**ClientConfig**（`config/mod.rs:553-619`）✅：

| 选项 | 默认 |
|---|---|
| tokenStore | 内存缓存（256 个服务端 × 2 个令牌） |
| initialDstCidProvider | 随机 20 字节 |
| version | 1 |

## 3. 驱动层与 API（复刻 quinn，按 neton.io 落地）

- **并发模型**：
  - 参考：一个端点驱动任务持有带互斥锁的 `Endpoint`；每个连接一个驱动任务；端点与连接之间用无界通道传递事件；接收循环以 50 µs 为时间片（`WorkLimiter`），每轮最多 160 次。
  - 本库 ⚖️：一个 `Endpoint` 归属一个反应器，它的 UDP 套接字与它的所有连接都在该反应器上，不共享、不加锁；端点与连接之间在同一反应器上直接调用，不经过通道。
  - 时间片与公平性交给反应器的轮次预算（neton-io §28.4）。
  - 多核：每个反应器一个端点（`SO_REUSEPORT`），按连接 ID 把数据报导向对应反应器（Linux 上用 eBPF 等手段）。这是后续项，参考实现也是一个端点一个驱动。
- **API**（对等，协程风格）：

| 类型 | 能力 |
|---|---|
| `Endpoint` | `client`、`server`、`accept`、`connect`、`setDefaultClientConfig`、`rebind`、`setServerConfig`、`localAddr`、`openConnections`、`close`、`waitIdle`、`stats` |
| `Incoming` | `accept`、`refuse`、`retry`、`ignore`、`remoteAddressValidated`、`mayRetry`、`origDstCid` |
| `Connecting` | `into0Rtt`、`handshakeData`、`localIp`、`remoteAddress` |
| `Connection` | `openUni` / `openBi`、`acceptUni` / `acceptBi`、`readDatagram`、`sendDatagram`、`sendDatagramWait`、`maxDatagramSize`、`closed`、`closeReason`、`close`、`rtt`、`stats`、`congestionState`、`handshakeData`、`peerIdentity`、`stableId`、`forceKeyUpdate`、`exportKeyingMaterial`、`setMaxConcurrent*`、`setSendWindow`、`setReceiveWindow` |
| `SendStream` | `write`、`writeAll`、`writeChunks`、`finish`、`reset`、`setPriority`、`stopped` |
| `RecvStream` | `read`、`readExact`、`readChunk(max, ordered)`、`readChunks`、`readToEnd(limit)`、`stop`、`receivedReset`、`is0Rtt` |

  流也以 neton-io `IoStream` 的形式提供（对应参考的 `futures-io` 特性），使上层可以复用 `Framed` / `Codec`；能力声明按 neton-io §28.6。
- **背压**：写被阻塞时挂起，由 Writable 事件恢复；读同理。
- **生命周期** ⚖️：
  - 参考依赖 Rust 的 Drop：SendStream 被丢弃时 finish（已被 stop 时 reset）；RecvStream 未读完被丢弃时 stop(0)；最后一个 Connection 句柄被丢弃时以 0 关闭；Incoming 被丢弃时拒绝。
  - Kotlin 没有 Drop，本库改为显式的 `close()`（`AutoCloseable`），并依靠结构化并发：连接的作用域结束时，按上述规则收尾；未显式处置的 `Incoming` 在端点关闭时被拒绝。
  - 每条规则都有对应测试。

## 4. TLS 1.3 的 QUIC 接口（依赖，实现方式待决）

参考实现的加密抽象（`$R/quinn-proto/src/crypto.rs`）与 rustls 集成（`crypto/rustls.rs`）决定了 TLS 层必须提供的能力：
1. 只支持 TLS 1.3；握手字节按加密阶段（Initial / Handshake / 1-RTT）经 CRYPTO 流输入输出。
2. 导出每个阶段的流量密钥（Handshake、1-RTT）；由目的连接 ID 派生 Initial 密钥（RFC 9001 中 v1 与各草案的 salt）。
3. 包保护：AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305；头部保护：AES-ECB / ChaCha20，采样长度正确。
4. 密钥更新（HKDF-Expand-Label "quic ku"）。
5. `quic_transport_parameters` 扩展（0x39）双向。
6. 会话票据、0-RTT 密钥、早期数据是否被接受、`max_early_data_size = 0xffffffff`。
7. ALPN、SNI、对端证书链。
8. RFC 5705 / 8446 导出器。
9. 每个套件的 AEAD 机密性与完整性上限。
10. HMAC-SHA256、HKDF-SHA256、AES-256-GCM（令牌与重置密钥）。
11. 固定的 AES-128-GCM Retry 完整性标签。
12. Initial 套件为 TLS13_AES_128_GCM_SHA256。

**待决（需用户选择）**：TLS 1.3 从哪里来。neton-io 已把 TLS 移出（neton-io SPEC §21、§28.1）。候选：
- (a) 自研 Kotlin TLS 1.3，底层密码原语用 libcrypto（neton-io SPEC §18.5 评估过）。
- (b) OpenSSL 3.5+ 的"第三方 QUIC 协议栈"TLS 接口。
- (c) BoringSSL 的 QUIC API。

选定之前，proto 层先用参考实现 `perf` 中的"无保护"加密实现（`$R/perf/src/noprotection.rs`）与测试用的明文密钥运行，以推进其余部分。

## 5. 测试（移植清单）

| 来源 | 数量 | 内容 |
|---|---|---|
| `$R/quinn-proto/src/tests/mod.rs` | 109 | 虚拟时间双端模拟（`Pair`）：版本协商、生命周期、无状态重置、导出器、流的 finish / reset / stop、证书拒绝、拥塞、高延迟握手、0-RTT（成功、被拒、缓存）、ALPN、流数限制、DATA_BLOCKED、密钥更新（含乱序）、重传、立即关闭、空闲超时、迁移、流量控制、零长度连接 ID、keep-alive、连接 ID 轮换、尾部丢包、数据报、防死锁探测、MTUD（探测、黑洞、600 s 重查）、ACK Frequency、GSO、`padToMtu`、手动拒绝、短初始连接 ID、首选地址 |
| `$R/quinn-proto/src/tests/token.rs` | 7 | 令牌 |
| quinn-proto 模块内测试 | 约 140 | mtud 28、assembler 26、streams/state 24、range_set 13、cid_queue 11、spaces 10、transport_parameters 8、bloom_token_log 7、send_buffer 7 等 |
| `$R/quinn/src/tests.rs` 等 | 21 + 3 + 1 + 2 | 真实套接字：握手超时、关闭端点、IPv4 / 双栈回显、重绑定、0-RTT、IP 屏蔽、零长度连接 ID、流的 stop / 丢弃；`many_connections`（多节点各发 1 MB）；后量子密钥交换（取决于 TLS 选择） |
| `$R/quinn-udp/tests/tests.rs` | 8 | 基本收发、源 IP、ECN（v4 / v6 / 双栈 / v4 映射）、套接字缓冲大小：作为 neton-io 数据报层的验收用例 |
| 模糊测试 | 4 个目标 | packet（PartialDecode）、params（传输参数）、streamid、streams |

另加参考仓库中没有、但本库需要的验收：
- 与 quinn 互通：本库客户端对 quinn 服务端，quinn 客户端对本库服务端。
- quic-interop-runner 的对应用例（在选定 TLS 之后）。

## 6. 性能对照

- **工具**：移植 `$R/bench/src/bin/bulk.rs`（批量吞吐：客户端数、流数、大小、乱序读、密码套件、MTU）与 `$R/perf`（含"无保护"模式，用于隔离加密成本）。
- **对照**：与 quinn 0.11.12 在 153 上以同等配置运行：相同密码套件、拥塞控制器、MTU、GSO / GRO 开关、窗口。按 neton-io §28.4 的规程与验收指标进行：吞吐、每字节 CPU、每包分配数（callgrind）、p99、公平性。

## 7. 参考中的性能手段（逐项落实）

- GSO 批量与分段对齐（填充上限 16 字节）、整批预留缓冲。每次发送最多 10 个分段，每轮驱动最多 20 个数据报。
- GRO 接收按步长拆分，每次 `recvmmsg` 收 32 个。
- 令牌桶 pacing，以 2 ms 为突发窗口。
- 接收循环按时间片分配（映射到反应器预算）。
- 全程零拷贝（neton-io `Bytes`）。
- 原地 AEAD，预先计算下一代密钥。
- 数据结构：本地生成的连接 ID 用快速哈希，对端控制的键用抗碰撞哈希；ACK 区间用小型区间集合；128 位窗口检测重复包；连接槽表。
- ACK 捎带按 RTT 节流；窗口类更新在用去 1/8 后才发送。
- 热路径按 neton-io §24 / §26.1 零分配，以 callgrind 实测为准。

## 8. 标注为 ⛔ 或延后的参考能力

| 参考能力 | 标注 | 理由 |
|---|---|---|
| tokio / smol / async-std 运行时抽象 | ⛔ | 统一在 neton-io 上 |
| `lock_tracking` 特性 | ⛔ | 本库无锁（§3） |
| Apple `fast-apple-datapath`（私有 `sendmsg_x` / `recvmsg_x`） | ⛔（首版） | 私有接口，App Store 风险；以后作为可选项评估 |
| qlog 输出 | 延后 | 首版之后补齐；参考中是可选特性 |
| 后量子密钥交换、FIPS | 取决于 §4 | TLS 层能力 |
| wasm32 | ⛔ | 不在 Kotlin/Native 目标之列 |

## 9. 需要 neton-io 先提供的能力（缺口清单）

| 需要 | 现状 | 处理 |
|---|---|---|
| **数据报层**：非阻塞 + 就绪通知；批量接收（每次 32 个）；每个数据报的 ECN 读写；目的 IP 报告与源 IP 选择（PKTINFO）；DF / PMTU 探测模式与 `mayFragment`；Linux GSO（`UDP_SEGMENT`，最多 64 段，遇 EIO / EINVAL 时运行中关闭）；Linux GRO（带步长）；Windows USO / URO（可选）；双栈与 v4 映射地址；不带 TOS 的 EINVAL 回退；容忍 EMSGSIZE 与 ECONNRESET；可配置的套接字缓冲；重绑定（换套接字后通知连接） | neton-io SPEC §28.9 只列了需求 | 以此表与 `$R/quinn-udp`（逐平台设施见盘点）为依据，在 neton-io 另起数据报层 SPEC；`quinn-udp` 的 8 个测试作为其验收 |
| **高精度计时**：1 ms 计时粒度（`TIMER_GRANULARITY`），pacing 需要亚毫秒级 | 反应器计时轮精度 10 ms（neton-io §23.2） | neton-io 另起：高精度计时器（或按连接的截止时间直接驱动一次轮询超时） |
| 单调时钟与系统时间 | 反应器有单调时钟 | 公开为 API |
| 加密安全的随机数 | 无 | 与 `websocket` 同一问题，评估是否移入公共模块 |
| 密码原语（AEAD、HKDF、HMAC、头部保护） | 无 | 随 §4 的 TLS 决定一起提供 |

## 10. 实施顺序（在 `http` 首版、`websocket`、HTTP/2 之后；前置：neton-io 数据报层 SPEC 通过、§4 TLS 决定）

1. varint、帧、包、传输参数编解码 + 对应的模块内测试与模糊测试。
2. 加密抽象 + "无保护"实现；连接状态机与握手（以测试密钥）；双端模拟框架（虚拟时间）。
3. 流、流量控制、数据报。
4. 丢包检测、拥塞控制（NewReno、Cubic、BBR 实验性）、pacing、ACK 策略、ACK Frequency。
5. DPLPMTUD、GSO 批量、ECN。
6. 迁移、密钥更新、0-RTT、Retry、令牌、版本协商、无状态重置。
7. TLS 1.3 接入（§4），证书与 ALPN；与 quinn 互通。
8. 协程驱动与 API（neton-io 数据报层）；真实套接字测试。
9. quic-interop-runner；性能对照。

每一步单独验证、单独提交，结果记入本 SPEC。
