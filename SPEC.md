# quic — 规格说明（SPEC）

> Kotlin/Native 的 QUIC（RFC 9000 / 9001 / 9002，另含 RFC 9221 数据报、DPLPMTUD、ACK Frequency 草案）协议库，建在 `com.netonstream:io` 之上。
> 坐标 `com.netonstream:quic`，包 `neton.quic`。仓库 `quic`。
> 状态：v1 已实现（含会话恢复与 0-RTT，§11.14），实现与验收记录见 §11；首个发布版本 0.1.0（2026-10-08，依赖 io 0.3.0、openssl 4.0.2；含 Windows，见 §11.13）。

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
  - TLS 1.3 协议本身：由 OpenSSL 4.0.2（经 `com.netonstream:openssl` 的原始绑定）完成；本库实现 QUIC 所需的 TLS 会话层（§4、§11.9）。
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
  - 参考：一个端点驱动任务持有带互斥锁的 `Endpoint`；**每个连接一个独立的驱动任务**，由运行时调度到任意线程；端点与连接之间用无界通道传递事件；
    接收循环以 50 µs 为时间片（`WorkLimiter`），每轮最多 160 次；每个连接每次驱动最多发 20 个数据报、每次发送最多 10 个分段。
  - **本库首版：单反应器端点** ⚖️（明确不等于参考）。一个 `Endpoint` 与它的 UDP 套接字、它的全部连接都在同一个反应器上，不共享、不加锁；端点与连接
    之间在同一反应器上直接调用，不经过通道。因此首版一个端点只用一个核，**多核吞吐不宣称与参考对等**；需要多核时，应用可在不同端口 / 地址上开
    多个端点。
  - **驱动自带预算**（反应器的轮次预算只限制任务个数，限制不了一个任务内部处理多少数据报，所以协议驱动必须自己有界）：
    - 接收：每次唤醒最多处理 `maxDatagramsPerTurn` 个数据报（默认 32 × 5，即五次批量接收）或 `recvTimeBudget`（默认 50 µs，同参考），先到为准；
      还有数据时把自己重新排到反应器任务队列末尾，而不是在循环里继续。
    - 发送：每个连接每次驱动最多 20 个数据报、每次发送最多 10 个分段（同参考）；有剩余时重新排队。
    - 端点对其全部连接轮转驱动，一个连接用完预算后让给下一个。
    - 测试：一个连接持续大量收发时，同一端点上其他连接的握手与小请求 p99 有上限（neton-io §28.4 的 F 类场景）。
  - **多核（后续阶段，首版不做）**，需先另立设计：
    - 服务端连接 ID 中编码所属反应器，据此路由；
    - Linux 上 `SO_REUSEPORT` + eBPF 按连接 ID 导向对应反应器；
    - 没有 eBPF 时，由一个接收反应器按连接 ID 转交给所属反应器（跨线程移交的成本需实测）；
    - 迁移后连接的归属以连接 ID 为准，不以四元组为准；
    - 新连接（尚无本端连接 ID）的分配策略。
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

## 4. TLS 1.3 的 QUIC 接口（已决定：本库在 openssl-kotlin 的原始绑定上实现，§11.9）

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

**决定（2026-09-29，所有者决定）**：QUIC 的 TLS 会话在**本库**实现，直接使用 openssl-kotlin（`com.netonstream:openssl` 4.0.2）的
**原始绑定**（包 `neton.openssl.c`，完整 OpenSSL 头文件的 cinterop）调用 OpenSSL 的第三方 QUIC TLS 接口（`SSL_set_quic_tls_cbs`、
`SSL_set_quic_tls_transport_params`、`SSL_set_quic_tls_early_data_enabled`）。§11.7 第一批原本请 openssl-kotlin 提供的安全门面
（按级别的 CRYPTO 输入输出、各级别秘密、ALPN、传输参数原始字节、证书验证、告警映射，以及输入缓冲生命周期、输出上限、C 边界异常、
关闭后无悬空回调等契约）改由本库实现，契约不变，逐条在 §11.9 记录实现方式与测试。openssl-kotlin 不作修改；§11.7 的请求不再阻塞本库。

**TLS 的来源（2026-09-27 用户确定）**：由另外封装的 `openssl-kotlin` 库提供（基于 OpenSSL 4.0.2），本库不自行实现 TLS，也不在此之前推进依赖 TLS 的部分。
本库先完成与 TLS 无关的全部工作；`openssl-kotlin` 可用后，按下面的可行性验证清单确认它提供 §4 的 12 项能力（OpenSSL 的第三方 QUIC TLS 接口
`SSL_set_quic_tls_cbs` 等），再接入。以下为此前的候选分析，保留作记录：

**TLS 的来源（原建议）**：neton-io 已把 TLS 移出（neton-io SPEC §21、§28.1）。候选：
- (a) 自研 Kotlin TLS 1.3，密码原语用 libcrypto（neton-io SPEC §18.5 评估过）。
- (b) OpenSSL 3.5+ 为第三方 QUIC 协议栈提供的 TLS 接口（`SSL_set_quic_tls_cbs`，https://docs.openssl.org/3.5/man3/SSL_set_quic_tls_cbs/）。
- (c) BoringSSL 的 QUIC API。

建议**先做 (b) 的可行性验证**，再决定：
- 五个平台（Linux / macOS / iOS / Android / Windows）上 OpenSSL 3.5+ 的构建与链接方式（静态链接的体积、neton-io SPEC §18.5 中 native-builds 的可用版本）。
- 回调契约与 §4 的 12 项能力一一对应：阶段密钥的导出、传输参数扩展、0-RTT、密钥更新、Retry 标签。
- 与 quinn 完成一次真实握手互通。
- 验证结论写入本节，之后才推进完整握手、0-RTT、密钥更新。

**关于参考中的"无保护"实现**（`$R/perf/src/noprotection.rs`）：它内部**仍持有真实的 rustls 会话**，握手、证书、密钥导出都照常由 rustls 完成，只是
关掉包加密。所以它不能替代 TLS 前置依赖（草案 v0 的"TLS 选定之前先用无保护实现推进其余部分"说法**撤回**）。本库的做法：
- 测试替身：只为单元测试提供一个确定性的"模拟握手会话"（双方交换固定的握手字节、派生测试密钥），用于测试帧、流、流量控制、丢包检测等**与 TLS
  无关的局部状态机**。
- 这个替身只存在于测试代码中，**不进入任何可用配置**。
- 握手、证书、0-RTT、密钥更新、Retry 等**依赖 TLS 的能力，只以真实 TLS 验收**。

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
| **计时精度**：1 ms 计时粒度（`TIMER_GRANULARITY`），pacing 需要亚毫秒级 | 反应器有两套计时：10 ms 的计时轮（只给流超时）与按截止时间的最小堆（纳秒记录，`delay` / `withTimeout` 走它，`Reactor.kt:159`）；等待时把截止时间向上取整到毫秒作为轮询超时（`nextTimerMillis`，epoll_wait 只收毫秒） | **先审计**：公开的计时接口、轮询超时的实际精度（epoll_wait 毫秒 / epoll_pwait2 纳秒 / io_uring TIMEOUT 纳秒 / kqueue 纳秒）、实际调度延迟（测量 `delay` 的迟到分布）；再决定是否需要补（如 epoll_pwait2 或 timerfd），不另造计时器 |
| 单调时钟与系统时间 | 反应器有单调时钟 | 公开为 API |
| 加密安全的随机数 | 无 | 与 `websocket` 同一问题，评估是否移入公共模块 |
| 密码原语（AEAD、HKDF、HMAC、头部保护） | 无 | 随 §4 的 TLS 决定一起提供 |

## 10. 实施顺序（在 `http` 首版、`websocket`、HTTP/2 之后；前置：neton-io 数据报层 SPEC 通过、§4 TLS 决定）

0. TLS 可行性验证（§4，建议 OpenSSL 3.5+），结论写入 §4；与此并行做 neton-io 计时审计（§9）。
1. varint、帧、包、传输参数编解码 + 对应的模块内测试与模糊测试。
2. 加密抽象 + 测试替身（仅测试代码，§4）；双端模拟框架（虚拟时间）；与 TLS 无关的状态机部分。
3. 流、流量控制、数据报。
4. 丢包检测、拥塞控制（NewReno、Cubic、BBR 实验性）、pacing、ACK 策略、ACK Frequency。
5. DPLPMTUD、GSO 批量、ECN。
6. 迁移、密钥更新、0-RTT、Retry、令牌、版本协商、无状态重置。
7. 真实 TLS 接入（§4），完整握手、证书与 ALPN、0-RTT、密钥更新、Retry 以真实 TLS 验收；与 quinn 互通。
8. 协程驱动与 API（neton-io 数据报层）；真实套接字测试。
9. quic-interop-runner；性能对照。

每一步单独验证、单独提交，结果记入本 SPEC。

## 11. 实施记录

### 11.1 步骤 1：编解码基础（2026-09-28）
- 代码（`neton.quic.proto`）：`VarInt`、`Coding`、`Shared`（常量、`Side`、`Dir`、`StreamId`、`ConnectionId`、`ResetToken`、`IssuedCid`）、`TransportError`、`Crypto`（`HeaderKey` / `PacketKey` / `HmacKey` / `HandshakeTokenKey` / `AeadKey` 接口与 `HeaderProtection` 的包布局）、`Frame`、`Packet`、`RangeSet`、`TransportParameters`、`CidGenerator`、`Token`。
- 测试：109 个，macosArm64 全过；linuxX64、mingwX64、androidNativeArm32 编译通过。
  - 参考模块内测试：frame 3、packet 4、btree_range_set 7、range_set 13（对两种集合各跑一遍）、transport_parameters 8、cid_generator 1、token 3，全部移植。
  - `headerEncoding`：参考比较真实 Initial 密钥下的密文；此处先校验未保护的头部字节、长度字段与解码路径，头部保护以 RFC 9001 附录 A 的三个例子单独校验。真实 Initial 密钥接入后（步骤 2，openssl-kotlin 已提供 AEAD / 头部保护 / HKDF-Expand-Label）补全为参考原样。
  - `token.rs` 3 个：暂用测试内的非密码替身密钥，只验证令牌格式；步骤 2 换成 HKDF-SHA256 + AES-256-GCM（openssl-kotlin）后按参考原样验证。
  - 另加：各帧类型、各包头类型的往返；合并包拆分；固定位 GREASE；全部解码错误路径；各包空间的帧规则（参考在 `connection/mod.rs:2715-2733、2786-2793`，此处为 `Frame.handshakeSpaceViolation()` / `zeroRttViolation()`）；RFC 9000 A.1 / A.2 / A.3 例子；FxHash 值（rustc-hash 2.1.3 生成）。
  - 模糊测试的 4 个目标尚未建立（与步骤 2 一起补）。
- 与 quinn 的差异：
  - `RangeSet`：Kotlin common 没有 `BTreeMap`，改为有序 `LongArray` + 二分查找（插入 / 删除 O(n)、无分配）；行为以对照参考集合的穷举测试保证一致。
  - 解码从 `ByteArray` + 游标读取（neton-io `Bytes` 不公开底层数组）。
  - 错误用异常而非 `Result`；`UnexpectedEnd` 为共享单例，坏包不分配。
  - `ConnectionIdGenerator.validate` 返回 `Boolean`；令牌中的墙钟时间为自 Unix 纪元的 `Duration`；128 位随机数为小的 `U128` 类。
  - 连接 ID 默认用 `secureRandom`；传输参数用注入的 `Random`（同参考用端点的可设种子的生成器）。
  - `EcnCodepoint`、`SocketAddress` 复用 neton-io。
- §4 可行性的进展：openssl-kotlin 4.0.2 已提供 AEAD（AES-128/256-GCM、ChaCha20-Poly1305，原地）、头部保护掩码（AES / ChaCha20）、摘要、HMAC、HKDF（含 Expand-Label）、常量时间比较，覆盖 §4 第 2（Initial 部分）、3、4、10、11、12 项；
  第 1、2（阶段密钥导出）、5–9 项需要 OpenSSL 的第三方 QUIC TLS 接口（`SSL_set_quic_tls_cbs`、`SSL_set_quic_tls_transport_params`、`SSL_set_quic_tls_early_data_enabled`），已列为对 openssl-kotlin 的封装请求。

### 11.2 步骤 2（部分）：加密层（2026-09-28）
- 代码：`nativeMain` 的 `PacketProtection.kt`（三个 TLS 1.3 套件、Initial 密钥（v1 与 draft 的 salt）、包密钥与头部密钥、"quic ku" 密钥更新与预先计算的下一代、Retry 完整性标签与校验）、`TokenKeys.kt`（HMAC-SHA256 重置令牌密钥、HKDF-SHA256 → AES-256-GCM 令牌密钥），全部基于 openssl-kotlin 4.0.2；`Crypto.kt` 增加 `KeyPair`、`Keys`、`UnsupportedVersion`。
- 目标平台随 openssl-kotlin 收窄：去掉 androidNativeArm32、androidNativeX86。
- 测试：131 个全过。`headerEncoding` 与 `token.rs` 3 个改为参考原样（真实密钥、逐字节密文）；RFC 9001 附录 A.1–A.5 与 draft-29 向量、各套件密钥更新、限额、解密失败、HMAC（RFC 4231）、HKDF（RFC 5869）共 18 个；quinn `fuzz/` 的 packet、params、streamid 三个目标（各 2 万 / 10 万个带种子的输入）另加 frames，未发现缺陷；streams 目标待流状态机。
- 与 quinn 的差异 ⚖️：openssl-kotlin 的句柄没有终结器，每个密钥登记 `Cleaner` 在回收时关闭（参考靠 drop）；附加数据需整个数组，头部复制进四个复用缓冲之一（稳定状态不分配）；ChaCha20 机密性上限取 `Long.MAX_VALUE`（参考 `u64::MAX`，都不可达）；Initial 套件固定为 TLS13_AES_128_GCM_SHA256；解密失败抛共享的 `CryptoError` 单例。
- 热路径待测：openssl-kotlin 每次 seal / open / mask 内部 `usePinned`，可能每次调用分配一个小对象；以 callgrind 实测后再决定是否请求 openssl-kotlin 提供预先固定的接口。
- `connection/packet_crypto.rs`（依赖包空间）随连接层移植。
- 顺带修正：common 中的值类去掉 `@JvmInline`（本模块只有原生目标，共享元数据编译拒绝该可选期望注解），`compileCommonMainKotlinMetadata` 通过。

### 11.3 步骤 3：流、流量控制、数据报（2026-09-28）
- 代码（`neton.quic.proto`）：`Assembler`、`SendBuffer`、`StreamsSend`、`StreamsRecv`、`StreamsState`、`Streams`（`SendStream` / `RecvStream` / `Chunks` / 事件与错误类型）、`Retransmits`（含 `ThinRetransmits`、`FrameStats`、`StreamReset`）、`Datagrams`、`CidQueue`、`CidState`、`Collections`（`LongMap` / `LongHashSet` / `LongList`）、`Instant`；`Frame.kt` 增加不创建 `StreamMeta` 的 `encodeStreamHeader`，`RangeSet` 增加 `removeMin` 与无分配的 `replaceEach`。
- 测试：229 个（此前 131 + 98）全过；linuxX64、mingwX64、androidNativeArm32 编译通过。assembler 26、send_buffer 7、streams/send 2、streams/recv 1、streams/state 24、datagrams 5、cid_queue 11 全部移植；另加：assembler 的堆对照有序列表模型与随机重组、控制帧经 `FrameIter` 解回、`maxSize` 上限、跨多次写出带 FIN 的 STREAM 帧与重传、替代数据结构对照参考模型、数据报收发路径。
- 保留的 quinn 行为：`Chunks` 在检查读取顺序前从映射中取出流状态，非法有序读时该状态被丢弃且不计为释放；部分有序读后改为无序读可能重复交付已读字节（`defragment` 从偏移 0 而不是读位置裁剪），有测试固定该行为。
- ⚖️：`FxHashMap` / `FxHashSet` / `Vec<u64>` 改为基于 `LongArray` 的 `LongMap` / `LongHashSet` / `LongList`（键不装箱，迭代顺序同样未指定）；`BinaryHeap<Buffer>` 改为平行数组的 `ChunkHeap`（逐步照搬 Rust 的 sift / pop / sort，相等块的出队顺序相同）；发送队列的优先级堆用平行数组，最近度按无符号比较；发送缓冲保留首段整体、以 `frontTrimmed` 标记起点；为避免每帧分配，元组返回值拆开（`Recv.ingest` 只返回新字节数，`Recv.stop` 只返回额度，`maxStreamData` + `maxStreamDataShouldTransmit`，`BytesSource` 累加 `chunksConsumed`）；`RecvState` 展平为字段（-1 表示最终大小未知）；会阻塞的结果以密封类返回而非抛出（K/N 抛异常代价为微秒级），误用类错误抛出；`Chunks` 必须显式结束（无析构）；句柄接收 `connClosed` 而不借用连接状态；数据报每个开销固定 32 字节；`StreamEvent` / `Chunk` / `CidQueue.Retired` / `Next` / `StreamReset` 为小对象（已打开流上每个入站 STREAM 帧一个 `StreamEvent.Readable`）；`debug_assert!` 以注释保留（同参考的发布版行为）。
- 向 neton-io 提出：`Bytes` 的区间复制（`copyInto(dst, dstOffset, from, to)`），可省去把存储的写入部分装进包时每个 STREAM 帧一个的小切片对象。

### 11.4 步骤 4–5 的组件：拥塞控制、pacing、RTT、MTU 探测、包空间、ACK（2026-09-28，不含 `connection/mod.rs`）
- 代码（`neton.quic.proto`）：`Congestion`、`NewReno`、`Cubic`、`Bbr`（与 quinn 一样标为实验性）、`Pacing`、`Paths`（`RttEstimator`、`PathData`、
  `PathResponses`、`InFlight`）、`Mtud`、`Spaces`（`PacketSpace`、`SentPacket`、`SentPackets`、`Dedup`、`SendableFrames`、`PendingAcks`、
  `PacketNumberFilter`）、`AckFrequency`、`Timer`、`Stats`、`BloomTokenLog`、`TokenMemoryCache`、`SpinLock`、`TransportConfig`（含
  `AckFrequencyConfig`、`MtuDiscoveryConfig`、`IdleTimeout`）、`Config`（`EndpointConfig`、`ValidationTokenConfig`、`ConfigError`、`TimeSource`）、
  `RustTime`（Rust `Duration` 的精确算术）、`DebugAssert`；`nativeMain` 的 `EndpointConfig.default()` 用随机 HMAC-SHA256 重置密钥。
- 测试：318 个（此前 229 + 89）全过；linuxX64、mingwX64、common 元数据编译通过。mtud 28、spaces 10、bloom_token_log 7、token_memory_cache 3、
  pacing 4、paths 1、cubic 2、bbr/min_max 1、ack_frequency 2 全部移植；另加模型对照（黑洞检测、`Dedup`、`SentPackets`）、与 fastbloom 0.17.0 逐位
  一致的向量、BBR 瓶颈链路模拟、NewReno、配置 / 计时器 / 统计。
- ⚖️：u64 用 `Long`（`u64::MAX` 成为 `Long.MAX_VALUE`，不可达处无差别）、u16 用 `Int` 并在设置时校验范围；热路径的"无"用哨兵值（包号与探测大小
  -1、`Instant.NONE`），可空的 `Instant` / `Int` / `Long` 在 K/N 上每次装箱；已发送包由 `BTreeMap` 改为按包号索引的平行数组环形缓冲（O(1)、无分配；
  乱序插入抛异常，quinn 不会发生），`SentPacket` 为可变记录；`Dedup` 的 u128 为两个 Long；`SendableFrames` 为位标志值类；`detect_ecn` 的结果为枚举；
  MTU 阶段为 `MtudPhase` + 复用的 `SearchState`；令牌日志的集合重现 hashbrown 的扩容点（在相同大小转为布隆过滤器），`TokenMemoryCache` 用按访问
  排序的 `LinkedHashMap`，两者用自旋锁（Kotlin common 没有阻塞互斥）；`debug_assert!` 只在调试二进制中执行；BBR 默认 `Random.Default`，
  `PacketNumberFilter` 注入 `Random`。
- 延后：qlog（§8）；`ServerConfig` / `ClientConfig`（需要 TLS 配置，§4）；由 `TransportConfig` 生成 `TransportParameters`（连接步骤）。

### 11.5 连接状态机与端点（2026-09-28，TLS 以测试替身代替）
- **范围说明（2026-09-28 修订）**：完成的是 mock TLS 下的核心实现，**不是 QUIC 完工**。真实握手、证书验证、密钥切换（握手级别推进、1-RTT 更新）
  与 quinn 的双向互通都未验证，可能暴露状态机问题；这些以真实 TLS 验收（§4、§10 第 7 步）为准。
- 代码：`Connection`（`connection/mod.rs` 全部：握手状态、收包解密、帧处理、丢包检测与 PTO、拥塞 / pacing、ACK、密钥更新、0-RTT、迁移与路径验证、
  CID 管理、无状态重置、空闲超时、关闭 / draining、数据报、流、MTU / ECN / GSO、`pollTransmit` / `handleEvent` / `handleTimeout` / `poll`）、
  `Endpoint`（路由、建连、Retry 与令牌、版本协商、无状态重置、`accept` / `refuse` / `retry` / `ignore`）、`PacketBuilder`、`PacketCrypto`、
  `CryptoSession`（quinn 的 `crypto.rs` 三个 trait）、`Events`、`ServerConfig` / `ClientConfig`。
- 测试替身：`MockTls`（只在 `nativeTest`，生产代码不可达）：固定的握手字节经 CRYPTO 帧交换，密钥用真实的 `PacketProtection` 原语派生，支持传输
  参数、ALPN、0-RTT、密钥更新、导出器。`PairUtil` 移植 `tests/util.rs` 的虚拟时间双端模拟。
- 测试：433 个（此前 318 + 115）连续三次全过，新增测试另连跑 400 次无失败。`tests/mod.rs` 109 → 103、`tests/token.rs` 7 → 7、模块内 1。
  - 待真实 TLS：`reject_self_signed_server_cert`、`reject_missing_client_cert`、`server_alpn_unset`、`client_alpn_unset`、`alpn_mismatch`；另
    `alpn_success`、0-RTT、密钥更新、`export_keying_material`、大证书 / 大 ClientHello 等在替身上通过，接入真实 TLS 后须复验。
  - 不适用：`endpoint_and_connection_impl_send_sync`（Rust 的 Send / Sync 编译期检查）。
  - `cid_rotation` 断言 quinn 实际产生的区间（参考中的 `assert_matches!(x, _bound)` 匹配任何值，已在 Rust 中确认）。
- ⚖️：每包的记录（包构造器、已发送帧、已发送包记录、新确认区间、丢失包列表）为复用字段；1-RTT 头部直接写出；"无"用哨兵；ACK 帧大小先算后写
  （`Buffer` 不能截断）；协议错误为异常；`StreamEvent` 直接是 `Event` 的子类型；随机源为按种子的 `kotlin.random.Random`（与 quinn 的 ChaCha12 序列
  不同）；加密 trait 命名为 `CryptoSession` / `CryptoClientConfig` / `CryptoServerConfig`；本地 IP 用端口 0 的 `SocketAddress`；端点的 CID 映射用
  `HashMap`、slab 复用最近释放的键；未处理的 `Incoming` 没有析构时的警告；配置为可变对象 + `copy()`。
- 驱动层（§3，下一步）所需：每个数据报一个可保留的字节数组（原地解密、零复制交出流数据）；按 `Transmit` 发送（ECN、GSO `segmentSize`、源 IP）；
  事件在端点与连接之间转发；每连接一个单调截止时间（亚毫秒 pacing）；只在套接字保证不分片时开启 MTUD；真实 TLS 实现 `CryptoSession`。

### 11.6 原生密钥的确定性释放（2026-09-28，评审 P1）
- 问题：包保护、头部保护与令牌 AEAD 密钥的 OpenSSL 上下文此前只靠 `createCleaner` 在 GC 时关闭。这不等于 Rust 的 drop：连接关闭、旧密钥淘汰后原生
  资源仍等待 GC，高连接周转或频繁密钥更新时原生内存无界。
- 所有权：每个包空间独占其 `Keys`；1-RTT 头部密钥在密钥更新间由当前 `Keys` 持有（更新只替换包密钥）；`prevCrypto` 独占上一阶段的包密钥、
  `nextCrypto` 独占预先计算的下一阶段包密钥；`zeroRttCrypto` 独占 0-RTT 密钥；`Incoming` 独占端点为首包派生的 Initial 密钥；令牌密钥单次使用。
- 显式释放点：包空间丢弃（`discardSpace`，含 Retry 后重建 Initial）；密钥丢弃计时器（上一阶段与 0-RTT）；新的密钥更新替换仍保留的上一阶段；
  客户端取得 1-RTT 后丢弃 0-RTT；连接进入 Drained（所有路径）时释放全部剩余密钥；端点的 Initial 密钥在 `accept` / `refuse` / `retry` / `ignore`
  之后与 `handle` 的其他每个出口释放（`retry` 抛 `RetryError` 时保留，调用方仍可接受或拒绝）；令牌密钥用后即关。
- 恰好一次：`NativeKeyResource` 以一次比较交换承载释放，显式 `close()` 与兜底的 cleaner 走同一路径，先到者释放、后到者无操作；
  `HeaderKey` / `PacketKey` / `AeadKey` 为 `AutoCloseable`（幂等）。
- 测试（`KeyLifecycleTest`，计数存活的原生上下文）：20 轮建连 + 交替发起的 3 次密钥更新 + 关闭排空后回到基线；10 轮 Retry 后拒绝回到基线；
  显式关闭两次只减一次；不关闭时 cleaner 兜底释放。去掉排空时的释放，测试报告残留 32 个上下文。合计 437 个测试通过。

### 11.7 对 openssl-kotlin 的请求（按批次，2026-09-28）
职责边界：openssl-kotlin 提供 TLS 1.3 握手与密码原语；**传输参数的解释、CRYPTO 帧的重组与重传、连接调度仍归本库**。

**第一批：QUIC TLS 握手接口（不混入 0-RTT）**
- 能力：按加密级别（Initial / Handshake / 1-RTT）输入与输出 CRYPTO 字节；每个级别的读 / 写秘密（带套件）；ALPN；`quic_transport_parameters`
  （0x39）原始字节双向；对端证书链与验证结果；TLS 告警（映射为 QUIC CRYPTO_ERROR 0x100 + alert）。
- 必须同时规定的契约：
  - 输入缓冲何时可复用；回调给出的数据能否被保留（还是只在回调期间有效）。
  - 输出队列的上限、部分消费与背压（输出未取走时握手如何表现）。
  - 回调中的异常不得穿过 C 边界；关闭引擎后不得留下悬空回调。
  - 握手完成后仍能处理 TLS 消息（NewSessionTicket、KeyUpdate 以外的握手后消息）。
  - 与 quinn 双向互通（本库客户端对 quinn 服务端、quinn 客户端对本库服务端），而不只是两个同实现端点互测。
- 0-RTT（早期数据密钥、是否被接受、`max_early_data_size`）另作后续批次，单独验收。

**第二批：现有 TLS 接口的正确性补齐（独立验证）**
- 重试原因区分（WANT_READ / WANT_WRITE）、TLS KeyUpdate 接口、错误队列按连接隔离（含跨连接污染测试）。
- TLS 的 KeyUpdate 与 QUIC 的包密钥更新（"quic ku"，本库自行派生）是不同接口、不同职责，不得合并。

**第三批：预固定缓冲 / 原生指针热路径**
- 先在当前构建中实测"每次调用 pin"的实际分配（pin 不必然等于堆分配），再分别比较安全数组接口与原生指针接口的每包指令数与分配数；
  不得为省 pin 绕过密钥的独占访问与长度约束。

### 11.8 驱动层（quinn 的 `quinn` crate，2026-09-29，TLS 仍为测试替身）
- **范围说明**：完成的是 §3 的协程驱动与 API，运行在真实的回环 UDP 套接字上，但握手用的仍是 `MockTls`（只在 `nativeTest`）。真实 TLS 未接入
  （§4、§11.7 第一批未交付），证书、ALPN、0-RTT、密钥更新在真实 TLS 上都未验收，与 quinn 的互通未做；**QUIC 没有完成**。
- 代码（`nativeMain`，包 `neton.quic`）：`Endpoint`（含 `DriverConfig`、`EndpointStats`）、`Connection`（`Connecting`、`ZeroRttAccepted`、
  每连接的驱动协程 `ConnectionState`）、`Incoming`、`SendStream`、`RecvStream`、`QuicStream`（IoStream 适配）、`Errors`、`Notify`；`commonMain`
  的 `WorkLimiter`（quinn `work_limiter.rs`）。此前的 WIP 提交未经评审，本节为评审与补齐的记录。
- **评审结论（对照 §3 与 quinn 源码逐项核对）**：
  - 核对无误：单反应器——端点、它的 UDP 套接字与全部连接都在创建端点的反应器上，端点的协程是创建者的子协程；接收循环把数据报的
    `ConnectionEvent` 直接放入连接的队列并唤醒其驱动，连接驱动直接调用协议端点处理 `EndpointEvent`，没有通道、没有状态锁。唯一的挂起原语
    `sendLock` 是套接字写满时各连接排队的 FIFO（neton-io 每个 UDP 套接字只允许一个挂起的 `send`），只在反应器线程上使用，不是跨线程锁。
    背压：写在流量控制阻塞时挂起、由 Writable 恢复，读同理。轮转：用完预算的驱动 `yield`，neton-io 反应器的 `dispatch` 把它排到普通任务队列末尾，
    有剩余工作的驱动按 FIFO 轮流执行。§3 API 表的六个类型逐项齐全，无缺项。quinn `tests.rs` 的 21 个测试全部移植（`DriverTest`，3 个压力测试
    与参考一样 `@Ignore`），`many_connections` 移植并随套件运行（参考为 `#[ignore]`），`post_quantum` 取决于 TLS。
  - 发现并修正（每项附原因）：
    1. **接收预算只有时间片**：WIP 只用 quinn 的 `WorkLimiter`（50 µs），没有 §3 的条数上限。增加 `DriverConfig`：`maxDatagramsPerTurn`
       （默认 32 × 5）与 `recvTimeBudget`（默认 50 µs，经 `WorkLimiter`），先到为准；条数按条精确截断，批内未处理的消息留到下一轮最先处理
       （Linux 一批 32 条，上限 8 时一轮在批中间结束，测试覆盖）；用完后 `yield` 排到任务队列末尾。
    2. **发送预算可超出**：quinn 每次 `poll_transmit` 都请求 `max_datagrams` 个分段，一次驱动最多可发 29 个数据报（quinn 同样如此）。改为请求
       min(10, 20 − 本次已发) ⚖️，一次驱动严格不超过 20 个。
    3. **rebind 与阻塞发送**：挂起在旧套接字上的发送，在新套接字收到流量、旧套接字被关闭时抛 `ClosedException`，连接随之以 INTERNAL_ERROR
       终止。改为在新套接字上重试（quinn 的连接收到 `Rebind` 后换套接字重发缓存的 transmit）。
    4. **同方向并发操作使前一个永远挂起**：两个协程同时读一个 `RecvStream`（或读与 `receivedReset` 同时进行）时，后者覆盖前者登记在
       `blockedReaders` 中的续体，前者再也不会被唤醒；写同理。quinn 的 `&mut self` 使这种情况不可能出现。改为第二个操作抛
       `IllegalStateException`（与 neton-io §28.6 的并发规则一致）。
    5. **关闭流时丢弃等待者**：`close` / `stop` 从表中移除等待的续体但不恢复它，另一个协程中挂起的读写永远挂起（quinn 中流被借用时不能被
       drop）。改为恢复它：读看到流已停止（返回 -1，同 quinn 在 `stop` 之后的读），写得到 `WriteError.ClosedStream`。
    6. **未处置的 `Connecting` 泄漏连接**：quinn 丢弃未完成的 `Connecting` 即丢弃最后一个句柄，连接以 0 关闭；WIP 中它没有关闭手段，连接要等空闲
       超时。`Connecting` 改为 `AutoCloseable`。
    7. **端点关闭时持有的 `Incoming` 拒绝得太晚**：WIP 只在端点最终停止（所有连接排空之后）时拒绝，端点仍有连接时对端要等到超时。改为
       `Endpoint.close()` 时立即拒绝；此后 `accept` 返回 `null`，新到的连接尝试被拒绝。
  - ⚖️ 轮次的界定：quinn 每次驱动被唤醒都开始新的 `WorkLimiter` 周期。协程无法在不分配的情况下判断 `UdpSocket.recv` 是否挂起过（neton-io 没有
    不挂起的 `tryRecv`），因此本库的一轮从一次 `yield` 到下一次，`recv` 中途挂起不开始新的一轮，挂起的时间不计入时间片。预算因此是每次唤醒
    工作量的上限；跨越挂起的一轮只会比 quinn 更早让出。
  - ⚖️ 计时器：连接的计时器用反应器的 `Delay.invokeOnTimeout`，精度为毫秒，截止时间向上取整（不早触发），到期判断以时钟为准（同 quinn）。
    pacing 所需的亚毫秒计时仍待 §9 的计时审计。
  - ⚖️ 流不保持连接：quinn 的流也持有连接的引用计数，最后一个句柄（含流）丢弃时连接才关闭；本库 `Connection.close()` 即关闭，读完的流可以不关闭，
    否则引用计数永远归不了零。
- **生命周期（§3，每条规则一个测试，`LifecycleTest` 13 个）**：显式 `close()`（`AutoCloseable`）承载 quinn 的 drop 规则，`use { }` 使取消也执行它们。

  | 规则 | 测试 |
  |---|---|
  | `SendStream.close()` = finish | `sendStreamCloseFinishes`（对端读到数据后 EOF，未发 RESET_STREAM）；`sendStreamUseFinishesOnCancellation`（`use` 中被取消） |
  | 已被对端 stop 的 `SendStream.close()` = 以对端的码 reset | `sendStreamCloseAfterStopResets`（STOP_SENDING(7) 后关闭，发出 RESET_STREAM） |
  | 未读完的 `RecvStream.close()` = stop(0) | `recvStreamCloseBeforeEndStops`（对端 `stopped()` 得到 0）；反例 `recvStreamCloseAfterEndDoesNotStop` |
  | `Connection.close()` = 以 0 关闭 | `connectionCloseUsesCode0`（对端得到 ApplicationClosed(0, "")）；`connectionUseClosesOnCancellation`；反例 `connectionCloseKeepsAnEarlierReason` |
  | 未交出连接的 `Connecting.close()` = 以 0 关闭 | `connectingCloseClosesConnection`（握手中的应用关闭按 RFC 9000 §10.2.3 以 APPLICATION_ERROR 送达，客户端端点随后空闲） |
  | `Incoming.close()` = refuse | `incomingCloseRefuses`（CONNECTION_REFUSED） |
  | 端点关闭时未处置的 `Incoming` 被拒绝 | `incomingHeldIsRefusedWhenEndpointCloses`；`incomingHeldIsRefusedWhenEndpointClosesWithLiveConnections`（去掉修正 7 即超时失败）；`endpointRefusesNewAttemptsOnceClosed` |

  - 从未交给 `accept` 的排队尝试在端点停止时忽略（同 quinn `State::drop`）。未覆盖：端点所在的作用域被**取消**时，连接驱动随之取消，不再发出
    CONNECTION_CLOSE（对端等空闲超时）；有序关闭须先 `close` 再 `waitIdle`。
- **流作为 IoStream（`QuicStream`）**：一对 `SendStream` / `RecvStream` 实现 neton-io `IoStream`：`read` 从 `RecvStream` 直接读入 `dst` 的底层数组
  （追加，finish 后 -1），`write` 写完 `src` 的全部字节（流复制数据，返回即可复用；按接受量推进），`flush` 无操作（同 quinn `poll_flush`），
  `shutdownOutput` = finish，`close` = 生命周期规则（不关闭连接）。能力声明 `HalfClose`、`ResumableAfterCancel`；不声明超时与 `AnyThread`
  （流属于端点的反应器）。错误为 `QuicStreamException`（`IoException`，携带原始流错误；对端 reset 不是 EOF），关闭时挂起的操作得到
  `ClosedException`。另有 `Connection.openBiStream()` / `acceptBiStream()`。测试（`QuicStreamTest` 5 个）：neton-io `io-testkit` 的
  `IoStreamConformance` 全部必选项与按能力的可选项（含对端 reset 钩子；把能力改为错误声明时套件报告失败，确认它确实在检查）、`Framed` +
  `LineCodec` 的 200 行回显、对端 reset、关闭规则。单向流未提供 IoStream 形式。
- **预算的验证（`DriverBudgetTest` 6 个）**：2000 个垃圾数据报分 20 次突发、上限设为 8：每轮最多 8 条，250–260 次让出，同时运行的另一协程
  得到约 3 万次执行；4 MiB 批量传输：每次驱动最多 20 个数据报、每次发送最多 10 个分段（Linux GSO；macOS 无 GSO 为 1），Linux 145 次、
  macOS 42 次因发送预算让出；并发读 / 写抛 `IllegalStateException`；关闭恢复挂起的读 / 写。
- **公平性测试（§3 "测试"，`FairnessTest`）**：服务端点、重连接的客户端点、轻连接的客户端点全在同一个反应器上。重连接持续双向满速收发
  （只受流量控制与拥塞控制限制），预热到 16 MiB 后，20 条轻连接每隔 20 ms 到达，各做一次握手与 20 次 32 字节请求 / 应答（间隔 5 ms）。
  断言：握手最大 ≤ 500 ms，请求 p99 ≤ 250 ms、最大 ≤ 500 ms，轻阶段内重连接至少传输 4 MiB（证明负载与轻连接同时存在）。另有无重连接的基线
  （只打印）。测得（debug 测试二进制）：

  | 环境 | 握手 p50 / 最大 | 请求 p50 / p99 / 最大 | 重连接在轻阶段 | 基线请求 p99 |
  |---|---|---|---|---|
  | macOS arm64（约 20 次） | 31–82 / 64–122 ms | 32–66 / 60–113 / ≤ 124 ms | 18–32 MiB / 1.5–2.2 s | 2–11 ms |
  | colima Linux arm64，2 vCPU，epoll 与 io_uring（各 6 次） | 9–13 / 14–17 ms | 11–13 / 16–18 / ≤ 20 ms | 12 MiB / 0.74 s | 3–4 ms |

  - 构成：轻连接的数据报与重连接的在途数据（受其流窗口 1.25 MB 约束）排在服务端套接字的同一个接收队列里，按到达顺序处理，所以负载下的延迟约为
    处理一个窗口所需的时间，是共享队列的排队，不是调度饥饿。上限取实测值的 4–5 倍，低于丢失一个 Initial 后恢复所需的约 1 s（初始 RTT 333 ms），
    所以饥饿（等到重连接结束）或需要丢包恢复的握手都会失败。测试中服务端的接受循环最初逐个等待握手完成，把握手串行化（握手 p50 约 400 ms），
    改为每个握手一个协程后降到上表数值——这是测试本身的问题，已在提交前修正。
  - 消融（去掉两项预算：条数与时间片无限、每次驱动不限数据报）：macOS 上结果不变（请求 p99 85–86 ms）；Linux 上请求 p50 15–16 ms、p99 19 ms，
    比有预算时略差（11–13 / 16–18 ms）。即在本测试的负载下（单个重连接，受流窗口约束，没有单个任务长时间占用线程），延迟由共享接收队列决定，
    预算的作用有限；预算防止的是单个任务无界地处理积压（接收积压、大量可发数据），由 `DriverBudgetTest` 直接验证。此测试只有 400 个请求样本，
    p99 是粗略值；neton-io §28.4 规程的 F 类测量（153、样本 ≥ 10 万、独立负载发生器）尚未进行（153 当前不可达）。
- **测试**：490 个（此前 464 + 26：`DriverBudgetTest` 6、`LifecycleTest` 13、`QuicStreamTest` 5、`FairnessTest` 2），macosArm64 487 通过、3 个跳过
  （quinn 的 3 个压力测试）；colima Linux arm64 虚拟机（Ubuntu 24.04）上 `NETON_IO_DRIVER=epoll` 与 `iouring` 各 490 个、487 通过、3 个跳过。
  新增的计时相关测试（预算、公平性、生命周期、IoStream、`DriverTest`）在 macOS 上各连跑 3–15 次、在虚拟机两种驱动上各 5 次，无失败。
  首次在 Linux 上运行时，接收预算测试一次发出 1000 个小数据报，超过 Linux 默认接收缓冲（只到达 222 个），改为分批突发。
- **仍未完成**：真实 TLS（§4）及其上的握手、证书、ALPN、0-RTT、密钥更新、Retry 验收与 quinn 互通；多核（§3，首版不做）；亚毫秒计时（§9）；
  作用域取消时的有序关闭；单向流的 IoStream 形式；按 neton-io §28.4 规程的公平性与性能测量（§6，需 153）；驱动层热路径的分配与指令数
  （callgrind，§7）未测。
- 153（linux x64，2026-09-29 恢复可达后）：epoll 与 io_uring 各 490 个测试（3 个与 quinn 一致地忽略）全过。该次运行（io_uring）的公平性测试：
  重载下握手 p50 26 / 最大 33 ms、请求 p50 21 / p99 33 / 最大 33 ms（400 个请求，重载连接 1,010 ms 传 10 MiB）；无重载基线握手最大 4 ms、
  请求 p99 6 ms。预算测试：每轮至多 8 个（上限 8）、每次驱动至多 20 个数据报、每次发送至多 10 个分段。重载下的延迟仍是共享接收队列中的排队，
  不是某个连接被饿死；按 neton-io §28.4 规程的正式负载对照尚未做。
- `quic-testkit`（2026-09-29）：TLS 测试替身 `MockTls` 移入独立的仅测试产物 `com.netonstream:quic-testkit`（包 `neton.quic.testkit`），
  供本库与其上的协议（http3）的测试使用，生产代码不得依赖；`expandLabel` / `packetKey` / `headerKey` 公开为 `CryptoSession` 实现的构件
  （真实 TLS 会话同样需要）。quic 与 quic-testkit 配置 `maven-publish` 以供本地消费。153 上两种驱动各 490 个测试全过。
- 公平性测试对宿主负载敏感：本机负载平均值约 200（其他编译任务并行）时请求 p99 达 290–335 ms，超出 250 ms 上限；空闲的 153 上稳定通过。
  该测试应在空闲机器上运行判定。
- 写入的协作让出（2026-09-29，HTTP/3 阶段 C 发现）：一直有流量控制额度的写入协程从不挂起，它唤醒的连接驱动得不到运行——期间不发包、不处理
  收到的包，对端的 STOP_SENDING 要等整个流窗口（约 1.25 MB）用完才被察觉（153 上 9–17 s）。改为照 quinn 所依赖的 tokio 协作预算：连续
  32 次未挂起的写入后 `yield` 一次，因阻塞挂起时清零。回归测试 `WriteCoopTest`：6 字节小写循环，对端收到首批字节即停止；去掉修复时写满
  1,249,998 字节才停止，修复后远低于 256 KiB。macOS 与 153 两种驱动各 491 个测试全过。

### 11.9 真实 TLS 会话（OpenSSL 第三方 QUIC TLS 接口，2026-09-29）
- **决定**（§4，所有者决定 2026-09-29）：TLS 会话在本库实现，建在 openssl-kotlin 4.0.2 的原始绑定（`neton.openssl.c`）上；§11.7 第一批
  请求的安全门面由本库按同样的契约实现，openssl-kotlin 未作任何修改。
- **代码**（`nativeMain`，包 `neton.quic.proto`）：`TlsSession`（quinn `crypto::rustls::TlsSession`）、`TlsClientConfig` /
  `TlsServerConfig`（quinn `QuicClientConfig` / `QuicServerConfig` 与 `with_root_certificates` / `with_single_cert`）、`Certificates`
  （DER / PEM）、`PrivateKey`（DER / PEM，拒绝加密私钥而不是提示输入口令）、`ClientAuth`（`None` / `Request` / `Require`）、
  `TlsHandshakeData`、`NativeTls`（原生对象计数与错误队列清理）；`SSL_ctrl` 的 C `long` 在各目标宽度不同，SNI 设置放在
  `appleMain` / `linuxMain` / `androidNativeMain` / `mingwMain` 的 `actual` 中。`CryptoSession` 新增 `close()` 与释放契约的 KDoc。
- **状态机（对照 quinn `crypto/rustls.rs`）**：
  - `readHandshake`：字节入队，驱动 `SSL_do_handshake`（握手完成后为 0 字节的 `SSL_read`，处理 NewSessionTicket 等握手后消息）直到 OpenSSL
    要求更多输入；"握手数据可用"沿用 quinn 对 rustls 的判定（ALPN 已定、服务端见到 SNI、或握手结束），只在第一次返回 `true`。
  - `writeHandshake`：先交出连接当前所在级别的字节，再在下一级别的读、写两个秘密都已产出时交出该级别的 `Keys`（rustls `write_hs` 的
    `KeyChange`）。发送字节按 OpenSSL 当时的写级别分级缓存，因此两个方向秘密的产出顺序不影响结果。
  - ⚖️ OpenSSL 为 QUIC 先设写密钥后设读密钥：服务端的 1-RTT 读秘密在收到客户端 Finished 之后才产出，所以服务端在那时才得到 1-RTT 密钥
    （rustls 在服务端发完首个飞行后即给出），服务端不发送 0.5-RTT 数据。quinn 的状态机两种顺序都能处理（HANDSHAKE_DONE 排在密钥之后），
    内存测试中逐级断言了两端的顺序。
  - 密钥：握手 / 1-RTT 的包与头部密钥由产出的秘密经已有的 `Secrets`（`expandLabel` / `packetKey` / `headerKey`）按协商的套件派生
    （AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305；CCM 不开放，同 rustls）；Initial 密钥与 Retry 标签不变；`next1rttKeys` 用应用秘密的
    "quic ku"，与 quinn 相同。套件由 `SSL_get_pending_cipher` 的协议号确定，秘密长度与套件哈希长度不符即失败。
  - 错误：告警 → CRYPTO_ERROR 0x100 + alert；没有告警的失败 → PROTOCOL_VIOLATION（同 quinn）；回调记录的失败优先（见下）。失败后会话
    保持失败状态，再次调用抛同一个错误。客户端提供了 ALPN 而服务端未选 → no_application_protocol（120），同 rustls 的 QUIC 规则；
    服务端有 ALPN 而客户端未提供（ClientHello 回调）或无共同协议（ALPN 选择回调）→ 120。
  - 0-RTT 不在本批：`earlyCrypto()` 为 `null`，`earlyDataAccepted()` 客户端为 `false`、服务端为 `null`；票据、会话恢复与早期数据均关闭
    （`SSL_OP_NO_TICKET`、`num_tickets = 0`、`max_early_data = 0`、`SSL_set_quic_tls_early_data_enabled(0)`）。
- **契约与测试**（`TlsSessionTest` 为两个会话在内存中直接对话，不经 QUIC）：

  | 契约 | 实现 | 测试 |
  |---|---|---|
  | C 边界：`staticCFunction` + StableRef，异常不穿过 C | 六个 QUIC TLS 回调与 ALPN 选择、ClientHello 两个 SSL_CTX 回调都经同一个 `callback` 包装：捕获全部 `Throwable`，记录第一个失败并返回 0（或对应的告警），OpenSSL 调用返回后抛出（非 `TransportError` 转为 INTERNAL_ERROR，保留原消息）；已释放的会话拒绝执行 | `aFailingCallbackNeitherCrashesNorLeaks`：对 8 个回调逐一注入异常，进程不崩溃，得到带注入消息的 INTERNAL_ERROR，SSL / StableRef 计数回到基线 |
  | 记录缓冲在 RELEASE_RCD 之前有效且不变 | CRYPTO_RECV_RCD 交出的是原生副本（至多 16 KiB，一次只有一个），RELEASE_RCD 释放；部分释放时其余部分保持不动 | `recordStaysPinnedUntilReleasedAndQueuesAreBounded`（直接驱动回调核心：新数据到达不改动已交出的记录、第二个记录被拒、部分释放、越界释放被拒） |
  | 有界队列 | 收到而 OpenSSL 未取的 CRYPTO 字节每级别至多 64 KiB，超出 → CRYPTO_BUFFER_EXCEEDED；读级别切换时仍有未取字节 → unexpected_message（10）；待 `writeHandshake` 取走的发送字节至多 1 MiB，超出 → INTERNAL_ERROR（连接每次调用后都取走，只有异常的自身证书链可能触及） | `tooMuchUntakenCryptoDataIsCryptoBufferExceeded`、`dataAfterAKeyChangeIsUnexpectedMessage`、上一项 |
  | 传输参数字节被复制 | 对端参数在回调中复制；本端参数复制进原生内存，保留到 SSL 释放之后（OpenSSL 持有该指针直到发送） | `transportParametersAreExchangedAsRawBytes`、`serverKnowsClientParametersAfterClientHello` |
  | 所有权与释放 | 会话独占 SSL、StableRef 与原生缓冲；`close()` 恰好一次（与 cleaner 共用一次比较交换）：先标记核心已释放，再 `SSL_free`（此后不可能再有回调），再 dispose StableRef，再释放缓冲并擦除秘密；创建途中任何失败都走同一释放；配置独占一个 SSL_CTX 引用，`close()` 释放，每个 SSL 持有自己的引用（OpenSSL 计数），所以配置关闭后已开始的会话照常工作；关闭的配置不能再开始会话 | `closeReleasesExactlyOnceAndIsIdempotent`、`manyHandshakesSucceedingAndFailingReturnToBaseline`（30 轮，其中三分之二失败，每轮在握手前关闭配置）、`aClosedConfigurationStartsNoSession`、`invalidServerNameIsAConnectError`（SSL 已建后的失败也回到基线）、`theCleanerIsOnlyABackstopForSessions` |
  | 接入连接的释放点（§11.6） | `Connection.releaseKeys()`（进入 Drained 的所有路径）同时关闭会话；端点丢弃首包失败的服务端连接时释放其密钥与会话（此前该路径的 Initial 密钥也未释放，一并修正）；`connect` / `accept` 中会话已开始但连接未建成时关闭会话 | `RealTlsConnectionTest.manyConnectionsWithKeyUpdatesReleaseSessionsAndKeys`（20 轮建连 + 3 次交替密钥更新 + 关闭）、`failedHandshakesReleaseSessionsAndKeys`（ALPN 不符、缺客户端证书、不受信任的服务端证书、客户端无 ALPN）、`RealTlsDriverTest.manyConnectCloseCyclesReturnToBaseline`（40 次 UDP 建连 / 关闭）、`echoManyStreamsWithKeyUpdatesAndClose`：SSL、StableRef、原生密钥均回到基线 |
  | 证书验证 | 客户端必须显式给出信任锚（PEM / DER），没有隐式的系统信任库；DNS 名以 `SSL_set1_dnsname`（禁止部分通配、不看 CN）验证并作为 SNI 发送，IP 地址以 `SSL_set1_ipaddr` 验证 IP SAN、不发 SNI；非法名 → `ConnectError.InvalidServerName` | `untrustedCaIsUnknownCa`（48）、`selfSignedServerNotTrustedIsUnknownCa`（48）、`hostnameMismatchFailsVerification`（42）、`expiredServerCertificate`（45）、`ipAddressServerNamesUseIpSans`、`trustedSelfSignedServer`、`peerIdentityIsTheServerChain` |
  | 客户端认证 | `ClientAuth.Request` / `Require` 以给定 CA 验证；缺证书为 certificate_required（116） | `clientAuthRequiredAndPresented`、`clientAuthRequiredButMissingIsCertificateRequired`、`clientAuthRequestedIsOptional`、`clientCertificateFromAnotherCaIsRejected`（48） |
  | 无不安全默认 | 只有 TLS 1.3；只有三个 QUIC 套件；无信任锚的客户端只能用 `TlsClientConfig.dangerousNoServerVerificationForTestsOnly(...)`（KDoc 注明不得用于生产） | `clientWithoutTrustAnchorsNeedsTheLoudTestOnlyMode` |
  | 错误队列隔离 | 每次 OpenSSL 调用前清空本线程的错误队列，调用后取尽并清空，错误只进入本次调用的异常消息 | `staleOpenSslErrorsDoNotLeakIntoAHandshake`（预先塞入无关错误，握手照常成功；失败的握手之后队列为空） |
  | 密钥、导出器、套件 | 见上 | `fullHandshakeLevelsAndKeysInOrder`（两端各为 Initial 字节 → 握手密钥 → 握手字节 → 1-RTT 密钥，握手与 1-RTT 的包 / 头部密钥双向一致）、`next1rttKeysAgreeAcrossUpdates`、`exporterMatchesOnBothSides`（含超长输出被拒）、`exporterFailsBeforeTheHandshakeAndAfterClose`、`eachCipherSuite`、`alpnServerPreferenceAndHandshakeData`、`alpnMismatchIsNoApplicationProtocol`、`alpnOnlyOnOneSideIsNoApplicationProtocol`、`largeClientHelloAndLargeCertificate`、`garbageIsATlsAlert`、`afterAFailureTheSessionKeepsFailing` |

- **quinn 的测试在真实 TLS 上**（`RealTlsConnectionTest`，经 `PairUtil` 的双端模拟，22 个）：此前等待真实 TLS 的 `reject_self_signed_server_cert`
  （UnknownCA 0x130）、`reject_missing_client_cert`（客户端先 Connected，随即收到 0x174）、`server_alpn_unset`、`client_alpn_unset`、`alpn_mismatch`
  （均为 0x178）全部通过；复验 `alpn_success`、`lifecycle`、`draft_version_compat`、`export_keying_material`、`key_update_simple`、
  `key_update_reordered`、`large_initial`、`handshake_anti_deadlock_probe`、`server_can_send_3_inital_packets`，另加双方交替 12 次密钥更新、
  Retry 后握手、每个套件传 100 KB、`X25519` 下 ClientHello 为一个数据报、验证过的客户端证书。
  - ⚖️ OpenSSL 默认的 ClientHello 带 X25519MLKEM768（后量子混合）与 X25519 两个密钥份额，约 1.5 KB，占两个 Initial 数据报（quinn 测试中
    rustls 的 ring 提供者只发 X25519，一个数据报）。`server_can_send_3_inital_packets` 因此断言服务端首个飞行为客户端数据报数的 3 倍
    （6 个）。配置新增 `groups`（OpenSSL 的列表语法），默认保留 OpenSSL 的选择。
- **测试框架的切换**：`TestTls`（`nativeTest`）在进程内生成测试 CA（`quic-testkit` 的 `TestPki`：OpenSSL X509 API、ECDSA P-256，仅测试产物）
  及其签发的 localhost / 127.0.0.1 / ::1 服务端证书；`PairUtil` 与 `DriverTestUtil` 的默认配置按 `NETON_QUIC_TEST_TLS`（默认 mock，`real`
  为真实 TLS）选择，专门的真实 TLS 测试显式使用真实会话。整个套件以 `real` 运行（macOS）：555 个中 541 通过、3 个跳过、11 个失败，均已
  逐一归因：0-RTT 5 个（本批不含）；替身专用 3 个（`alpnSuccess` 强转 `MockHandshakeData`，另两个用 `MockServerCrypto` 的大证书服务端配默认
  客户端，真实版本在 `RealTlsConnectionTest`）；ClientHello 占两个数据报导致按 `Incoming` 计数的 3 个（`validateThenRejectManually`、
  `refusedAndRetriedAttemptsReleaseTheirInitialKeys`、`useTokenThenRetry`，以 `NETON_QUIC_TEST_TLS_GROUPS=X25519` 运行即通过）。此后全部清零，见 §11.11。
- **驱动层端到端**（`RealTlsDriverTest`，回环 UDP，6 个）：32 条双向流各约 48 KiB 的回显、期间强制 4 次密钥更新、之后再传一条流、以 7 关闭
  并由服务端看到 ApplicationClosed(7)；以 IP 地址连接；不受信任的服务端 → Transport(0x130)；ALPN 不符 → ConnectionClosed(0x178)；
  客户端认证；40 次建连 / 关闭后原生对象回到基线。
- **与 quinn 双向互通**（quinn 0.11.12 / quinn-proto 0.11.18，rustls 0.23 ring 提供者，TLS 1.3，ALPN `neton-interop`；证书由 openssl 命令
  行生成的一次性测试 CA 签发，双方显式信任该 CA）。quinn 端源码与脚本在 `interop/quinn-peer`（`gen-certs.sh`、`run-interop.sh`，在 153 上
  位于 `/root/bench/quic-interop/`）；本库一端是 `InteropTest`（`NETON_QUIC_INTEROP=server|client`，未设置时不执行，不进入生产产物）。
  每条流回显后服务端强制一次密钥更新，客户端在停顿 200 ms（等上一阶段按 3 PTO 丢弃）后再强制一次；quinn 端以
  `RUST_LOG=quinn_proto::connection=trace` 统计 "executing key update"，本库端统计密钥阶段切换（区分对端发起）。
  - 命令（153 与本机相同）：`cd /root/bench/quic-interop && ./gen-certs.sh && cargo build --release &&
    ./run-interop.sh /root/pulsekit/quic-tls/quic/build/bin/linuxX64/debugTest/test.kexe 24433`。
  - 结果：见下表（macOS 本机与 153 各一次）。

  | 情形 | macOS arm64（本机） | 153 Linux x64（Rocky 9.8，epoll 驱动） |
  |---|---|---|
  | 1. 本库客户端 → quinn 服务端：8 条流共 827,916 字节回显一致，以 0x42 关闭 | 通过；本库 16 次密钥阶段切换（8 次由 quinn 发起），quinn 记录 16 次；丢包 0；quinn 看到 "closed by peer: done (code 66)" | 通过；16 次（8 次由 quinn 发起），quinn 16 次；丢包 0；quinn 看到 code 66 关闭 |
  | 2. quinn 客户端 → 本库服务端：同上 | 通过；本库 15 次（8 次由 quinn 发起），quinn 15 次；丢包 0；本库看到 ApplicationClosed(0x42) | 通过；16 次（8 次由 quinn 发起），quinn 16 次；丢包 0；ApplicationClosed(0x42) |
  | 3a. 只信任另一 CA 的 quinn 客户端 → 本库服务端 | quinn：error 48 UnknownIssuer；本库服务端记录握手失败（ConnectionClosed 0x130）后继续服务 | 相同 |
  | 3b. ALPN 为 other-alpn 的 quinn 客户端 → 本库服务端 | quinn：aborted by peer, error 120 no application protocol；本库：Transport(0x178) | 相同 |
  | 3c. 之后正常的 quinn 客户端 → 同一本库服务端 | 通过（2 条流，4 次切换，2 次由 quinn 发起） | 相同 |
  | 4. 只信任另一 CA 的本库客户端 → quinn 服务端 | 本库：Transport(0x130, certificate verify failed)；quinn：aborted by peer, error 48 | 相同 |

  - 密钥更新的安排：服务端读完一条流后等 300 ms、强制更新、再在新阶段发回回显；客户端收到回显后等 300 ms、强制更新、再在新阶段发下一条
    流。间隔大于 3 PTO，使上一次更新已被丢弃（否则按 RFC 9001 §6 第二次更新被视为并发而跳过，quinn 与本库都如此），且每次更新都由数据
    携带（只强制而不发包时，双方可能在同一时刻各自翻转，分不清发起方——最初的脚本即因此在 153 上出现 "0 次由对端发起"，已改）。
  - 153 的密钥交换组：quinn 的 ring 提供者只支持 X25519 / P-256 / P-384，本库客户端的 ClientHello 同时带 X25519MLKEM768 与 X25519，
    协商为 X25519；quinn 客户端 → 本库服务端同为 X25519。

- **测试数**：macOS 555 个（此前 491 + 64：`TlsSessionTest` 35、`RealTlsConnectionTest` 22、`RealTlsDriverTest` 6、`InteropTest` 1），
  552 通过、3 个与 quinn 一致地跳过。153（Linux x64，Rocky 9.8）：`NETON_IO_DRIVER=epoll` 与 `iouring` 各 555 个，
  552 通过、3 个跳过。153 在本次运行期间重启过一次（3.6 GB 内存、无交换分区，Gradle 构建与另一构建并发时失去响应）；重启后
  `kernel.io_uring_disabled` 回到发行版默认的 2，io_uring 测试全部以 EPERM 失败，已按此前状态临时（非持久）设为 0 后重跑。此后在 153 上
  只串行运行单个重型任务（`--max-workers=1`，`systemd-run` 与登录会话脱离）。
- **仍未完成**：0-RTT（会话票据、早期数据密钥、是否被接受，另作后续批次单独验收）；服务端 0.5-RTT 数据（受 OpenSSL 读密钥顺序所限，
  见上）；导出器的标签只接受 ASCII（绑定以 C 字符串传递标签；RFC 的标签均为 ASCII）；会话释放后导出器不可用（quinn 的会话随连接
  存在）；没有系统信任库（信任锚必须显式给出，按设计）；其余目标只做了编译检查（共享源集元数据与 mingwX64、linuxArm64、iosArm64、androidNativeArm64 的编译通过），未在其上
  运行测试；quic-interop-runner 与性能对照（§6、§10 第 9 步）未做。

### 11.10 丢包、乱序、取消、关闭与流额度耗尽的组合验证（2026-09-29，TLS 仍为测试替身）
- **范围说明**：回环 UDP 不丢包、不乱序，此前的测试从未在真实条件下走过恢复路径。本节在协议层（虚拟时间）与驱动层（真实套接字、计时器、
  pacing、预算）各加一层网络损伤，按场景组合验证。握手仍用 `MockTls`，真实 TLS 下的同类验证待 §4。
- **损伤层**：
  - 共用模型 `LinkImpairment`（`nativeTest`，`Impairment.kt`）：单方向、按种子的随机丢包、复制、乱序（被选中的数据报延后 `reorderDelay`
    以内的随机时长，后发的超车）；定向丢包规则（按方向内序号与包类型：Initial、含 Handshake 包的数据报——沿长包头的 Length 字段遍历合并包、
    短包头）；黑洞；计数（提供 / 丢弃 / 规则丢弃 / 复制 / 延后）与观察回调。同一种子同一命运序列。
  - 协议层：`ConnPair.clientToServer` / `serverToClient`（`null` 即 quinn 的完美链路），投递按到达时间有序插入，复制体各持一份字节（包在原地
    解密）。新增 `driveUntil(limit, done)`：quinn 的 `step()` 在双方都空闲时停止，而延迟链路上此时仍可能有数据报在途；`driveUntil` 推进到
    条件成立，没有在途数据报、没有计时器而条件仍不成立时返回失败（死锁 / 停滞检测），虚拟时间超限同样失败；应用步骤之后先再驱动一次，
    否则"无在途时的新写入"会被误判为停滞。
  - 驱动层：`LossyRelay`，同一反应器上的 UDP 中继（前后两个套接字，客户端连中继，中继连服务端），每方向一个 `LinkImpairment` 加固定单向
    延迟；GRO 批按 stride 拆开，每个数据报单独定命运，发出时不用 GSO；每方向一个发送协程按释放顺序发送（一个 UDP 套接字只允许一个挂起的
    发送）；套接字缓冲 4 MiB，避免中继自身溢出造成模型之外的丢包。
  - quinn-proto `tests/mod.rs` 中已有的丢包 / 乱序场景（清空 inbound / outbound、`delay_outbound` 的 16 个，如 `initial_retransmit`、
    `server_hs_retransmit`、`finish_retransmit`、`data_blocked_retransmit`、`key_update_reordered`、`congested_tail_loss` 等）此前已全部
    移植，没有遗漏；本节的场景是其上的组合。
- **场景**（每个场景断言数据完整、有界时间内完成、无停滞；连接统计一致——丢包被计数、丢失数不超过发送数、有拥塞事件；两端排空后原生密钥
  计数回到基线，在对象仍可达时检查，基线在 GC 与 cleaner 稳定之后取，排除其他测试遗留对象的 cleaner 干扰）：

  | 场景 | 协议层 `LossyPairTest`（虚拟时间，单向延迟 10 ms） | 驱动层 `LossyDriverTest`（真实 UDP，单向 2 ms） |
  |---|---|---|
  | 批量传输 1% / 5% / 20% 丢包（双向） | 4 / 4 / 2 MiB；另断言无乱序时丢失数 ≤ 丢弃数 + 4 | 同左 |
  | 重度乱序（30%，延后至 30 / 15 ms） | 4 MiB | 4 MiB |
  | 复制 25% + 丢包 2% + 乱序 10%，双向传输 | 4 + 1 MiB，接收方收到的数据报多于发送方发出的包 | 同左 |
  | 握手包丢失 | 客户端 Initial、服务端 Initial、服务端 Handshake、客户端最后一轮 Handshake、双方首个 1-RTT 包，各丢 1–3 个 | 四类各丢 2 个 |
  | 握手随机丢包 | 双向 30%，50 个种子 | 双向 30%，10 个种子 |
  | 握手被黑洞 | — | 服务端的回复全丢：双方的 `Connecting` 都以 TimedOut 失败，密钥全部释放 |
  | 最后的 ACK 丢失 | 发送方写完并 finish 后服务端的 10 个数据报全丢：发送方靠 PTO 探测最终得到确认 | 同左（6 个） |
  | 密钥更新 + 丢包 5% + 乱序 10% | 每 256 KiB 交替发起，≥ 10 次 | 每 20 ms 交替发起，双向传输 |
  | RESET_STREAM 丢失 | reset 后客户端的 3 个数据报全丢：重传，对端读到 Reset(77)，流释放 | 同左 |
  | STOP_SENDING 丢失 | stop 后服务端的 3 个数据报全丢：重传，写方得到 Stopped(9) | 同左 |
  | 取消 | — | 在流量控制上阻塞的写协程与在数据上阻塞的读协程被取消，随后 `close` 两个流，连接继续可用（10 轮） |
  | CONNECTION_CLOSE 丢失 | 关闭方的数据报全丢：关闭方 3 PTO 后排空，对端在空闲超时（10 s）时结束 | 同左（空闲 3 s） |
  | CONNECTION_CLOSE 丢失一次 | 对端仍在发送：关闭方对后到的包再发 CONNECTION_CLOSE，对端得到 ApplicationClosed(6) | 同左 |
  | 高丢包下关闭 | 传输中途改为双向 50% 丢包后关闭（10 个种子）：两端都结束（ApplicationClosed、TimedOut 或无状态重置） | 同左（6 个种子） |
  | 流 / 连接窗口耗尽 + 丢包 | 流窗口 16 KiB、连接 24 KiB、慢读，读后紧接的数据报定向丢弃（MAX_STREAM_DATA / MAX_DATA 丢失），无死锁 | 同窗口、8% 丢包、慢读 3 条流 |
  | 流数额度耗尽 + 丢包 | 并发上限 4、200 条流、10% 丢包（MAX_STREAMS 丢失） | 并发上限 16、100 条双向回显流 |
  | 多流并发 | 双向各 50 条、5% 丢包 + 乱序 | 同上 |
  | 数据报 | 10% 丢包 + 复制 + 乱序：不重传、不重复交付、内容完整、丢包计数 | 同左，等发送队列排空后统计 |
  | 综合（`LossyChaosTest` / `LossyDriverChaosTest`） | 每个种子随机的丢包 / 复制 / 乱序 / 延迟 / 窗口，双向各 12 条流，部分被发送方 reset、部分被接收方 stop，随机密钥更新与数据报，最后在同一链路上关闭、排空；默认 12 个种子 | 每个种子随机损伤，24 条回显流，部分被取消、reset、stop，随机密钥更新与数据报；默认 4 个种子 |

  综合场景的种子范围可由 `QUIC_CHAOS_SEEDS` / `QUIC_DRIVER_CHAOS_SEEDS=from:until` 指定，用于长时间浸泡。协议层每个种子完全可复现；驱动层
  依赖真实计时，同一种子不保证同一过程（失败信息给出种子与损伤参数）。
- **测得**（协议层为虚拟时间；驱动层为负载很高的 macOS 上的墙钟时间，仅供参考）：

  | 场景 | 协议层 | 驱动层（macOS） |
  |---|---|---|
  | 4 MiB，1% 丢包 | 4.7 s，丢失 30（丢弃 30） | 3.5 s，丢失 30 |
  | 4 MiB，5% 丢包 | 11.5 s，丢失 175（丢弃 175） | 7.8 s，丢失 175 |
  | 2 MiB，20% 丢包 | 14.4 s，丢失 423（丢弃 424） | 11.5 s，丢失 422 |
  | 4 MiB，30% 乱序 | 25.7 s，约 590 个包被（虚假地）判为丢失 | 526 个 |
  | 握手首轮丢 2 个 | — | 客户端 Initial 1.08 s、服务端首轮 1.05 s（各约一个初始 PTO），客户端 Handshake 62 ms、HANDSHAKE_DONE 61 ms |
  | CONNECTION_CLOSE 全丢 | 关闭方 < 5 s 内排空，对端 10–12 s 超时 | 关闭方 108 ms 排空，对端 3.04 s 超时 |
  | 数据报 2000 个 | 交付 1790 | 交付 1790，发出 2000 |

  浸泡：协议层综合场景 212 个种子（0–211）全过；驱动层综合场景在两处修正与测试回显的生命周期修正之后 240 个种子（0–239，macOS）全过。
- **发现并修正的缺陷**（各为独立提交，回归测试在 `LossyRegressionTest`，去掉修正时失败、加上后通过，均已实测）：
  1. **被 STOP 的流在连接窗口满时永远等待**（`Streams.kt` 的 `writeSource`）。原因：写入先检查连接级额度，连接窗口满时对已被对端 STOP 的流
     返回 `Blocked` 并把流放进"连接阻塞"列表；`MAX_DATA` 到来时该列表只报告仍有流级额度的流，而对端已停止读取、流级额度用完的流再也不会得到
     额度，写协程收不到 `Stopped`，直到连接空闲超时。`Stopped` 事件本身会唤醒写协程，但同一个 `MAX_DATA` 唤醒的其他写协程先运行、用掉了
     STOP 时归还的连接额度。quinn 0.11.12 的检查顺序相同。修正 ⚖️：先报告 `ClosedStream` / `Stopped`，再检查连接级额度。回归测试
     `writeOnStoppedStreamFailsWhileConnectionBlocked`：A 用完流窗口、B 用完连接窗口，服务端 stop A，另一条流用掉归还的额度后再写 A——
     修正前得到 `Blocked`，修正后得到 `Stopped(9)`。由 `LossyDriverChaosTest` 发现（停滞时两端无在途数据、无计时器，写方挂在 `blockedWriters`
     中而流已有 stopReason）。
  2. **丢包下的密钥更新使连接永久失效**（`Connection.kt` 的 `forceKeyUpdate`，例行更新同样经过它）。原因：发起更新只检查"不保留上一阶段
     密钥"，而上一阶段密钥由丢弃计时器（3 PTO）清除，与对端是否见过当前阶段无关。一方采纳对端的更新（K1）后，若它在 K1 下发出的包全部丢失，
     计时器到期后它可以再发起 K2；对端仍在等它的第一个 K1 包（上一阶段密钥的结束包号未定），于是用 K0 解 K2 的包，全部认证失败，直到空闲超时。
     违反 RFC 9001 §6.1（在当前阶段有包被确认之前不得发起新的更新）；quinn 0.11.12 同样只检查上一阶段密钥。修正 ⚖️：记录当前密钥下的第一个
     包号，在最大已确认包号达到它之前不发起更新。回归测试 `keyUpdateWaitsForAnAcknowledgedPacketOfTheCurrentPhase`：服务端更新，客户端采纳，
     客户端的包全丢到计时器之后，客户端再强制更新——修正前服务端再也读不到客户端的数据，修正后传输完成。由 `LossyDriverChaosTest` 发现
     （停滞时双方都有未确认的本端更新、相位不同，服务端 `authenticationFailures` 增加）。
- **排查后确认不是库缺陷的现象**（记录以免重复排查）：
  - 双向 30% 丢包下连接可能在握手后空闲超时：重传的 Initial 使 RTT 样本达约 1 s，客户端在对端完成地址验证之前不重置 PTO 计数（RFC 9002），
    PTO 退避可超过 30 s 的空闲超时，连接按规范结束。握手随机丢包场景因此在握手完成后把丢包率降到 5%。
  - `sendDatagramWait` 只是入队（发送缓冲 1 MiB），拥塞下测试结束时大部分数据报仍在队列中；场景改为等发送队列排空后再统计。
  - 关闭方排空后，对端的迟到包得到无状态重置，对端以 `Reset` 结束——符合 RFC 9000，场景接受它为正常结束。
  - 驱动层综合场景一度出现流数额度耗尽后的空闲超时：测试中的回显处理在写入遇到 `Stopped` 时没有关闭 `SendStream`，流永远不被释放，服务端
    不再发 MAX_STREAMS。这是 §3 生命周期规则（Kotlin 没有 drop，须显式 `close`）的使用错误，已在测试中修正；quinn 中 drop 会自动 reset。
- **全量测试**：macOS 532 个（529 通过，3 个与 quinn 一致地忽略）；153（linux x64）`NETON_IO_DRIVER=epoll` 与 `iouring` 各 532 个，
  同样 529 通过、3 个忽略。153 上驱动层综合场景浸泡种子 0–23，两种驱动均全过（153 内存小，浸泡范围有意限制）。
- **局限**：TLS 为测试替身；中继一次服务一个客户端，不模拟 ECN 标记、MTU 变化与路径迁移（迁移、MTU 黑洞在 quinn 移植的测试中另有覆盖，
  但不在损伤链路上）；中继的延迟用每个数据报一个协程与毫秒级计时器实现；0-RTT 未在损伤链路上验证；驱动层场景的时间界限按负载很高的宿主设定
  （宽松）；与 quinn 的互通未做，两处修正是对 quinn 0.11.12 的偏离（⚖️），应向上游报告。

### 11.11 整个套件在真实 TLS 上通过（2026-09-29，macOS）
- **范围**：§11.9 记录的以 `NETON_QUIC_TEST_TLS=real` 运行整个套件时的失败逐一查明原因。原则：揭示库缺陷的修库（独立提交、回归测试
  去掉修正即失败）；测试侧的差异让测试按模式区分，且不删除、不削弱任何断言；0-RTT 不在本批，相关测试在真实 TLS 下跳过并打印原因。
- **逐项结果**：

  | 原失败 | 原因 | 处理 |
  |---|---|---|
  | `DriverTest.zeroRtt`（超时） | **库缺陷**（见下）：服务端在握手完成前取得连接（`Connecting.into0Rtt`）后立即 `openUni`，永远等待。第二次连接取 0-RTT 密钥的断言尚未执行就挂住 | 修库；测试本身依赖 0-RTT，真实 TLS 下跳过 |
  | `ConnectionTest.zeroRttHappypath`、`zeroRttIncomingBufferSize`、`zeroRttIncomingBufferSizeTotal`（`has0rtt()` 为假） | 真实会话不发票据，没有 0-RTT（本批不含，§11.9） | 真实 TLS 下跳过并打印原因；替身下照常运行 |
  | `ConnectionTest.zeroRttRejection`（服务端 alert 50 length mismatch） | 测试显式用 `MockClientCrypto`（要改它的 ALPN 使票据失效），与真实服务端配对：替身的 ClientHello 不是 TLS，真实服务端以 decode_error 拒绝——行为正确 | 同上（依赖 0-RTT），跳过 |
  | `ConnectionTest.alpnSuccess`（ClassCastException） | 测试把握手数据强转为 `MockHandshakeData` | 经 `TestTls.negotiatedProtocol` 读取（两种握手数据都认，其他类型即失败），断言不变 |
  | `ConnectionTest.handshakeAntiDeadlockProbe`（客户端 alert 50） | 测试的大证书服务端写死为 `MockServerCrypto`，与真实客户端配对，替身的 ServerHello 被真实客户端拒绝 | `bigIdentityPair()` 按模式成对：真实 TLS 下为 1000 个名字的自签名证书与信任它的客户端 |
  | `ConnectionTest.serverCanSend3InitalPackets`（期望 3 得 1） | 同上配对错误（得 1 是客户端收到 alert 的一个数据报）；配对正确后，默认的两数据报 ClientHello 使服务端首轮为 6 个 | 同上成对，并用 X25519 客户端（quinn 测试中 rustls ring 提供者只发 X25519，ClientHello 一个数据报），断言仍为 3；默认两数据报的情形已由 `RealTlsConnectionTest.serverCanSend3InitalPackets` 断言 2 与 6 |
  | `ConnectionTest.validateThenRejectManually`（期望 0 得 1） | 每个不属于已有连接的 Initial 数据报都是一个独立的 `Incoming`，测试框架（与 quinn 的相同）逐个同步决定；两数据报的 ClientHello 使应用被问两次，quinn 的计数假定一个数据报 | 用 X25519 客户端（`oneDatagramHelloClientConfig`），断言不变；新增两数据报版本 `validateThenRejectWithATwoDatagramClientHello`，断言确切序列 `[未验证, 未验证, 已验证, 已验证]`（首个 ClientHello 两次 Retry，客户端只接受第一个；第二个 ClientHello 两次拒绝，客户端在第一个 CONNECTION_REFUSED 上关闭），两端最终不留连接与 CID |
  | `TokenPairTest.useTokenThenRetry`（期望 true） | 同上。两数据报时第二个数据报带同一个 NEW_TOKEN 令牌，而令牌第一次使用后即记入令牌日志，第二次视为重用、不验证地址（quinn `use_same_token_twice` 的规则）——行为正确 | 用 X25519 客户端，断言不变；新增 `useTokenThenRetryWithATwoDatagramClientHello`，断言确切序列 `[(已验证, 可 Retry), (未验证, 可 Retry), (已验证, 不可 Retry)]`，连接建立并关闭后两端清空 |
  | `KeyLifecycleTest.refusedAndRetriedAttemptsReleaseTheirInitialKeys`（期望 1 得 2） | **不是泄漏**：失败的是 `validated` 计数，不是密钥计数——两数据报的 ClientHello 在 Retry 之后的两个数据报各得一个 `Incoming`、各被拒一次（同上）。断言在密钥检查之前失败，所以两数据报下的释放此前未被检查过 | 用 X25519 客户端，断言不变；新增 `RealTlsConnectionTest.refusedAndRetriedAttemptsWithATwoDatagramClientHello`：10 轮，`validated` 为 2，四个 `Incoming` 与被拒客户端的 Initial 密钥、TLS 会话、StableRef 全部回到基线（基线在 cleaner 稳定后取），通过——没有泄漏 |
  | `FairnessTest.heavyConnectionDoesNotStarveOthers`（p99 608 ms > 250 ms） | 宿主负载：当时 1 分钟 load average 85–125（另有其他任务） | 界限不变（见下） |

  测试侧另一处修正：`KeyLifecycleTest` 的基线原为测试开始时的 `NativeKeys.live`。按过滤器改变测试顺序后（例如先运行 `ConnectionTest`，其中
  有测试不关闭就丢弃连接，由 cleaner 兜底），前面测试的垃圾会在计数中途被 cleaner 释放，出现"打开的连接不持有密钥"之类的误报（两种模式都
  有）。改为 `settledNativeKeys()`（GC 并等 cleaner 稳定后取基线，§11.10 的做法），断言不变。
- **发现并修正的库缺陷：握手完成前取得的服务端连接打不开流**（`neton.quic.Connection` 驱动层）。
  - 原因：服务端的 `Connecting.into0Rtt()`（quinn 的 0.5-RTT 路径）在首个 Initial 数据报处理后即交出连接。ClientHello 跨多个数据报时（OpenSSL
    默认的 X25519MLKEM768 混合密钥份额，或很长的 ALPN 列表），客户端的传输参数——包括流数上限——在后面的数据报里才到，此前 `open` 得到
    `null` 并等待 `StreamEvent.Available`。而应用对端参数（`StreamsState.setParams`）只抬高上限、不产生任何流事件（quinn 0.11.12 相同：
    `set_params` 不推 `Available`），客户端也不会为初始上限再发 MAX_STREAMS，于是 `openUni` / `openBi` 永远等待。与 TLS 无关：替身配很长的
    ALPN 列表同样挂住。quinn 的测试不触发它，是因为那里 rustls 的 ClientHello 只占一个数据报。
  - 修正 ⚖️：proto 层记录"对端参数已应用"（`Connection.peerParamsApplied`，在 `setPeerParams` 置位，含 0-RTT 票据中的缓存参数），驱动层每轮
    处理后第一次看到它时唤醒两个方向的 `streamBudgetAvailable`。不在 proto 层发 `Available` 事件，以免改变 quinn 测试断言的事件序列。
  - 回归测试 `HalfRttOpenTest`（服务端 `into0Rtt` 后立即 `openUni` 与 `openBi` 并写入，客户端读到两条流）：替身 + 1000 个 ALPN 协议的
    ClientHello、真实 TLS 默认密钥份额（两个数据报）——去掉修正时两者都在 15 s 超时，加上后约 100 ms 通过；真实 TLS + X25519（一个数据报）
    修正前后都通过（对照）。
- **0-RTT 在真实 TLS 上被干净地拒绝**（本批不支持，但不得崩溃或挂住）：
  - 跳过方式：kotlin.test 没有运行时跳过，`TestTls.skipOnReal(test, reason)` 在真实 TLS 下打印
    `SKIPPED on real TLS: <测试>: 0-RTT (session tickets, early data) is not in this batch ...` 后返回（出现在测试输出与 XML 报告的
    system-out 中）；这 5 个测试（`ConnectionTest` 4 个、`DriverTest.zeroRtt`）因此在 Gradle 的计数中算作通过，下文计数单列。替身下照常运行。
  - 新增验证：`RealTlsConnectionTest.zeroRttIsDeclinedOnReconnect`（同一客户端配置第二次连接：`has0rtt()` 假、`earlyCrypto()` 为 null、握手前
    不能开流、`accepted0rtt()` 假、客户端 `earlyDataAccepted()` 为 false、服务端为 null，1-RTT 数据照常，无丢包）；
    `zeroRttPacketsAtARealServerAreDropped`（在两数据报的 ClientHello 之间与之后注入伪造的 0-RTT 包：服务端没有 0-RTT 密钥，丢弃，握手与关闭
    照常，服务端事件只有 HandshakeDataReady、Connected）；`RealTlsDriverTest.zeroRttIsDeclinedOnReconnect`（驱动层：第二次连接 `into0Rtt()`
    返回 null，`await()` 后回显照常）。`DriverTest.zeroRtt` 在真实 TLS 上的超时即上面的库缺陷，不是 0-RTT 本身的问题。
- **计数（macOS arm64，各 3 次完整运行，`--rerun-tasks`）**：共 605 个（此前 596 + `HalfRttOpenTest` 3 + `RealTlsConnectionTest` 5 +
  `RealTlsDriverTest` 1）。
  - 替身（默认）：3 次均 602 通过、3 个与 quinn 一致地忽略。
  - 真实 TLS：602 通过（其中 5 个为上述打印原因后跳过的 0-RTT 测试，实际执行 597）、3 个忽略；3 次中 2 次全过，1 次 `FairnessTest` 失败
    （request p99 290 ms > 250 ms；这次运行开始时 1 分钟 load average 65、结束时 112，5 分钟平均 202 → 141）。
  - `FairnessTest` 各次（heavy 负载下 request p99）：替身 106 / 185 / 151 ms，真实 TLS 207 / 218 / 290 ms；无 heavy 连接的基线 p99 为替身
    3 / 4 / 30 ms、真实 TLS 7 / 31 / 23 ms；heavy 负载下握手 p50 替身 85 / 133 / 111 ms、真实 TLS 86 / 158 / 150 ms。运行期间宿主 1 分钟
    load average 在 65–350 之间（本机 10 个逻辑核，另有其他任务）。真实 TLS 的请求延迟略高但同一数量级（3 次样本、负载不同，未再细分
    原因）；失败只在负载极高时出现，没有发现真实 TLS 特有的问题，界限不变。
- **仍未完成**：0-RTT（票据、早期数据、是否接受）；服务端 0.5-RTT 数据（§11.9，OpenSSL 的读密钥顺序）；以上只在 macOS 上运行（153 当时供其他
  任务使用，未在 Linux 上复验本节）。

### 11.12 发布准备与 Linux 全量复验（2026-10-07 / 08，版本 0.1.0）
- **包序号耗尽 ⚖️**（RFC 9000 §12.3）：`PacketBuilder` 在取包序号前检查数据空间的下一个序号，达到 2^62 − 2（一次可能取两个：`PacketNumberFilter`
  会跳过一个）即 `kill(INTERNAL_ERROR "packet numbers exhausted")` 并不再发送任何包（连 CONNECTION_CLOSE 也不发）；`PacketSpace.getTxNumber`
  保留 `nextPacketNumber < 2^62` 的不变式检查。quinn 0.11 在此断言（panic）。测试 `PacketNumberExhaustionTest`：把客户端的下一个序号设为
  2^62 − 2（同时把已确认的最大序号设在附近，使序号可编码，如同一条真实连接走到这里时那样），再写数据：客户端连接关闭并报告
  `ConnectionLost(Transport(INTERNAL_ERROR))`，服务端连接未关闭（没有收到任何包），只收到此前的数据。
- **目标与依赖**：去掉 mingwX64——io（0.1.0 至 0.2.0）在 Windows 上没有 UDP，该产物无法打开端点；依赖改为 io 0.2.0、io-testkit 0.2.0（测试）、
  openssl 4.0.2。
- **发布配置**：版本 0.1.0；POM、签名、javadoc jar 与本地暂存仓库，与 http 相同。本地暂存产物：quic 与 quic-testkit 各 9 个目标 + 元数据，
  共 20 个 POM、1220 个文件，全部签名；POM 依赖为 io 0.2.0、openssl 4.0.2。尚未上传 Maven Central。
- **互通脚本能报失败**：`run-interop.sh` 每项打印 PASS / FAIL，有意外结果时以非零退出；拒绝类用例（3a、3b、4）只在以预期原因失败时才算通过
  （日志中分别须有 `UnknownIssuer`、`no application protocol`、`certificate verify failed`），否则对端没有启动也会被当成"拒绝成功"。负对照：
  把本库可执行文件换成 `/usr/bin/false`，8 项全部 FAIL、退出码 1。两个脚本加上可执行位。
- **互通中本库发起的密钥更新被跳过**（测试问题，已改）：153 上本库一端只成功发起 2–5 次（应为 8 次，quinn 发起的 8 次都成功）。原因是 9 月 29 日
  的修正（RFC 9001 §6.1：当前密钥阶段发出的包得到确认之前不得发起下一次更新；quinn 0.11 不检查）：采用对端的更新后，本库在 300 ms 的等待里
  可能只发过 ACK（ACK 不会被确认），于是强制更新被跳过。§11.9 表中的计数是在该修正之前测得的；在 153 上用当时的二进制复测仍为 16 / 16，
  新二进制为 10 / 13、10 / 11、12 / 12（epoll 与 io_uring 相同）。`InteropTest` 改为先发 PING、再重试强制更新直到更新发生（最多 1 s），并断言
  本库发起的更新数等于流数（原为至少 1 次）。改后 macOS 与 153（epoll、io_uring）均为双方各 16 次（各 8 次由对端发起），quinn 记录 16 次。
- **测试计时容差**：`LossyDriverTest.lostConnectionCloseEndsInIdleTimeout` 在 153 上测得空闲超时 2.99994 s 而失败：对端的空闲计时从它最后一次
  收到包时开始，略早于测试开始计时的时刻，且计时器精度为毫秒。下界改为 3 s − 100 ms。复验 4 次为 3.0001–3.0020 s。
- **计数**：606 个（605 + `PacketNumberExhaustionTest`），3 个与 quinn 一致地忽略。
  - macOS arm64：替身 603 通过；真实 TLS（`NETON_QUIC_TEST_TLS=real`）603 通过。此前一次全量中 `LossyDriverTest.handshakeUnderRandomLoss`
    超时失败，当时本机同时在编译 quinn（cargo），单独重跑 5 次均通过（23.8–27.1 s），无负载的全量也通过。
  - 153（Rocky 9.8，linuxX64）：替身 + io_uring、替身 + epoll、真实 TLS + io_uring、真实 TLS + epoll 各 603 通过；quinn 互通 8 / 8。
    串行运行（`bench-arena/quic-linux-regression.sh`），结束后无残留进程。

### 11.13 Windows 与 CI（2026-10-08）
- **恢复 mingwX64**：io 补上 Windows 的 UDP（io SPEC §29.7：`WSARecvMsg` / `WSASendMsg`、ECN、PKTINFO、USO；IOCP 以 0 字节 `MSG_PEEK` 接收等待可读）
  后，quic 与 quic-testkit 重新提供 mingwX64（§11.12 曾因 io 没有 UDP 而去掉）。
- **CI**（`.github/workflows/ci.yml`，此前本仓库没有 CI）：全量测试在 macOS（kqueue）、Linux（epoll、io_uring）、Windows（IOCP、WSAPoll）上运行，替身与
  真实 TLS（`NETON_QUIC_TEST_TLS=real`）各有覆盖，共 7 项，另编译全部目标、链接 Windows 与 Android 测试程序。io 在含 Windows UDP 的版本发布之前以
  `--include-build` 取其仓库的 main。
- **第一轮**（run 37658939882）：6 项通过，Windows IOCP + 真实 TLS 失败 2 个——`FairnessTest`（重连接在轻负载阶段只传了 3.7 MB，下限 4 MiB）与
  `DriverBudgetTest.sendDrivesAreBounded`（4 MiB 传输从未用满发送预算）。各平台对照：Windows 上即使用替身，重连接也只有约 5 MiB/s（Linux / macOS
  约 23–24 MiB），发送预算的让出 0–2 次（Linux 145 次）：发送端在等计时器。原因在 io：Windows 默认 15.6 ms 的系统时钟周期使 `delay(1)` 迟到
  13–15 ms，pacing 与丢包计时器按约五分之一的速度运行；io 以每个 reactor 运行期间 `timeBeginPeriod(1)` 修正（io SPEC §29.8，修正后迟到 p50 约 1 ms）。
- **计时修正后仍未好转**（run 37663345112）：3 个 Windows 任务失败，发送预算的让出仍为 0。`DriverBudgetTest` 加上路径统计后（run 37664936685）：Windows
  传 4 MiB 丢 74–105 个包、14–15 次拥塞事件、拥塞窗口停在 138–192 KB、接收缓冲 128 KiB；Linux 0 丢包、窗口 4.2 MB、接收缓冲 1 MiB（GitHub
  Ubuntu 的默认）；macOS 丢 74 个。回环上发送突发（USO 每次 10 段）超过接收缓冲即丢，每次丢包窗口减半。计时不是主因。
- **接收缓冲实验**（测试端点）：4 MiB 时各平台 0 丢包，Windows 重连接 25–35 MiB（此前 3–5），但 `FairnessTest` 的请求 p99 在 Windows 与 macOS 上
  为 271–344 ms，超过当时 250 ms 的界限；1 MiB 时各平台 0 丢包，只有 Windows 的两项 p99 268 / 298 ms 越界。
- **修正 ⚖️**（所有者决定：由 quic 主动调大）：`DriverConfig.receiveBufferSize`（默认 1 MiB，即实测消除丢包的最小值；只调大不调小；0 表示不改，
  即 quinn 的行为），端点创建与 `rebind` 时应用；操作系统可能封顶（Linux 的 `net.core.rmem_max`）。quic-go 同样主动调大接收缓冲。
- **`FairnessTest` 的界限**：不再丢包后重连接填满其流量窗口，轻请求排在它之后，测得的正是该测试文档所述"约一个窗口的处理时间"；此前的低延迟
  部分来自重连接因丢包跑不满窗口。按其原则（远低于丢失 Initial 的 1 s 恢复与饥饿时的数秒）重定：请求 p99 250 → 500 ms、最大 500 → 900 ms，
  握手 500 ms 不变。修正后（run 37671374403）Windows 请求 p99 164–314 ms、最大 175–343 ms，Linux 45–78 ms，macOS 115–203 ms。
- **`LossyDriverTest.stopSendingLostAndRetransmitted`** 在 macOS 真实 TLS 上失败一次（STOP_SENDING 只发了一次）：中继按经过的数据报计数，`stop()`
  之前服务端已发出、仍在中继套接字里排队的 ACK 也占用"丢 3 个"的名额，3 个未必轮到 STOP_SENDING。改为丢 10 个，失败信息给出发送次数与实际
  丢弃数。本机真实 TLS 连续 11 次通过。（原因是推断：CI 那次没有留下计数。）
- **结果**（run 37672832185）：7 个测试任务与全目标编译全部通过。`DriverStats.blockedSends`（发送缓冲满而等待的次数）在各平台都是 0，排除了
  "Windows 发送缓冲满、IOCP 退避轮询可写"的假设。
- **仍未解决**：Windows 上不丢包后传 4 MiB 仍需 0.55–0.85 s（Linux 0.10–0.17 s、macOS 0.31 s），发送预算的让出 1–19 次（Linux 145 次）：发送端
  不忙，瓶颈多半在接收侧（Windows 每次系统调用收一个数据报，Linux `recvmmsg` 一次 32 个；同一反应器上的接收轮次有 50 µs 的时间预算）。作为
  性能项，需要在 Windows 上做剖析后再改；`DriverBudgetTest` 在 Windows IOCP 替身上只让出 1 次，处在边界上。

### 11.14 真实 TLS 上的会话恢复与 0-RTT（2026-10-08）
此前真实 TLS 会话拒绝 0-RTT（§11.9、§11.11，相关测试在真实 TLS 下跳过）。参照 quinn 0.11 的做法——quinn 把票据、早期数据与接受判定都交给
rustls——在 OpenSSL 4.0.2 的第三方 QUIC TLS 接口上实现（`TlsSession.kt`、`TlsConfig.kt`；所需函数 openssl-kotlin 的绑定都已有，未改动它）。
- **客户端**：`TlsClientConfig(enableEarlyData = true)`（默认开启，quinn 设置 rustls `enable_early_data`）。客户端 `SSL_CTX` 设为客户端会话缓存
  且不在 OpenSSL 内部存储，票据经 `SSL_CTX_sess_set_new_cb` 以 DER 形式交给会话，再连同本连接收到的服务端传输参数与"是否允许早期数据"
  （`max_early_data == 0xffffffff`）存入配置的 `TicketCache`：按服务器名，每名至多 8 张、至多 256 个名字，取最新的一张、用后即弃（与 rustls
  `ClientSessionMemoryCache` 相同）。新连接取到票据时 `SSL_set_session`，在服务端参数到达之前 `transportParameters()` 返回票据记下的参数
  （RFC 9000 §7.4.1），票据允许时 `SSL_set_quic_tls_early_data_enabled(1)`。OpenSSL 在写完 ClientHello 后给出 EARLY 级别的写密钥，由它导出
  0-RTT 的报文与头部保护密钥；该级别不改变 CRYPTO 数据所用的级别。握手完成时以 `SSL_get_early_data_status` 判定 `earlyDataAccepted`。
- ⚖️ **ALPN 变化**：票据所协商的协议不在本次提议中时，OpenSSL 客户端会以 INCONSISTENT_EARLY_DATA_ALPN 使握手失败；rustls 照发 0-RTT、由服务端
  拒绝。本库此时只恢复会话、不发 0-RTT，改了协议的客户端照常连接（`zeroRttRejection` 在真实 TLS 下据此断言）。
- **服务端**：`TlsServerConfig(earlyData = true)`（默认开启，quinn 把 rustls `max_early_data_size` 设为 `u32::MAX`）：每个会话
  `SSL_set_quic_tls_early_data_enabled(1)`，OpenSSL 随之把 `max_early_data` 设为 0xffffffff 并启用重放保护——票据有状态、单次使用（第二次使用
  回退为完整握手，0-RTT 被拒绝），与 rustls 有状态恢复相同。每个连接签发两张票据（OpenSSL 默认；rustls 也是两张）。设置 session id context，
  使启用客户端证书时也能恢复。与 rustls 一样，服务端只比较 TLS 层的条件（版本、密码套件、ALPN、票据新鲜度），不比较 QUIC 传输参数。
- **途中发现并修正的两个缺陷**：
  - 服务端缓存丢失最新票据的会话：`SSL_free` 对"握手完成但未发送 close_notify"的连接调用 `ssl_clear_bad_session`，把它当前的会话——最后
    一张票据的会话——从服务端缓存删除；QUIC 以 CONNECTION_CLOSE 结束，从不发送 close_notify。客户端用最新的票据恢复，于是总是完整握手
    （诊断：服务端缓存中 1 个会话、客户端收到 2 张票据；改取最早的一张即恢复成功）。修正：握手完成过的会话在释放前 `SSL_set_shutdown(SENT |
    RECEIVED)`；rustls 不会因连接结束而遗忘会话。
  - 服务端过早地认为握手完成：开启早期数据的服务端，`SSL_do_handshake` 在发出自己的 Finished 后即返回 1（以便读取早期数据），握手要到客户端
    的 Finished 才完成。旧代码据此把握手标为完成、连接进入已建立状态，1-RTT 读密钥却尚未到达，数据空间没有密钥——大证书的测试在 MTU 探测处
    空指针，丢包与多连接测试超时。修正：以 `SSL_is_init_finished` 判定完成；返回 1 而未完成时，有进展且仍有输入就继续驱动，否则等待输入。
- **票据回调失败不影响连接**：与其他回调不同，`NEW_SESSION` 的失败只丢弃这张票据并计数（缓存只是优化；rustls 也不会因存票据失败而断开）。
- **测试**：quinn 的 0-RTT 测试（`ConnectionTest` 四个、`DriverTest.zeroRtt`）在真实 TLS 下运行（取消跳过；缓冲大小两个改用单数据报
  ClientHello，按数据报计数）；新增 `RealTlsConnectionTest.zeroRttIsAcceptedOnReconnect`、`aReplayedTicketGetsItsZeroRttRejected`（同一张票据用
  两次：第二次 0-RTT 被拒绝，0-RTT 流作废后同一 ID 重新打开、数据在 1-RTT 重发）、`zeroRttCanBeTurnedOffOnEitherSide`，
  `RealTlsDriverTest.zeroRttThroughTheDriver`（第二次连接以 `into0Rtt` 发送并确认被接受；第一次连接等票据到达后再关闭，否则票据可能尚未
  到达——quinn 与 rustls 相同）。macOS 全量两种 TLS 模式各 605 个通过。
- **与 quinn 互通**（`interop/quinn-peer`，quinn 客户端开启 `enable_early_data`、服务端 `max_early_data_size = u32::MAX`）：本库客户端以 quinn
  （rustls）签发的票据向 quinn 服务端发送 0-RTT，quinn 客户端以本库（OpenSSL）签发的票据向本库服务端发送 0-RTT，两个方向都被接受；脚本要求
  两端都报告 0-RTT 被接受。服务端一侧以 `has0rtt()` 判定（quinn 的 `accepted_0rtt` 只是客户端视角）。互通从此在 GitHub Actions 上运行（Linux，
  epoll 与 io_uring 各一次，quinn 端由 `cargo build` 构建），11 项全部通过。
- **CI**（run 37717311830）：全目标编译（首轮在 mingwX64 失败：`SSL_CTX_ctrl` 的 C `long` 在 Windows 上是 32 位，改为按平台的
  `sslCtxSetSessionCacheMode`）、Linux 两项、Windows IOCP 两种 TLS 模式（各 608 个）、macOS 真实 TLS、两项互通通过；macOS 替身的
  `LossyDriverTest.handshakeUnderRandomLoss` 与 Windows WSAPoll 的 `ManyConnectionsTest` 各一次超时（均在替身 TLS 上，与本节改动的代码无关；
  前者是空闲超时：30% 双向丢包下多数据报的握手数据组常被连续丢失，PTO 逐次翻倍，连续六七次即超过默认 30 s 的空闲时限；本机每个种子 2–3 s、
  连续 10 次通过。该测试验证的是丢包下完成握手而非空闲时限，改为 120 s 空闲时限并注明原因。后者未复现，记为待观察）。

