# MITM 高级协议：HTTP/3、解压、流式、WebSocket、HTTP/2 帧

本文盘点内嵌引擎（`crates/engine-embedded`，iOS、macOS、Windows、Linux、Android
共用）HTTPS 解密在五类高级能力上的现状，给出排期、每项的设计要点与 CI 门槛。
状态随 PR 更新本文，不另开文档。

约束（全部条目都要守住）：

- iOS Network Extension 内存上限约 50 MB。解密路径的每一项新缓冲都要有固定上限，
  并计入抓包预算（`capture.rs` 的 `MAX_*` 常量）。
- 抓包发版硬门槛不放宽：HTTPS 解密成功率 ≥ 95%、开抓包吞吐下降 ≤ 15%、峰值内存
  增量 ≤ 10 MiB（`capture-gates.yml`，见 [性能与长稳 CI](../performance-ci.md)），以及
  短连接风暴门槛 F8。
- 不做 HTTP/1.1 ↔ HTTP/2 协议转换；协议细节交给维护中的 crate（`h2`、`rustls`），
  不手写 HPACK 或 TLS。
- 客户端展示先接 Apple（SwiftUI）与 Tauri 检查器；原生化中的 Windows/Linux/安卓
  界面复用同一组内核接口。

## 现状盘点（main 385744d）

| 能力 | 现状 | 缺口 |
| --- | --- | --- |
| HTTP/2 | 全平台按 stream 解密、改写、抓包（`mitm/http2.rs`，16 stream、128 KiB 窗口） | 帧级视图：SETTINGS、WINDOW_UPDATE、PING、RST_STREAM、GOAWAY、PRIORITY 不可见，`h2` crate 不暴露帧 |
| HTTP/3 / QUIC | 不解密；手动「屏蔽 QUIC」开关拒绝全部 UDP/443（#223），默认关 | 开着 MITM 时，App 走 HTTP/3 的请求整段绕过解密与抓包（Safari、URLSession、Chrome 常用 HTTP/3） |
| WebSocket | HTTP/1.1 `101` 后原样转发，抓包只留握手，`note = streaming`；HTTP/2 扩展 CONNECT 回 405（不宣告 `ENABLE_CONNECT_PROTOCOL`，App 回落 HTTP/1.1） | 消息不可见 |
| 流式响应 | SSE 与升级不缓冲直接转发，但不记录内容；无规则读的正文边到边转，抓包留前 64 KiB；规则读的正文整包缓冲到 1 MiB，超出 `too_large` 且本连接后续不再改写 | SSE 事件不可见；进行中的请求要等结束才出现；命中规则却因流式被跳过时没有提示 |
| 解压 | 内核不解压。规则读响应时请求改为 `Accept-Encoding: identity`；Apple 检查器自解 gzip/deflate/br，Tauri 只解 gzip/deflate | 无 zstd；Tauri 无 br；源站无视 identity 时规则读到压缩字节；导出（HAR 等）不给解压文本 |

## 排期（按价值与风险）

| 序 | 条目 | 价值 | 风险 | PR |
| --- | --- | --- | --- | --- |
| 1 | MITM 主机的 QUIC 自动回落 TCP | 高：不做则 HTTP/3 流量抓不到 | 低 | #238 |
| 2 | 内核统一解压 gzip/deflate/br/zstd | 中高：检查器、导出、改写都受益 | 低（压缩炸弹要限） | 本 PR（内核）；客户端另开 |
| 3 | 流式：进行中请求可见、SSE 事件、流式跳过提示 | 中高：AI/推送类 App | 中（内存） | 待开 |
| 4 | WebSocket 消息查看 | 中 | 中（内存、permessage-deflate） | 待开 |
| 5 | HTTP/2 帧视图 | 中：排查流控、RST、GOAWAY | 低 | 待开 |
| 6 | HTTP/3 真正终结（QUIC MITM） | 低到中 | 高（见 D1） | 不做（D1） |

每项内核一个 PR，Apple 与 Tauri 检查器各一个 PR（anixops-net）。

## 1. MITM 主机的 QUIC 自动回落

开着 MITM 时，发往 UDP/443、且目标主机在合并后的 `[MITM] hostname` 列表里的 QUIC
流，用与「屏蔽 QUIC」相同的 ICMP 端口不可达拒绝，App 立刻回落 TCP，从而进入
HTTP/2 / HTTP/1.1 解密。其余主机的 QUIC 照常放行，不影响非解密流量的速度。

- 主机名来源：Fake-IP 映射有名字时直接用；否则解析 QUIC v1 Initial 包取 SNI
  （RFC 9001 §5.2 的 Initial 密钥只由 DCID 派生，可解；头部保护用 AES-128-ECB，
  载荷 AES-128-GCM，由 `ring` 提供）。ClientHello 跨多个 Initial 包（后量子
  密钥交换下常见、Chrome 还会打乱 CRYPTO 帧顺序）时按偏移重组，最多 4 个包、
  8 KiB；超出或解析失败按「无 SNI」放行。QUIC v2 与未知版本放行。
- 连接列表规则名 `MITM-QUIC`，失败原因 `quic_mitm_fallback`，与 `BLOCK-QUIC` 区分。
- 测试：Initial 解密用 RFC 9001 附录 A 的测试向量；跨包、乱序、截断、错误版本；
  端到端用 `quinn` 客户端发 Initial，断言 MITM 主机收到 ICMP、非 MITM 主机通过。
- 门槛：抓包门槛不变；新增单测与集成测试进 `ci.yml`。

## 2. 内核统一解压

新模块 `capture/decode.rs`：gzip、deflate（zlib 与裸流）、br、zstd，纯 Rust
（`flate2` 的 `miniz_oxide` 后端、`brotli-decompressor`、`ruzstd`），可叠加编码
（`Content-Encoding: gzip, br`）逆序解。

- 解压炸弹：输出上限与输入无关，扩展内（导出、改写）用 `MAX_HTTP_BODY_BYTES` /
  `MAX_BODY_BYTES`，App 进程内（检查器）16 MiB，超出即停并标 `truncated`。
- 窗口：br 与 zstd 按流头声明的窗口一次性分配，所以先读流头再解：扩展内上限
  4 MiB（覆盖 brotli 默认 22 位窗口与 zstd 常用级别），App 内 brotli 16 MiB、zstd
  8 MiB（RFC 9659 对 HTTP 的上限）；超出直接报错，原样显示。zstd 字典帧不支持。
- deflate 截断：`flate2` 的读取器把未结束的流当成正常结束，改用底层
  `Decompress` 判断是否读到最终块，完整正文截断即报错。
- 抓包：存的仍是线上字节。HAR 导出 `content.text` 用解压后内容（`size` 为解压后
  长度、`compression` 为节省字节），解不开的照旧 base64 并在 `comment` 写原因。
  检查器在 App 进程里调无状态 FFI `networkcore_ios_decode_body`（桌面直接调 Rust
  `capture::decode::decode_body`），不在扩展里解，四种编码在所有平台一致。
- 脱敏：压缩正文先解压再脱敏（原来压缩体里的凭据会原样进导出）；有字段被遮盖时
  导出的是遮盖后的明文，`Content-Encoding` 改名为
  `X-AnixOps-Decoded-Content-Encoding`。
- 改写：规则读响应时仍发 `Accept-Encoding: identity`；源站仍返回压缩体时先解压
  再交给规则，去掉 `Content-Encoding` 按明文发回；解不完整（超 1 MiB、窗口超限、
  损坏）时保持原样。
- 测试：四种编码的样本与叠加编码、截断、损坏、1 KiB → 1 GiB 的炸弹（断言内存与
  输出上限）；`cargo fuzz` 目标 `decode_body`。

## 3. 流式

- 进行中的请求：头部到达即入抓包列表（`state: in_progress`），正文边到边增，
  结束时 `ended_at_ms` 落定；`capture_requests` 用已有的 `since_seq` 增量拉取，
  另加 `updated_since` 让客户端刷新进行中的条目。
- SSE：按事件（空行分隔）解析并记录 `id`/`event`/`data` 与时间戳，每个响应最多保留
  最近 256 个事件、64 KiB，超出丢最旧的并计数；原始字节照旧边到边转发，不增加延迟。
- 大正文：无规则读的正文已经边到边转发；抓包留前 64 KiB 并记总长不变。
- 规则命中但因流式被跳过（SSE、升级、超 1 MiB）时，抓包条目写
  `skipped_rules`，检查器显示「改写未生效：流式响应」。取舍见 D3。
- 门槛：SSE 长连接 10 分钟、每秒 50 事件，峰值内存增量 ≤ 1 MiB/连接；抓包门槛不变。

## 4. WebSocket

- HTTP/1.1 `101 Switching Protocols` 之后按 RFC 6455 解帧（两方向、去掩码、分片
  重组、控制帧），permessage-deflate（RFC 7692）在内核解压后记录；原字节照旧转发，
  不重新编码（除非 D2 选了可改写）。
- 每条消息记方向、类型（text/binary/ping/pong/close）、长度、时间戳与前 4 KiB；
  每个连接最多保留最近 512 条、256 KiB，超出丢最旧的并计数。close 记码与原因。
- 帧解析失败时停止解析、继续原样转发，不断连。
- HTTP/2 扩展 CONNECT（RFC 8441）仍不宣告；以后需要再开。
- 测试：RFC 6455 示例帧、分片、超长帧、掩码、deflate 上下文接管与不接管；与
  `tokio-tungstenite` 端到端互通；内存上限测试。

## 5. HTTP/2 帧视图

在解密后的明文字节流上旁路解析帧头（9 字节），记录每个连接两方向的帧时间线：类型、
stream、flags、长度，以及 SETTINGS 键值、WINDOW_UPDATE 增量、RST_STREAM 与 GOAWAY
错误码、PING 载荷。HEADERS/DATA 只记元数据（头部内容已经在请求里，不做第二份 HPACK
解码）。每个连接最多 1024 帧（环形），新增 `capture_h2_frames {connection}`。

- 测试：用 `h2` 两端互发，断言时间线顺序与字段；畸形帧不影响转发。

## 6. HTTP/3 真正终结

在用户态终结 QUIC（`quinn` + `h3`），对 App 发自签叶证书、对源站开 QUIC 客户端，
逐请求走同一改写钩子。代价：`h3` 仍是 0.0.x，接口不稳；每个 QUIC 连接要拥塞控制和
重传缓冲，iOS 上很难守住 50 MB；还需要逐包转发路径改成终结路径。条目 1 已经让解密
不再漏 HTTP/3 流量，这一项只在需要「看到 App 真的用的是 HTTP/3」时才有价值。见 D1。

## 用户决定（2026-11-15）

- **D1 HTTP/3**：只做条目 1 的自动回落 TCP，不终结 QUIC；条目 6 不做。
- **D2 WebSocket**：只看不改，插件不能改写消息。
- **D3 流式与正文改写冲突**：保持流式，跳过命中的正文规则，检查器提示「改写未生效：
  流式响应」。
