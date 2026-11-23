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
| 2 | 内核统一解压 gzip/deflate/br/zstd | 中高：检查器、导出、改写都受益 | 低（压缩炸弹要限） | #239（内核）；客户端另开 |
| 3 | 流式：进行中请求可见、SSE 事件、流式跳过提示 | 中高：AI/推送类 App | 中（内存） | #241（内核）；客户端另开 |
| 4 | WebSocket 消息查看 | 中 | 中（内存、permessage-deflate） | #242（内核）；客户端另开 |
| 5 | HTTP/2 帧视图 | 中：排查流控、RST、GOAWAY | 低 | 本 PR（内核）；客户端另开 |
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

- 进行中的请求：请求头读到即入抓包（`state: in_progress`，`seq` 为 0），响应开始
  流式时刷新（状态码、响应头），结束时 `ended_at_ms` 落定并拿到 `seq`。
  `capture_requests` 原有的 `since_seq` 语义不变（只列已结束的，每条一次，旧客户端
  不受影响）；新增 `since_rev`：列出 `rev` 之后变过的条目（含进行中），按最后变更
  排序，回答带 `last_rev`，行里带 `state`、`rev`、`message_count`、`rules_skipped`。
- SSE（`text/event-stream`，无内容编码时）：转发的同时按 WHATWG「解释事件流」解析
  （BOM、CR/LF/CRLF、`data` 以 LF 拼接、`id` 跨事件保留、注释与未知字段忽略），
  每个事件记 `event`（`label`）、`id`、时间、数据前 4 KiB 与原长。每个交换最多保留
  最近 512 条、数据合计 64 KiB，超出丢最旧的并计数（`seen` / `dropped`）；单行最多
  看 4 KiB + 256 字节，其余只计长度，所以长连接、超长事件内存都有上界。
  HTTP/1.1 由透传改为按原分帧（chunked / 定长 / 到关闭）逐块转发并立即 flush，
  连接在流结束后可继续复用；未开抓包时仍走原透传，不影响吞吐门槛。HTTP/2 同理。
  被 gzip 等编码的事件流不解析，只照常转发。
- `capture_exchange {id, index, since_message}`：取一个交换及其 `since_message`
  之后的事件，检查器据此增量追加。会话保存（`.anxcap`）把事件写进连接记录末尾的
  扩展区（tag 1），旧会话照常读。
- 大正文：无规则读的正文已经边到边转发；抓包留前 64 KiB 并记总长不变。
- 规则命中但没有执行（SSE、升级、超 1 MiB 的 `too_large`）时，条目写
  `rules_skipped: true`，检查器显示「改写未生效：流式响应」（超限时为「正文过大」）。
  取舍见 D3。
- HTTP/2 一条连接上同时为规则持有的正文合计不超过 2 MiB（`MAX_HELD_BODY_BYTES`，
  每个持有的正文在规划时大约还有两份拷贝）：放不下的那条不等待（等待的流占着流控窗口，
  会卡住持有额度的流），按原样转发，条目写 `note: "busy"`、`rules_skipped: true`。
- 整个引擎所有解密连接同时为规则持有的正文另有总上限（`MAX_ENGINE_HELD_BODY_BYTES`，
  iOS 6 MiB，其他平台 16 MiB）：每条 HTTP/2 连接的额度从中扣，HTTP/1.1 在读正文前按
  `Content-Length`（不超过 1 MiB；分块、读到关闭或带 `Content-Encoding` 的按 1 MiB）预留。
  预留不到时同样不等待：HTTP/2 这条流按原样转发，HTTP/1.1 这条消息按原样转发并且之后整条
  连接透传（与 `too_large` 相同），条目写 `note: "busy"`、`rules_skipped: true`。
  多条连接同时读正文时内存因此有界，不会叠加到 Network Extension 的内存上限。
- 源站 HTTP/2 连接发 GOAWAY 或关闭时，App 一侧也优雅关闭：App 收到 GOAWAY，
  进行中的流继续转完（最多 `idle_timeout`），源站没有处理的流回 `REFUSED_STREAM`
  （App 可以在新连接上安全重试），源站 RST_STREAM 的原因原样转给 App。
- HTTP/1：头部里不是 UTF-8 的字节（GBK / Latin-1 文件名）原样转发；裸 LF 行尾、
  折行头、重复且相同的 `Content-Length` 照常读取；读不懂的请求头或响应头（含
  `ICY 200 OK`）不再断开连接，而是从这里起原样透传，响应条目写 `note: "unparsed"`；
  值不一致的 `Content-Length` 回 502 后关闭（RFC 9112 §6.3）。显式代理形式的请求目标
  （`GET http://…`、`OPTIONS *`）不接管。chunked 正文的分块行、扩展与 trailer 一并
  计入上限（超出按 `too_large` 原样转发），分块大小只接受至多 16 位十六进制数。
- 门槛：内存上界由单元测试卡住（2 万条事件，相当于每秒 50 条跑近 7 分钟，单交换
  事件内存 ≤ 64 KiB + 512 × 64 字节，且与预算记账一致）；端到端测试覆盖 chunked
  事件跨块、事件在流未结束时就到达 App、`since_rev` 进行中 → 结束、规则跳过提示。
  抓包门槛（解密率、吞吐、内存、F8）不变。

## 4. WebSocket

- 开抓包时，HTTP/1.1 `101 Switching Protocols`（`Upgrade: websocket`）之后不再用
  `copy_bidirectional` 透传，而是两方向各自读、原样写出并 flush，再交给
  `capture/websocket.rs` 按 RFC 6455 解帧（去掩码、分片重组、控制帧可插在分片之间）。
  只读不改（D2），原字节不重新编码；未开抓包仍走原透传。
- permessage-deflate（RFC 7692）：按 `101` 响应的 `Sec-WebSocket-Extensions`
  取协商结果，解压后记录；默认跨消息共享窗口，`server_no_context_takeover` /
  `client_no_context_takeover` 分别让下行 / 上行每条消息后重置。每个方向只在出现
  压缩消息时才建一个 inflate 状态（32 KiB 窗口）。一条消息解压超过 1 MiB 或解压出错
  时，该方向停止解压（窗口已失），之后的压缩消息原样记录并标 `permessage-deflate`。
- 每条消息记方向、类型（text/binary/ping/pong/close）、原长、时间与前 4 KiB；数据帧
  只复制要保留的前 4 KiB，超出部分只计长度。close 记码（`code`）与原因（`label`）。
  与 SSE 共用 `capture/stream.rs` 的有界模型：每个交换最多 512 条、数据合计 64 KiB，
  超出丢最旧的并计数；`capture_exchange` 增量取，会话保存同一扩展区。
- 帧解析失败（未知 opcode、RSV 位、控制帧过长或分片、无消息的续帧等）时停止解析、
  继续原样转发，不断连。
- HTTP/2 扩展 CONNECT（RFC 8441）仍不宣告；以后需要再开。
- 测试：RFC 6455 §5.7 全部示例（任意切分、7 字节一块）、close 码与原因、RFC 7692
  §7.2.3 示例（共享窗口、分片、stored 块）、不接管上下文时的重置、压缩炸弹只停解压
  不停解析、协议错误；端到端用手写帧（RFC 示例字节）走完整 MITM 中继，验证 App
  收到的字节不变、事件被记录、关闭后交换结束。

## 5. HTTP/2 帧视图

开抓包时，`h2` 连接的两条 TLS 链路（App ↔ 中继、中继 ↔ 源站）各包一层
`FrameTap`：字节原样读写，同时在明文上旁路解析帧头（9 字节，客户端一侧先跳过
24 字节的连接前言，对不上就停止解析）。每帧记链路（`app` / `origin`）、方向
（`up` 朝源站 / `down` 朝 App）、类型、flags、stream、长度，以及
RST_STREAM / GOAWAY 错误码、WINDOW_UPDATE 增量、GOAWAY 最后 stream、SETTINGS 条数。
HEADERS/DATA 只记元数据（头部内容已经在请求里，不做第二份 HPACK 解码），只看载荷
前 8 字节，不缓冲。每个连接保留最近 512 帧（每帧按 32 字节计入抓包预算），新增
`capture_h2_frames {id, since}`；会话保存写进连接记录扩展区（tag 2）。未开抓包时
`FrameTap` 只是直通。

- 测试：帧头任意切分（1/2/7/9/13/4096 字节一块）结果一致、各类型字段、前言不符即
  停、保留上限；`h2` 端到端（App 与源站两条链路、两个方向的 SETTINGS/HEADERS、
  上传的 DATA、`since` 增量）；会话往返。

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
