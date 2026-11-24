# 性能与长稳 CI

性能指标只在 GitHub Actions 上测量（见 [CI/CD policy](ci-cd-policy.md)）。下表是可脚本化的门槛：任何一项不达标，对应 job 失败。

| 指标 | 门槛 | 工具 | Workflow / Job | 何时运行 |
| --- | --- | --- | --- | --- |
| R2 规则决策 | 1 万条规则，单次决策 p99 ≤ 50 µs | `crates/config-core/examples/rule_bench.rs` | `perf.yml` / Rule decision benchmark | 改动 config-core 或引擎的 PR、手动 |
| F2 并发连接 | 5000 条 TCP 同时建立并各回显 1 字节（PR 测 redirect、ss2022；手动 `scale_outbounds=all` 测全部 9 种出站，门槛相同） | `tunnel_bench scale` | `perf.yml` / Tunnel scale | 同上 |
| F3 UDP 会话 | 10 万个 UDP 流同时打开，进程 RSS ≤ 300 MiB | `tunnel_bench udp-sessions` | `perf.yml` / Tunnel scale | 同上 |
| F7 长稳 | 预热后 RSS 斜率 ≤ 1 MiB/h，连接失败率 ≤ 0.1%，结束无残留流与 fd | `tunnel_bench soak` | `soak.yml` | 每周六 5.5 h（托管 runner）；24 h 手动选自托管 runner；改动 soak 本身的 PR 跑 30 min 冒烟（斜率门槛放宽到 20 MiB/h） |
| F9 桌面本地代理长稳 | Linux、macOS、Windows 各跑一次：本地代理（SOCKS5/HTTP，出站 Shadowsocks 2022）持续承受短连接、保持连接轮换与 4 MiB 突发；预热后 RSS 斜率 ≤ 1 MiB/h、描述符/句柄斜率 ≤ 10/h，连接失败率 ≤ 0.1%，负载停止 10 s 后无活动连接、描述符/句柄不超过负载前 + 8 | `crates/engine-embedded/examples/proxy_soak.rs` + `.github/scripts/proxy_soak.py` | `soak.yml` / Proxy soak | 每周六每个平台 2 h（托管 runner）；手动按 `hours`；改动 proxy soak 本身的 PR 跑 20 min 冒烟（斜率门槛放宽到 20 MiB/h、200/h） |
| I3 HTTPS 解密成功率 | `testdata/capture-sites.txt` 的 60 个真实站点，直连可达的站点里，经隧道解密后状态码类别一致且交换进了抓包（HAR）的 ≥ 95% | `capture_bench` + `.github/scripts/capture-gates.py` | `capture-gates.yml` | 改动 engine-embedded / mitm-policy / netstack 等的 PR、main、手动；`release.yml` 发布前必跑 |
| I4 抓包吞吐 | 同一隧道进程里抓包开 / 关相邻成对下载 256 MiB 共 10 对（raw TCP、明文 HTTP、HTTPS 解密），每对吞吐比的中位数下降 ≤ 15% | 同上 | 同上 | 同上 |
| I4 抓包内存 | 抓包关 / 开各 3 个新进程，600 条短连接（16 并发，默认 2 MiB 预算），峰值 RSS（VmHWM）中位数增加 ≤ 10 MiB | 同上 | 同上 | 同上 |
| F8 短连接风暴 | 抓包关，600 条短连接（raw / HTTP / HTTPS 解密各 200，16 并发）峰值 RSS（3 个进程中位数）≤ 32 MiB；每阶段结束 2 s 后没有仍打开的转发 | 同上 | `capture-gates.yml` | 同 I3/I4 |
| C4 IPC 模糊测试 | `networkcore_ios_runtime_control` 不 panic、回答必为 JSON 对象、错误码在文档集合内 | `crates/engine-embedded/fuzz` 的 `runtime_control` | `ci.yml` / HTTP/2 MITM fuzz | 每个 Rust PR（30 s）、main（60 s） |
| C5 入站握手模糊测试 | VLESS、Trojan、VMess、Shadowsocks AEAD / 2022 服务端读取客户端首包不 panic、不越界、不超 2 GiB RSS；VLESS、Trojan 一半输入带有效凭据，覆盖认证后的命令、地址与附加字段解析 | `crates/engine-inbound/fuzz` 的 `inbound_handshakes` | `ci.yml` / HTTP/2 MITM fuzz | 每个 Rust PR（30 s）、main（60 s） |
| C6 导入文本模糊测试 | 订阅与分享链接（含随附分流）、TOML 配置文档、规则行与规则集、Loon 插件的解析不 panic、不超 2 GiB RSS | `crates/node-import/fuzz` 的 `subscription_import`、`config_document`、`rule_text`、`loon_plugin`（字典 `fuzz/dict/import_text.dict`） | 同上 | 同上 |

R2 的门槛是绝对值，而托管 runner 的 CPU 快慢相差约 1.5 倍：PR 上 head 超出门槛时，会在同一台 runner 上再测 base；head 不比 base 慢 15% 以上就只告警（runner 偏慢，不是回归），否则失败。

`perf.yml` 的隧道基准（base 对 head）仍只做信息展示，不设门槛。同一 job 的 Multi-core 步骤在同一台 runner 上对 head 跑 1 线程与 4 线程（`tunnel_bench run --workers`），summary 里的 “Tunnel threads” 表给出多核收益（8 流下载）与代价（每 GiB CPU、内存、空闲唤醒）。

## 说明

- 抓包门槛（I3/I4）：隧道进程打开 TUN 后，设备被移进 network namespace `capbench`，客户端（curl、raw TCP 读取）在里面跑，隧道自己的出站留在宿主。解密成功率用生产上游 TLS 客户端（webpki 根）；吞吐与内存用本地源站。`--diagnose` 额外跑最小预算和 glibc `mmap_threshold=32768` 对照，用来区分预算内数据和堆碎片，不设门槛。

- 规则决策走 `RoutingModel::decide_indexed`：DOMAIN 与 DOMAIN-SUFFIX 规则用哈希表查找，其余规则按顺序尝试，结果与逐条 `decide` 完全一致（`crates/config-core/tests/rule_index_contracts.rs`）。基准里 10% 的查询不命中任何规则，是最坏情况（走完全部非域名规则、解析一次域名、落到 FINAL）。
- UDP 流上限由配置 `limits.max_udp_flows` 决定（默认 iOS 256，iOS 内存预算不变；Android 与桌面 4096）；测 10 万流时基准自行调高。表满时先清掉已结束的流，再一次性关闭一批（上限的 1/16）空闲至少 15 s 的流，空闲最久的先关；没有空闲流时，占用超过表 1/4 的应用套接字让出它最不活跃、且至少 2 s 没有数据报的流；都不行才丢弃新流，并在 250 ms 内不再扫描，所以满表时不是每个数据报都遍历全表。关闭的流计入 `udp_evicted`，丢弃计入 `udp_dropped`。
- TCP 连接上限由 `limits.max_tcp_connections` 决定（默认 iOS 128、Android 512、桌面 1024，系统代理用同一个值）。满额时新连接关闭最久没有载荷、且空闲至少 30 s 的连接并接替它（`tcp_evicted`），只有所有连接都在活跃时才拒绝（`tcp_rejected`）。`tunnel_bench`、`capture_bench` 显式设置上限，门槛不受默认值变化影响。
- 文件描述符预算：每个中继连接或 UDP 流至少占一个描述符（系统代理连接占两个）。Linux 默认软限制 1024、macOS 由 launchd 启动时常为 256，都低于桌面默认上限，描述符先耗尽时新连接在出站 connect 就以 EMFILE 失败，空闲回收根本不会触发。所以 Linux、Android、macOS、iOS 上运行时启动隧道或系统代理时把 `RLIMIT_NOFILE` 软限制一次性提到硬限制（Apple 平台不超过 `kern.maxfilesperproc`），再把 TCP、UDP 上限（配置值和默认值都算）压到预算内：预留描述符的 1/4（64 到 512 之间）给 DNS、规则集、健康检查和监听器，TCP 不超过余下的一半，UDP 不超过 TCP 剩下的。硬限制只有 1024 时为 TCP 384、UDP 384。Windows 没有这一限制，保持配置值。`tunnel_bench`、`capture_bench` 直接构造 `TunnelSettings`，不经过这一步。
- 隧道线程：配置 `limits.worker_threads`（0 = 按平台默认）。iOS、Android 恒为 1 个线程（current-thread runtime，iOS 网络扩展有硬内存上限；这两个平台的构建不含 tokio 多线程调度器）；macOS、Windows、Linux 默认每个 CPU 一个工作线程，最多 4 个，上限 16。用户态 TCP/IP 栈仍是一个任务，多线程分摊的是各条流的转发、加解密和出站 I/O。`tunnel_bench` 的 `run`、`scale`、`soak` 默认跟产品一样按平台取值，所以 F2、F3、F7 门槛测的是桌面默认的多线程运行时；`capture_bench`（I3/I4/F8）固定 1 线程，与此前结果可比。
- 长稳的 RSS 斜率是去掉前 15% 采样后的最小二乘斜率，每 60 s 采样一次；完整曲线在 job summary 和 artifact `tunnel-soak` 里。
- 24 h 长稳需要自托管 runner，准备步骤见 [manual-intervention.md](manual-intervention.md)。
- 手动调整门槛：`perf.yml` 的 `max_rule_p99_us`、`concurrent`、`udp_flows`、`max_udp_rss_mb` 输入（`scale_outbounds` 只选出站，不改门槛）；`soak.yml` 的 `hours`、`max_slope_mb_per_h` 输入。

## 首次结果（2026-11-13，GitHub 托管 ubuntu runner）

- R2：1 万条规则 p99 约 35 µs（runner 之间约有 2 倍波动）。
- F2：5000 并发全部回显成功，redirect / ss2022 回显 p99 约 3 ms，隧道进程约 52 KiB/连接。
- F3：10 万 UDP 流 RSS 222 MiB（约 2.2 KiB/流）。此前每流两个任务加一个 tokio mpsc 通道，是 4.2 KiB/流、417 MiB；现在每流一个任务、按需分配的队列，打开流的 future 用完即释放。该数字用的是不带缓冲的模拟出站，不含真实出站每流的接收缓冲；真实出站（直连、Shadowsocks、SOCKS5、VMess、Hysteria2、TUIC）此前每流常驻 64 KiB，现在空闲时不持有接收缓冲（读取时借用每线程一块的 64 KiB 临时缓冲），见 `crates/engine-outbound/README.md`。

## 全出站 5000 并发（2026-11-23，GitHub 托管 ubuntu runner）

手动触发 `perf.yml`，输入 `scale_outbounds=all`，其余输入为默认值（`concurrent=5000`）。门槛与 PR 上的 F2 相同，没有放宽：5000 条 TCP 连接全部建立、每条都回显成功，任何一种出站不达标 job 就失败。

- Run：[Tunnel perf #207](https://github.com/AnixOps/AnixOps-core/actions/runs/45188721934)，job “Tunnel scale (5000 conns, 100k UDP flows)”，结论 success；每种出站的 JSON 报告在该 run 的 artifact `tunnel-scale` 里（保留 14 天，数字也打印在 job 日志的 “Concurrent connections” 步骤中，日志随 run 保留）。
- 被测代码：commit `616c2ca`，即 [#271](https://github.com/AnixOps/AnixOps-core/pull/271) 的分支头，squash 合并为 main 上的 `e461eeb`，代码相同。
- 方法：`tunnel_bench scale`，每种出站的服务端是基准进程内起的本机服务端（TLS 用自签证书，客户端按 SHA-256 固定），隧道端按产品同样的 JSON 设置从出站注册表构建客户端；WireGuard 的对端是 boringtun 加第二个隧道终结 TCP。只测隧道进程的 CPU 与内存。每连接内存 = （5000 条全开时 RSS − 开始前 RSS）÷ 5000。

| 出站 | 建立 | 回显成功 | 回显 p50 | 回显 p99 | 回显最大 | 全部建立耗时 | 每连接内存 | 关闭后残留连接 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| redirect（无协议，隧道自身开销） | 5000 | 5000 | 2.56 ms | 4.74 ms | 6.15 ms | 0.64 s | 54.5 KiB | 0 |
| Shadowsocks 2022 | 5000 | 5000 | 2.85 ms | 5.15 ms | 6.79 ms | 0.70 s | 56.0 KiB | 0 |
| Trojan（TLS） | 5000 | 5000 | 2.99 ms | 5.44 ms | 6.85 ms | 1.18 s | 62.4 KiB | 0 |
| VLESS（TLS） | 5000 | 5000 | 2.89 ms | 5.46 ms | 6.60 ms | 1.18 s | 62.2 KiB | 0 |
| VLESS（REALITY） | 5000 | 5000 | 2.99 ms | 5.09 ms | 7.15 ms | 1.79 s | 65.1 KiB | 0 |
| VMess | 5000 | 5000 | 3.06 ms | 5.78 ms | 8.23 ms | 0.79 s | 73.0 KiB | 0 |
| SOCKS5 | 5000 | 5000 | 2.81 ms | 5.11 ms | 6.50 ms | 0.73 s | 54.4 KiB | 0 |
| HTTP CONNECT | 5000 | 5000 | 2.77 ms | 5.22 ms | 6.42 ms | 0.75 s | 54.3 KiB | 0 |
| WireGuard | 5000 | 5000 | 15.7 ms | 70.5 ms | 102 ms | 1.00 s | 72.6 KiB | 0 |

- 9 种出站都是 5000/5000 建立、5000/5000 回显，`connect_failed`、`echo_failed`、`tcp_rejected` 均为 0。
- 除 WireGuard 外，回显 p99 在 4.7–5.8 ms，每连接 54–73 KiB；带 TLS 的出站建立更慢（握手 CPU：Trojan / VLESS 约 2.4 s、REALITY 约 4.4 s 累计 CPU，无协议约 1.0 s）。
- WireGuard 回显 p99 约 70 ms：5000 条 TCP 都要经过出站自己的用户态 TCP/IP 栈再封进同一条 UDP 隧道，对端也是用户态栈；多出的延迟应来自这两层栈的排队（推断，尚未单独剖析），没有连接失败。
- 范围：这是本机回环上的容量与正确性测试，不代表真实网络的吞吐或延迟；ANX 协议不在本仓库，未包含在内。
- 复现：在本仓库 Actions 里手动运行 “Tunnel perf”，`scale_outbounds` 填 `all`；或按 `crates/engine-embedded/examples/tunnel_bench.rs` 开头的说明在 Linux 上建 TUN 后运行 `tunnel_bench scale --outbound <名称>`。

## 抓包门槛首次结果（2026-11-14，GitHub 托管 ubuntu runner）

- I3：60/60 站点解密成功（100%）。压测中发现负载下 ClientHello 晚于 100 ms 或被分段时漏解密，已修（80/443 首包等待 1 s 并读完整 TLS 记录）。
- I4 吞吐：raw −2.7%、HTTP −0.3%、HTTPS 7.3%（同进程交替测；分进程测时 runner 波动可达 ±15%，不可用）。
- I4 内存：峰值 87.7 → 93.6 MiB（+5.9 MiB）。最初是 +14.2 MiB，多出的部分是成倍增长的抓包缓冲留下的堆碎片；TCP 抓包改为 ≤16 KiB 分片、body 一次性分配后降到 +5.9 MiB。
- 抓包关闭时 600 条短连接也会把峰值推到约 88 MiB，见下节 F8。

## 短连接风暴 F8（2026-11-14，GitHub 托管 ubuntu runner）

- 修复前：抓包关 600 条短连接峰值 87.7 MiB，每批 200 条结束 2 s 后仍全部挂着（约 7 s 才归零）。原因是 netstack 的 `poll_shutdown` 要等套接字到 CLOSED：隧道先发 FIN 的连接要等对端 FIN 加 smoltcp 10 s TIME-WAIT，期间整条转发（出站、TLS、缓冲）和套接字的两个窗口都不释放。
- `poll_shutdown` 改为 FIN 排队即完成、TIME-WAIT 保留 1 s：41.7 MiB，转发 2 s 内全部释放；一批里的套接字大多同时停在 1 s 的 TIME-WAIT 里。
- TIME-WAIT 保留 100 ms（只等 smoltcp 的延迟 ACK）：抓包关 22.7 MiB、抓包开 25.1 MiB，门槛 32 MiB。
