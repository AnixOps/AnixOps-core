# 节点体检（engine-embedded `checkup`）

节点体检是用户在客户端里手动发起的一次节点测量，经引擎给该节点建的同一个出站完成，结果供客户端展示和导出。
测量口径与 AnixOps Speedtest 一致，两边的数字可以直接对比。用词遵守 AnixOps Design `guidelines/terminology.md`。

## 已实现（第一步）

`engine_embedded::checkup`（`local-proxy` feature）：

- `run_checkup(config, options)`：用一个引擎配置信封建出站，在自己的 current-thread runtime 上跑完，和 URL 延迟测试一样。
  `checkup(outbound, options)` 在调用方的 runtime 上跑。
- **延迟**：`samples`（1–20，默认 5）轮，每轮一次“连接 + TLS 握手”（`handshake_url`，默认 `https://1.1.1.1/`）和一次 HTTP 请求
  （`latency_url`，默认 `https://www.gstatic.com/generate_204`）。握手必须经节点完成一次真实往返，所以本地接受连接但出不去的节点会失败。
  第一轮握手单独报为冷启动（`cold_handshake_ms`，含协议自己的握手），后面各轮的中位数为 `warm_handshake_ms`；
  另有握手与请求的中位数、请求抖动（相邻成功样本差的平均，RFC 3550 口径）和两者的失败率。`handshake_url` 写 `http://` 时按 URL 延迟测试测量。
- **吞吐**（`throughput`，可选）：`connections`（1–16，默认 4）条并行下载 `download_url`（默认 Cloudflare `__down`，25 MB 一块）持续 `duration_ms`
  （1–30 s，默认 8 s），记录每秒曲线、平均与峰值；下载期间每 `probe_interval_ms`（≥100 ms，默认 500 ms）对 `latency_url` 发一次新连接请求，
  得到负载下延迟（中位数、P90、失败率），`bloat_ms` = 负载下 − 空闲。开始前丢弃一次请求再测 `idle_samples` 次空闲延迟（冷握手不计入基线）。
  `max_bytes` 大于 0 时到量即停（`capped`），用于按流量计费的节点。
- 结果是 `CheckupReport`（serde 序列化为 JSON）；失败只给固定代码（`timeout`、`connect_failed`、`tls_failed`、`not_http`、`http_status`），
  不含节点地址或响应内容。选项的未知字段一律拒绝。

## 网络行为

体检只在用户点击时运行，不定时、不自动。默认地址只有上面三个，客户端可以改；客户端接入时在 anixops-net
`docs/network-behavior.md` 写明“什么时候、发往哪里、带什么”。

## 后续步骤

1. 客户端接入：桌面 IPC 与 iOS / Android FFI 暴露 `run_checkup`，节点详情页加“节点体检”。
2. 上传方向与 HTTP/3：上传需要 POST 体；HTTP/3 走节点的 UDP 中继（`TcpOutbound::open_udp`），不支持 UDP 的协议报“不支持”而不是失败。
3. 服务可用性：用户自己提供检查规则（Speedtest 的规则格式，JSON），公开版不内置第三方服务名单（与“公开版不带预设”一致）。
4. 出口信息：出口地址与地区沿用现有查询；出口信誉查询要访问第三方，只在用户另行打开时运行。
