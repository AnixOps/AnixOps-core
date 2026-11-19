# 规则与策略组模型（M2）

本文件是 M2「规则与策略组模型」的设计说明与验收清单。规则与策略组是 `config-core` 的一等对象，桌面端经 `engine-singbox` 翻译为 sing-box `route`，iOS/macOS NE 内的 `engine-embedded` 直接调用同一模型的决策接口。两条路径共用一份快照夹具，防止行为分叉。

## 范围

- 规则：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`/`IP-CIDR6`（可带 `no-resolve`）、`GEOIP`、`IP-ASN`（AS 号，`13335` 或 `AS13335`，可带 `no-resolve`）、`GEOSITE`、`DST-PORT`（别名 `DEST-PORT`，单个端口或 `起-止`）、`SRC-IP`（别名 `SRC-IP-CIDR`，地址或网段，IPv6 可加方括号）、`IN-PORT`（入站监听端口，单个或 `起-止`）、`PROCESS-NAME`、`RULE-SET`（可带 `no-resolve`）、`SCRIPT`（规则脚本，不能放在逻辑规则里）、逻辑规则 `AND`/`OR`/`NOT`、`FINAL`。
- 逻辑规则采用 Surge 写法：`AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,443)),Proxy`、`NOT,((DOMAIN-KEYWORD,ads)),DIRECT`；子规则不带目标，可以嵌套（最多 8 层），`NOT` 只能有一个子规则。含 IP 子规则的逻辑规则按 IP 规则处理，可带 `no-resolve`。
- 策略组：`select`、`url-test`、`fallback`、`load-balance`（按目的主机一致性哈希）、`round-robin`（轮询）、`subnet`（按设备当前网络选目标，Surge `subnet` / 旧 `ssid` 组）。
- 目标：`DIRECT`、`REJECT` 系列（`REJECT`、`REJECT-NO-DROP`、`REJECT-DROP`、`REJECT-TINYGIF`，Loon `REJECT-IMG` 等同 `REJECT-TINYGIF`）、策略组 id、节点 id（保留名大小写不敏感）。
- 非目标：`USER-AGENT`、`URL-REGEX`、`relay` 组。

## 配置形状

```toml
profile = "default"
rules = [
  "DOMAIN-SUFFIX,google.com,Proxy",
  "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
  "GEOIP,CN,DIRECT",
  "FINAL,Proxy",
]

[[policy_groups]]
id = "Proxy"
type = "select"            # select | url-test | fallback | load-balance | round-robin
members = ["Auto", "hk-1", "DIRECT"]
default = "Auto"           # 仅 select

[[policy_groups]]
id = "Auto"
type = "url-test"
members = ["hk-1", "jp-1"]
url = "https://www.gstatic.com/generate_204"   # 默认值
interval_secs = 300                            # 默认值
tolerance_ms = 50                              # 默认值，仅 url-test
evaluate_before_use = false                    # 默认值，仅测速组

[[policy_groups]]
id = "ByNetwork"
type = "subnet"            # 没有 members，成员即 default 与各规则的目标
default = "Proxy"          # 必填：没有规则命中或网络未知时使用
network_rules = [
  { when = "SSID:Home", target = "DIRECT" },        # Wi-Fi 名，区分大小写
  { when = "BSSID:aa:bb:cc:dd:ee:ff", target = "DIRECT" },
  { when = "ROUTER:192.168.1.1", target = "DIRECT" }, # 默认网关
  { when = "SUBNET:10.8.0.0/16", target = "DIRECT" }, # 设备地址所在网段
  { when = "TYPE:CELLULAR", target = "Auto" },        # WIFI | WIRED | CELLULAR，也可写 CELLULAR
]
```

`rules` 或 `policy_groups` 任一出现时，`parse_config_document` 产出 `ParsedConfigDocument.routing`；未出现时为 `None`，现有 `routes` 默认动作不受影响。

## 校验规则

- 规则必须以且仅以一条 `FINAL` 结尾；错误信息带规则序号，不回显节点凭据。
- 目标解析顺序：`DIRECT`/`REJECT` 系列 → 策略组 id → 节点 id；策略组 id 不得与节点 id、保留名（含全部 `REJECT` 系列名字）重复。其他 `REJECT-*` 名字（`REJECT-200`、`REJECT-DICT` 等只在解密后才有意义的应答）不是分流目标。
- 组成员不能是任何 `REJECT` 策略；只有 `select` 与 `subnet` 可以包含其他组；`url-test`/`fallback`/`load-balance`/`round-robin` 成员只能是节点或 `DIRECT`；只有 `url-test` 可写 `tolerance_ms`；只有这四种测速组可写 `evaluate_before_use`。
- `subnet` 组必须有 `default`，不能写 `members` 与测速字段；`network_rules` 只能出现在 `subnet` 组，`when` 必须是上面五种前缀之一（`config.core.routing_group_network_rule_invalid`）。
- 组之间不得成环；重复成员按首次出现去重。
- 域名统一小写、去掉结尾点；`DOMAIN-SUFFIX` 去掉开头点，匹配自身与全部子域名；`DOMAIN-KEYWORD` 匹配包含该子串的域名。
- CIDR 归一化为网络地址（`10.1.2.3/8` → `10.0.0.0/8`）。

## 决策接口（engine-embedded 使用）

`RoutingModel::decide(&RouteQuery, &dyn RoutingEnvironment) -> RouteResolution`

- `RouteQuery { domain, ip, port, process }`：FakeIP/嗅探得到的域名、目的地址、目的端口（`DST-PORT`）与发起连接的本地进程名（`PROCESS-NAME`，大小写不敏感，平台无法得知时为空，规则不命中）。进程名的来源：桌面本地代理在 Linux、Windows、macOS 按客户端连接查系统表；包隧道只在 Linux 和 Windows 查（TCP 按连接两端、UDP 按应用绑定的本地地址，含 FakeIP 地址），macOS/iOS 的隧道在 Network Extension 里看不到其他进程的套接字、Android 不开放这些表，所以隧道流量在这三个平台上不命中 `PROCESS-NAME`，客户端应提示。只有配置用到 `PROCESS-NAME`（含规则集里的）时才查，在阻塞线程上进行。
- `RoutingEnvironment` 提供 GeoIP 查询（`geoip_matches`）、GeoSite 查询（`geosite_matches`）、DNS 解析、select 当前选择、成员测速结果；全部方法有保守默认值，`StaticRoutingEnvironment` 即无运行时状态。
- `RoutingModel::route_to` 跳过规则直接解析一个目标（全局模式），`group_member` 给出组当前选择，`target_named` 按规则目标的方式解析名称。
- `RuleMatcher` 的 `Display` 输出不带目标的规则行，供连接列表显示命中规则。
- 第一条不带 `no-resolve` 的 IP 规则触发一次解析，之后所有 IP 规则使用解析结果，与 sing-box `resolve` 动作一致。解析失败时连接被拒绝（`RouteMatch::ResolveFailed`），与 sing-box 一致，不会落到 `FINAL`；需要远端解析的域名应放在 IP 规则之前用域名规则分流，或给 IP 规则加 `no-resolve`。engine-embedded 里这次解析走运行时配置的 `dns` 设置（`PolicyResolver`，见 `embedded-dns.md`「DNS 泄露核对」），不用系统解析器。
- 组选择：`select` 用环境选择 → `default` → 第一个成员；`url-test` 取延迟最低的成员（无结果时取第一个），但当前成员（`RoutingEnvironment::url_test_current`）仍有结果且不比最快的慢超过 `tolerance_ms` 时保持不变；`subnet` 按顺序取第一条与 `RoutingEnvironment::network` 相符的规则的目标，都不符或网络未知时取 `default`；`fallback` 取第一个有测速结果的成员（都没有时取第一个）；`load-balance` 在有测速结果的成员（都没有时为全部成员）中按目的域名（无域名时为 IP）做 rendezvous 哈希（FNV-1a），同一主机固定到同一成员，某成员下线时只有原本落在它上面的主机会换成员；`round-robin` 在同样的成员中按 `RoutingEnvironment::round_robin` 计数轮流选择。`group_member`（策略页显示）没有连接时返回第一个健康成员。
- `RouteResolution` 返回命中规则序号或 `FINAL`、规则目标、经过的组路径、最终 `Direct/Reject/Node(id)` 与解析出的地址，可直接用于诊断页。

## sing-box 翻译（engine-singbox）

`render_sing_box_route(&RoutingModel) -> SingBoxRouteFragment { outbounds, route }`

- 规则一对一按序翻译为 rule action（sing-box 1.11+）：`domain`、`domain_suffix`、`domain_keyword`、`ip_cidr`、`rule_set`；`REJECT` 为 `action: reject`，其他为 `action: route` + `outbound`。
- 第一条需要解析的 IP 规则前插入 `{ "action": "resolve" }`。
- `GEOIP,CN` 翻译为 `rule_set: ["geoip-cn"]`，并生成指向 `SagerNet/sing-geoip` 的远程 `.srs` 规则集，经 `direct` 下载。
- `FINAL,<目标>` 写入 `route.final`；`FINAL,REJECT` 追加无条件 `reject` 规则，`final` 为 `direct`。
- `select` → `selector`；`url-test` → `urltest`；`fallback` → `urltest` 且 `tolerance = 65535`。
- 片段只含策略组出站与 `route`；调用方负责节点出站（tag 为节点 id）和 `direct` 出站。

## 已知差异

- sing-box 没有按顺序回落的 fallback 组。翻译结果首次选择的是最快成员，之后只在当前成员失败时切换；`engine-embedded` 实现严格按顺序回落。快照用无测速状态的环境，两边都取第一个成员。
- sing-box 不对目的域名做大小写和结尾点归一化，决策接口会归一化；快照中对应用例标记 `engine_only`，不参与 sing-box 比较。
- 组内 `REJECT` 暂不支持，因为 sing-box 1.13 起移除了 `block` 出站。

## 快照夹具与验收

夹具位于 `testdata/routing-snapshot/`：

| 文件 | 校验方 |
| --- | --- |
| `config.toml` | 两侧共用的输入 |
| `decisions.json` | `crates/config-core/tests/routing_contracts.rs`：静态与带运行时状态两种环境下的逐条决策 |
| `sing-box-route.json` | `crates/engine-singbox/tests/route_contracts.rs`：完整 sing-box 片段 |

修改路由语义时必须同时更新两个快照。验收标准：上述测试在 GitHub Actions 全矩阵中通过。

## 真实 sing-box 等价性测试

CI job `Routing equivalence (sing-box)` 下载最新 sing-box 正式版和 `geoip-cn.srs`，运行 `crates/engine-singbox/tests/route_equivalence.rs`：

- 用 `render_sing_box_route` 渲染夹具，节点和 `direct` 都换成本地 SOCKS5 mock，GeoIP 规则集改为本地文件，夹具 DNS 由 sing-box `hosts` DNS server 提供，整个测试不访问外网目的地。
- 先 `sing-box check`，再 `sing-box run`，把 `decisions.json` 中所有静态用例经 mixed 入站逐条发出；每条用例使用唯一目的端口，收到该端口的 mock 即 sing-box 选中的出站，`REJECT` 要求没有任何 mock 收到。
- 结果与 `RoutingModel::decide` 的快照不一致即失败，并输出 sing-box 日志。带运行时状态（`live`）的用例依赖 select 选择和测速结果，不在此测试中比较。
- 未设置 `NETWORKCORE_SING_BOX_BIN` 时（普通 workspace 测试），该测试没有可比较的对象，直接返回；专用 job 设置 `NETWORKCORE_REQUIRE_SING_BOX_EQUIVALENCE=1`，缺少二进制会失败。

## 订阅导入（config-core `routing_import`）

`import_subscription_routing(content, &nodes) -> ImportedRouting { routing, diagnostics }` 从订阅原文再读一遍规则和策略组，`nodes` 是同一份订阅解析出的节点：

- Surge/Loon：`[Proxy Group]` 行 `名称 = 类型, 成员, 成员, url=..., interval=..., tolerance=..., evaluate-before-use=true`，`[Rule]` 段规则行。Surge `subnet` 组（`default = A, "SSID:Home" = DIRECT, "TYPE:CELLULAR" = B`）与旧 `ssid` 组（`default = A, cellular = B, "Home" = DIRECT`，裸名按 SSID）导入为 `subnet`；不认识的键、目标未导入的规则跳过并告警，`default` 无法导入时整组跳过。
- Clash YAML：`proxy-groups`（`name`/`type`/`proxies`/`url`/`interval`/`tolerance`）与 `rules`，`MATCH` 视为 `FINAL`。
- 成员和规则目标按代理名称映射到节点 id，策略组 id 保留原名称；`REJECT`、`REJECT-NO-DROP`、`REJECT-DROP`、`REJECT-TINYGIF`（Loon `REJECT-IMG`）保留各自含义，其余 `REJECT-*`（Loon `REJECT-200`、`REJECT-DICT`、`REJECT-ARRAY`、`REJECT-VIDEO`）视为 `REJECT`；规则只保留 `no-resolve` 选项。
- 导入的规则类型：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`/`IP-CIDR6`、`GEOIP`、`IP-ASN`、`GEOSITE`、`DST-PORT`/`DEST-PORT`、`PROCESS-NAME`、`RULE-SET`、Surge `DOMAIN-SET` 和 `AND`/`OR`/`NOT`。`GEOSITE,<c>` 与 `GEOIP,<CC>` 原样保留，由客户端提供 `geosite-<c>`、`geoip-<cc>` 规则集。
- 规则测试与命中计数：运行时控制 `test_route` 按当前规则判定一条假想连接（`host` 为域名或 IP，可给 `port`、`network`、`address`、`process`、`url`、`user_agent`、`source`），返回决定它的规则序号与文本、策略组链和出站，不建连接也不计数；需要地址而没给时返回 `needs_address`。`rule_hits` 返回每条规则（插件规则在前）与 FINAL 自规则载入以来决定的连接数和最近命中时间，`clear_rule_hits` 清零，热重载后从零开始。
- 远程规则集：Surge/Loon `RULE-SET,<url>`、`DOMAIN-SET,<url>`（裸域名只匹配该域名，即 `format: domain`）、Loon `[Remote Rule]`（`url, policy=..., enabled=...`，排在本地规则之后、`FINAL` 之前）和 Clash `rule-providers`（只接受 `type: http`，`behavior` 为 `domain`/`ipcidr`/`classical`，`format` 为 `yaml`/`text`；`mrs`、`file`、`inline` 跳过）变成 `ImportedRouting::rule_sets`，规则改写为 `RULE-SET,<id>,<target>`，逻辑规则内的引用同样改写。id 取 Clash provider 名或 URL 最后一段去扩展名，只保留 `[A-Za-z0-9._-]`，重名时加 `-2`、`-3`。同一 URL 或 provider 只建一个规则集，最多 32 个。Surge `update-interval=` 与 Clash `interval` 写入 `interval_secs`（不足 600 秒按 600），Clash `proxy` 指向已导入的策略组或节点时写入 `via`。`no-resolve` 随规则保留。Surge 内置的 `RULE-SET,LAN`（没有同名 Clash provider 时）改写为内核内置的 `LAN` 集，不生成远程集；内置的 `SYSTEM`（苹果系统服务名单，内容未公开）跳过并给出诊断。导入的远程集不会取名 `LAN`（取 `LAN-2`）。诊断不包含规则集 URL（可能带订阅 token）。`node-import` 把它们作为 `routing.rule_sets` 输出（键为 id，字段 `url`、可选 `format`、`interval_secs`、`via`、`public_key`），没有远程规则集时不输出该键。导入的警告（不支持的规则类型按类型计数、跳过的 `SYSTEM`、未导入的策略等，最多 32 行）作为报告顶层的 `routing_warnings` 输出，供客户端显示，不含列表 URL。列表 URL 末尾的 `#anixops:pubkey=<base64 公钥>` 标记（面板给自签名列表加的）会从 URL 去掉并写成 `public_key`。
- `load-balance` 组：Clash `strategy` 或 Loon `algorithm` 为 `round-robin`/`random` 时导入为 `round-robin`，其他（`consistent-hashing`、`sticky-sessions`、`pcc`）导入为 `load-balance`。
- 节点名过滤：Surge `include-all-proxies`、Clash `include-all`/`include-all-proxies` 加入全部节点；Surge `policy-regex-filter`、Clash `filter`（可用反引号分隔多个模式）只保留名称匹配的节点，Clash `exclude-filter` 去掉匹配的节点，按订阅中的节点顺序追加在显式成员之后。两者原本作用于外部列表/provider（不导入），所以没有成员的组带过滤器时从全部节点中筛选；有成员且没有 include-all 的组忽略过滤器并警告；正则无法编译（Rust `regex` 语法，不支持环视）时不加节点并警告。
- 不支持的规则类型、目标未导入的规则、`relay` 等组、组内 `REJECT`、url-test/fallback 内的组成员都会跳过并给出警告；成员全部被跳过的组也会跳过，引用它的规则随之跳过。`FINAL` 之后的规则忽略。
- 跳过后剩余内容仍无法通过 `RoutingModel::from_spec`（如没有 `FINAL`、组成环）时整体不导入，返回 `None` 和 `config.core.routing_import.invalid` 警告。诊断只包含规则类型、组名和节点名，不包含节点凭据。

## 本地代理接入

- `engine-singbox::render_sing_box_local_proxy_routing_config(request, &model)`：模型引用到的节点按节点 id 作为 tag 渲染（WireGuard 进 `endpoints`），加上策略组出站、`direct` 和 `render_sing_box_route` 的 `route`；未引用的节点不渲染。引用到的节点不能被本地代理渲染时返回错误。报告的节点是 `FINAL` 在无运行时状态时落到的节点。
- Windows Tauri GUI 导入订阅：订阅含规则和策略组且渲染成功时写入路由配置，系统代理指向 `127.0.0.1:7890`，节点列表为空，策略组按原生 sing-box 配置的分组方式（`list_native_groups`/`select_native_group_outbound`）查看和修改默认成员；否则保持原来的选择器配置。HTTPS MITM 导入路径与 Win32 旧界面暂不使用路由。
- `networkcore-linux run-url`：未指定 `--node` 时导入订阅中的规则和策略组，导入成功就用路由配置启动；导入失败或渲染失败时退回原来的单节点配置并给出警告。指定 `--node` 时保持单节点行为。Mieru 节点路径不变。

## engine-embedded 接入

- 运行时配置新增 `routing` 段（与 `outbound` 二选一）：`outbounds` 以节点 id 为键，`rules` 与 `groups` 字段同 `RoutingSpec`/`PolicyGroupSpec`。路由节点必须是 TCP 出站（Shadowsocks-2022、direct）；WireGuard 是包级隧道，只能作为单一 `outbound` 使用。
- `engine_embedded::routing::RoutedOutbound` 对每个连接调用 `decide`，`DIRECT` 走直连出站，`REJECT` 系列直接失败（按下文「REJECT 系列」应答），节点走对应出站。select 组先用运行时 `select` 控制命令的选择，再用 `default` 或第一个成员；url-test/fallback/load-balance/round-robin 使用 `run_health_checks` 的测速结果，round-robin 的计数在 `RoutedOutbound` 内。
- 策略组自愈（`RoutedOutbound`，详见 `routing.rs` 模块文档「Self-healing groups」）：
  - 连接经测速组的成员建立失败（`Dispatcher` 调 `report_failure`，被规则拒绝的 `PermissionDenied` 不算）时立即只重测这个成员，同一成员 10 秒内最多一次；重测失败即去掉它的结果，下一条连接换成员，重测通过则保持不变，所以目标站点拒连不会把组推离好节点，也不会因一个坏站点去拨全组节点。UDP 失败不触发（不带 UDP 中继的节点照样能通过 TCP 测速）。
  - `reset_network` 同时调用 `forget_health`：清空全部延迟、url-test 当前成员与失败冷却；切网前开始的测速结果作废。之后有连接经过某个还没有结果的测速组时立即测它（不等间隔）。
  - `evaluate_before_use`：组没有结果时（首次使用、切网后）连接等待该组测完（最多 6 秒）再选成员，而不是先走可能已失效的第一个成员；测速循环没有运行（无 `local-proxy`）时不等待。
  - `subnet` 组的网络来自控制命令 `set_network`（`type`、`ssid`、`bssid`、`router`、`addresses`），客户端在网络变化时先发 `set_network` 再发 `reset_network`。Wi-Fi 名与 BSSID 只留在内核内存里，不进日志、列表和导出。
- 按请求路由：`USER-AGENT`、`URL-REGEX` 在明文 HTTP 流上按首个请求生效；被 MITM 解密的连接（HTTPS 与经改写钩子的明文 HTTP）里每个请求都重新分流（`mitm::request_route`）：同出站复用源站连接，`REJECT` 本地回 403，其他出站时 HTTP/1.1 换源站连接、HTTP/2 为该出站另开源站连接（每个 App 连接最多 4 条）。规则表没有这两类规则时（`RoutingTable::uses_request`）完全不做按请求路由。`URL-REGEX` 可以单独成行指向节点或策略组（也可在 AND/OR/NOT 里）；指向 `REJECT`/`REJECT-*` 的单独 `URL-REGEX` 仍由 HTTPS 解密的拦截处理，不是分流规则。
- 隧道从 TCP 首包嗅探 TLS SNI 或 HTTP `Host`：域名规则按嗅探到的名字匹配，IP 规则仍匹配目的地址，连接仍发往原地址。UDP（含 QUIC）尚不嗅探，FakeIP 未接入。
- 每个连接都带目的端口，`DST-PORT` 规则在隧道和本地代理里都生效。`SRC-IP` 匹配发起连接的一方：本地代理、局域网共享和回放代理里是客户端地址（双栈监听上的 IPv4 映射地址按 IPv4 比较），包隧道里是应用的源地址（隧道作网关时即局域网设备的地址）。`IN-PORT` 匹配客户端连上的本地监听端口（本地代理、局域网共享各自的端口），包隧道没有监听端口，不命中。HTTPS 解密后的连接沿用原连接的来源。`PROCESS-NAME` 规则在桌面 local proxy 中生效：配置含该规则时，每条连接先由 `engine-embedded::process` 按连接两端地址查出发起进程（Linux `/proc`、Windows `GetExtendedTcpTable`、macOS `proc_pidfdinfo`），名称为可执行文件名，连接列表的 `process` 字段显示它。查不到（其他用户的进程、无权限）时该连接不命中 `PROCESS-NAME`。iOS 隧道没有进程信息，规则不命中。
- 规则集（`routing.rule_sets`，最多 32 个，合计 50 万条）：每个集可含 `domain`、`domain_suffix`、`domain_keyword`、`ip_cidr`。`RULE-SET,<name>` 匹配同名集；`GEOSITE,<category>` 匹配名为 `geosite-<category>` 的集（未配置时整个配置被拒绝）；`GEOIP,<CC>` 匹配 `geoip-<cc>`（小写），`IP-ASN,<号>` 匹配 `asn-<号>`；这两种集未配置时规则不命中，运行时控制 `rule_sets` 的 `missing` 列出规则（含规则集里的规则）用到却没有的这类集名（排序，最多 64 个），客户端据此提示用户按 URL 导入数据，不静默失效。内核不内置任何 GeoIP 或 ASN 数据。客户端以普通列表提供 GeoSite/GeoIP 数据，例如 MetaCubeX `meta-rules-dat` 的文本规则集。
- 规则集里的地址与 Surge 一致：集里有网段（或下载列表里有匹配地址的规则）时，只有域名的连接先按集里的域名匹配，没命中再解析一次域名、用解析结果匹配网段（与 IP 规则共用这一次解析，解析失败同 IP 规则一样拒绝）；规则写 `no-resolve` 时只匹配已经是地址的连接。只有域名的集从不解析。
- 内置 `LAN` 集（Surge 同名内置集）：`localhost`、`.local` 以及 10/8、100.64/10、127/8、169.254/16、172.16/12、192.168/16、::1、fc00::/7、fe80::/10。配置里自己定义 `LAN` 时以配置为准。它不出现在 `rule_sets` 状态里。
- 远程规则集：规则集带 `url` 时由内核自己下载（需要 `local-proxy` feature，iOS 与桌面构建都包含），可选 `format`（`suffix`：裸域名匹配自身与子域名，默认；`domain`：裸域名只匹配自身，即 Clash `behavior: domain`）、`interval_secs`（至少 600，默认 86400）和 `via`（经哪个策略组、节点或 `DIRECT` 下载，默认 `DIRECT`）。内联条目作为初始内容（客户端缓存的副本）；初始为空时启动即下载，之后按间隔刷新，失败保留旧内容并在 5 分钟内重试。下载为 HTTP/1.1 GET（不跟随跳转、不压缩，最大 32 MiB，60 秒超时），列表可以是 Surge/Loon/Clash classical 行、Clash `payload:` YAML 或每行一个域名/网段。classical 列表里域名、网段以外的规则（`DOMAIN-WILDCARD`、`PROCESS-NAME`、`USER-AGENT`、`URL-REGEX`、`DST-PORT`、`SRC-IP`、`IN-PORT`、`PROTOCOL` 及其 `AND`/`OR`/`NOT`，每集最多 4096 条）也保留，在域名表和网段表之后逐条按整条连接匹配；集里有 `PROCESS-NAME` 或 `USER-AGENT`/`URL-REGEX` 时，进程查找和解密后按请求分流也随之开启。`GEOIP`、`IP-ASN` 行也保留（只在 `geoip-<cc>`、`asn-<号>` 集的网段里查地址）。集不能容纳的行（`SCRIPT`、`RULE-SET`、`GEOSITE`、格式错误等）按规则类型计数，见下面的 `skipped`。可选签名校验：`public_key`（Ed25519 公钥 32 字节，base64）要求每次下载都附带分离签名，签名默认取 `<url>.sig`（可用 `signature_url` 指定），文件内容是对列表原始字节的 64 字节签名（标准或 URL-safe base64，可带 `#` / `untrusted comment:` 注释行，最大 1 KiB）；签名缺失记 `signature_missing`、格式不对记 `signature_malformed`、校验失败记 `signature_invalid`，都按下载失败处理，保留旧内容。运行时控制 `rule_sets` 返回每个集的来源、条目数、最近成功时间、最近错误（不含 URL）、是否要求签名（`signed`）和最近一次下载跳过的行数（`skipped`，按规则类型计数，如 `{"SCRIPT": 12}`；格式错误记 `INVALID`，超过 16 种的类型合并为 `OTHER`；规则类型以外的行内容一律不保留），`update_rule_sets` 立即刷新全部远程集。
- 运行时控制（见 FFI 边界文档 “Runtime Control”）提供连接列表、模式切换（`rule`/`global`/`direct`，全局目标为 `routing.global`）、策略组列表与 select 切换。
- 目标改写（`redirects`，运行时配置顶层，最多 256 行，`config_core::redirect`）：每行是一条规则加新目的地，新目的地写 `host`、`host:port`、`[v6]:port` 或 `:port`（省略端口沿用原端口，`:port` 只换端口），例如 `IP-CIDR,203.0.113.10/32,10.8.0.5:7000`、`AND,((DOMAIN-SUFFIX,game.example.com),(PROTOCOL,UDP)),10.8.0.5`。按顺序取第一条命中的行，TCP 与 UDP 都生效，在所有模式（rule/global/direct）下都在分流之前执行；分流随后只看新目的地（嗅探到的名字不再参与），所以可以再用 `IP-CIDR` 规则把开发内网地址交给某个节点。匹配从不解析域名：IP 规则只命中目的地是地址的连接；隧道里的域名规则靠 TCP 嗅探到的 SNI/`Host`，UDP 没有名字，只能按地址和端口匹配（域名游戏用 `dns.hosts` 即可）。`GEOIP`、`GEOSITE`、`RULE-SET` 不能用于改写。隧道里 UDP 回包仍以应用原本发往的地址为源，TCP 连接对应用也保持原目的地。连接列表保留原 `destination`，另给出 `redirect`（新目的地和命中的行）。单一 WireGuard 出站是包级隧道，不经过改写。

## REJECT 系列

被拒绝的连接按策略应答（engine-outbound `reject` 把应答方式带在 connect 错误里，包隧道、本地代理和 HTTPS 解密各自照做）：

| 策略 | 包隧道 TCP | 包隧道 UDP | 本地代理（HTTP/SOCKS5） | HTTPS 解密的主机 |
| --- | --- | --- | --- | --- |
| `REJECT`、`REJECT-NO-DROP` | 读完首包后关闭 | 丢弃；443 端口回 ICMP 端口不可达，QUIC 立即退回 TCP | 回 502 / SOCKS5 一般失败 | 解密后关闭 |
| `REJECT-DROP` | 不回任何数据也不关闭，保持到应用自己关闭或 60 秒；同时保持的被拒连接最多为 `max_tcp_connections` 的 1/8，超出即关闭 | 丢弃，不回 ICMP | 不回应，保持到客户端关闭或 60 秒（进程内最多 256 条，超出按 `REJECT` 回复） | 同 `REJECT`（解密的连接不保持） |
| `REJECT-TINYGIF` | 明文 HTTP 请求回 `200`、`image/gif` 的 1x1 GIF 并关闭；其他按 `REJECT` | 同 `REJECT` | 明文 HTTP 代理请求回 GIF；CONNECT/SOCKS5 按 `REJECT` | 解密后第一个请求回 GIF 并关闭 |

防重试风暴：同一主机（域名，没有域名时为地址）30 秒内被普通 `REJECT` 拒绝超过 10 次，之后的拒绝按 `REJECT-DROP` 应答，直到该主机最近 30 秒内的拒绝不超过 10 次；被升级的拒绝本身也计数，持续猛打的客户端会一直被静默。`REJECT-NO-DROP` 永不升级。计数只针对用户流量（包隧道、本地代理、解密连接的路由），DNS 服务器路由和状态查询不计。最多跟踪 1024 个主机，满时先清掉 30 秒内没有被拒的主机，再清最早被拒的。连接列表的 `outbound`/`chain` 显示实际应答（风暴中为 `REJECT-DROP`），`error` 仍为 `rejected`。

## SCRIPT 规则（规则脚本）

对齐 Surge 规则脚本：`SCRIPT,<名称>,<策略>`，脚本在 `routing.scripts` 里按名称配置，例如 `"scripts": {"corp": {"path": "/…/corp.js", "argument": "443", "timeout_secs": 1}}`。`path` 是客户端保存脚本的本地文件（启动时读一次，最大 1 MiB），`argument` 为 `$argument`，`timeout_secs` 为 1–3 秒（默认 1）；最多 32 个脚本，规则（含热重载的规则）引用未配置的脚本时整个配置被拒绝（热重载返回 `unknown_script`）。需要 `scripts` feature（默认构建都包含，iOS 同样用 QuickJS）。公开版不带任何预设脚本，脚本只来自用户。

- 决策按顺序进行：前面的规则先判，走到 `SCRIPT` 规则且本连接还没有该脚本的结论时，config-core 返回 `RouteMatch::ScriptPending`，engine-embedded 在阻塞线程池里运行脚本，再带着结论重新决策；IP 规则需要的解析结果沿用，不重复解析。同一连接每个脚本最多运行一次。
- 脚本看到的 `$request`：`hostname`（小写域名）、`destIP`（目的地址或之前 IP 规则解析出的地址）、`destPort`、`sourceIP`、`inPort`、`processName`、`protocol`（`TCP`/`UDP`）、`userAgent`、`url`，未知时为 `null`；`$script.type` 为 `rule`。只有 `$done({matched: true})` 算命中；抛异常、超时、不调用 `$done`、或等待空闲槽位超过超时都按不命中继续往下判。
- 规则脚本没有网络（`$httpClient` 失败），`$persistentStore` 只在内存里、引擎重启即清空；同时最多运行 2 个，每个 QuickJS 堆上限 4 MiB。
- 没有具体连接的决策（DNS 服务器分流、状态查询）不运行脚本，`SCRIPT` 规则一律不命中。重定向（`redirects`）和插件规则不接受 `SCRIPT`。

## 绑定网卡的直连

直连出站可以写 `{"type":"direct","interface":"<名称>"}`（对齐 Surge `direct, interface=...`），把公司 VPN 或某块网卡专用的流量钉在那块网卡上，例如 `DOMAIN-SUFFIX,corp.example,CorpVPN`，`CorpVPN` 为绑定 `utun4` 的直连节点。名称在 Linux/Android 是网卡名（`wg0`，最长 15 字节，`SO_BINDTODEVICE`），macOS/iOS 是 BSD 名（`utun4`、`en0`，`IP_BOUND_IF`/`IPV6_BOUND_IF`），Windows 是“网络连接”里的适配器名（`IP_UNICAST_IF`/`IPV6_UNICAST_IF`）。网卡在每个连接时查找：VPN 后起也能立刻用上；网卡不存在时连接失败（`NotFound`，本地代理回 502 / SOCKS5 一般失败），绝不改走默认网卡。域名用系统解析器解析后逐个地址尝试。这类出站不经过进程级的 socket 保护（绑定的网卡取代了它），也不能再套 `via`。

后续工作：Windows MITM 导入路径接入路由；engine-embedded 的 FakeIP、UDP/QUIC 嗅探与桌面进程名查询。
