# 组网状态快照与控制命令

本页是客户端、Agent 与安装器读取组网状态、发出组网命令的接口正本。客户端界面说明在 anixops-net 仓库 `docs/architecture/mesh-client.md`，两边不一致时以本页为准。模块结构见 [`mesh-module.md`](mesh-module.md)。

## 通道

- 组网与代理在同一个引擎实例里运行（需求 R23，手机上共用一个 VPN），命令走现有控制通道：iOS、macOS 为 `networkcore_ios_runtime_control`，Android、Windows、Linux 为 `client-core` / `client-ipc` 的同名命令。
- 请求是 JSON，命令名放在 `cmd` 字段，用下划线命名，与现有命令一致，例如 `{"cmd":"mesh_status"}`。
- 引擎编入组网后 `networkcore_ios_feature_set_version` 为 7。未编入 `mesh` feature 时 `capabilities.mesh` 为 `false`，所有 `mesh_*` 命令返回 `unsupported`。
- 不新增任何网络监听端口（需求 R11）。独立节点程序 `anixops-mesh` 在本机 Unix 域套接字上回答同样的 `mesh_status`（Windows 上为命名管道），文件权限只允许 root 与指定组访问；不监听任何 TCP 或 UDP 端口，回环地址也不行（OpenWrt LuCI 插件使用，需求 R35）。

## 快照

`mesh_status` 一次返回完整快照。快照按网络给出：`network`、`self`、`members`、`subnets`、`refusedAdvertisements` 都属于请求的那个网络（命令参数 `network`；省略时为第一个已加入的网络，没有已加入的网络时为第一个已保存的网络）。`tunnel` 属于整个引擎：一台设备只有一个隧道，它汇总所有已加入的网络，在每个网络的快照里取值相同。顶层 `networks` 列出所有已保存的网络 `{ "id", "name", "state" }`，供多网络时逐个读取。字段名用 lowerCamelCase。读取方忽略未知字段，枚举遇到未知取值按 `other` 处理；某个内核版本尚未提供的字段直接缺省。

| 对象 | 字段 | 自哪个内核版本 |
|---|---|---|
| 顶层 | `statusVersion`（固定 1）、`networks`、`network`、`self`、`members`、`subnets`、`refusedAdvertisements`、`tunnel` | 0.3 |
| 顶层 | `regions`、`links` | 0.4 |
| 顶层 | `paths` | 0.5 |
| `network` | `id`（即配置里的 `network.name`）、`name`、`state`、`security`、`failure`、`joining`、`routingPolicy`、`dnsSuffix`、`dnsEnabled` | 0.3 |
| `self` | `id`、`name`、`role`、`address`、`addressV6`、`domain`、`relay`、`listen`、`advertised`、`suggestedSubnets`、`ipForwarding` | 0.3 |
| `self` | `staticKey` | 0.3 |
| `self` | `addressManaged`、`region`、`regionBasis`、`regionState`、`hostMode` | 0.4 |
| `self` | `regionRequest`、`regionSuggestion` | 0.4（`regionRequest` 的 `rejected` 需能力 `mesh_region_request_state`） |
| `members[]` | `id`、`name`、`role`、`state`、`address`、`domain`、`connection`、`hops`、`transport`、`latencyMs`、`path`、`pathState`、`unreachable`、`subnets`、`duplicateOf` | 0.3 |
| `members[]` | `region`、`addressManaged`、`vms` | 0.4 |
| `members[]` | `bridgesExternal` | 0.4（能力 `mesh_external_routes`） |
| `network` | `kind`、`limitations` | 0.3 |
| `members[]` | `implementation` | 0.3 |
| `subnets[]` | `cidr`、`advertisers[{member,inUse}]`、`latencyMs`、`path`、`state`、`overlaps`、`localOverlap`、`route` | 0.3 |
| `subnets[]` | `region` | 0.4 |
| `subnets[]` | `kind`、`hostGroup` | 0.4 |
| `subnets[]` | `bridge`、`name`（`kind` 为 `external` 时） | 0.4（能力 `mesh_external_routes`） |
| `tunnel` | `routes`、`routesVersion`、`dns` | 0.3 |
| `externalBridge` | `allowDigest`、`allowCount`、`routesDigest`、`appliedAt` | 0.4（能力 `mesh_external_bridge`） |
| 顶层 | `names`、`refusedNames` | 0.3 |
| 顶层 | `regionRequests` | 0.4 |

### 取值

| 字段 | 取值 |
|---|---|
| `network.state` | `joined`、`joining`、`partial`（部分成员不可达）、`not_joined`、`failed` |
| `network.security` | `forward_secrecy`（安全模式）、`standard`（默认模式，未启用前向保密）、`none`（显式选择的不加密，需求 R14） |
| `network.kind` | `managed`、`legacy`（配置里的 `network.kind`，规范 §5.2） |
| `self.staticKey` | 本机在该网络的安全模式静态公钥：32 字节 X25519 公钥的标准 base64（RFC 4648 §4，带填充，44 个字符）。按网络各一份（规范 §8.1），保存网络配置时即生成，网络未加入时也给出；旧模式网络为 `null`。没有 Agent 的设备在登记时或首次上报时提交这个值，供面板列入 `network.native_keys`（规范 §8.3.1 第 7 条） |
| `network.limitations` | 字符串列表，空列表表示没有限制；只在安全模式网络上给出，旧模式网络为空列表（旧模式另由 `security` 标出）。`reference_peers`：`network.kind` 为 `legacy` 且为安全模式（旧网本来就由原版节点组成）；与原版节点之间的会话保密性以参考实现为上限（规范 §19.2 第 5 条），界面显示「含原版节点，保密性受限」。`managed` 网络按规范 §8.3.1 只接纳 `native_keys` 中的我方节点，不会出现该值。`unverified_peers`：保留值，当前不再产生（原用于 `managed` 网络中实现无法判定的成员）；客户端仍应能显示它，提示「无法确认对端实现」 |
| `members[].implementation` | `native`（我方节点程序）、`reference`（原版实现）、`unknown`（尚不能判断）。判定用的是**经握手认证**的对端静态公钥：直连邻居取 Noise XX 握手中认证的静态公钥，经中继的成员取已建立的中继会话（Noise IK）中认证的静态公钥；还没有会话的成员只有路由信息字段 18 中的自报公钥，一律为 `unknown`。认证后的公钥与配置 `network.native_keys`（面板经 Agent 下发的我方节点静态公钥清单，见 `mesh-module.md`）比较：在清单中为 `native`；清单存在但不在其中为 `reference`；配置没有该清单时为 `unknown`。`managed` 网络必须有清单，且不在清单中的对端握手被拒（规范 §8.3.1），所以已有会话的成员一律为 `native`，`reference` 只出现在带清单的 `legacy` 网络中。旧模式网络没有静态公钥认证，一律为 `unknown` |
| `network.failure` | `null` 或 `{ "code", "detail" }`，`code` 见下表；`detail` 只给人看。只有一个值，按优先级取：使网络无法运行的原因（`native_keys_pending`、`port_in_use`、`tun_in_use`、`route_overlap`、`address_in_use`、`identity_online`、`permission_denied` 等）优先，其次 `unreachable_peers`，最后 `peer_not_native`。`peer_not_native` 在被拒对端此后握手成功，或 10 分钟内没有新的被拒时清除 |
| `network.joining` | `null` 或 `{ "stage": "connecting" \| "assigning_address" \| "measuring_regions", "peersConnected" }` |
| `routingPolicy` | `hops`、`latency` |
| `role` | 0.3：`server`（完整节点）、`client`（接入节点）；0.4 起另有 `border`、`gateway`、`host` |
| `id`（成员与本机） | 不透明字符串，取节点实例 UUID，重启后不变；不用每次启动都会变的数字节点号 |
| `member.state` | `online`、`unreachable` |
| `connection` | `self`、`direct`、`relay`（`hops` 为中转次数）、`unreachable`；0.4 起另有 `cross_region`、`via_host`、`via_gateway`。`cross_region` 为保留值：区域之间不传递节点信息（规范 §15.6 第 8 条），`members[]` 只列本区域成员，0.4 内核不产生该值；其他地区只以 `subnets[]` 中 `kind = summary` 的汇总网段出现（`path` 止于出口边界节点），其他地区的主机名只经 `names[]` 出现，不进入 `members[]`。客户端遇到该值时按「经边界节点」显示 |
| `transport` | `tcp`、`udp` |
| `latencyMs` | 整数毫秒；未测到为 `null` |
| `path` | 成员 `id` 列表，从第一跳到目的 |
| `pathState` | `auto`；0.5 起另有 `custom`、`fallback`（`unreachable` 为连不上的成员 `id`，需求 R9）、`first_hop_only` |
| `paths[]`（0.5） | 本网络配置的自定义路径（规范 §17.2），按配置顺序：`{ "id", "target", "via", "state", "unreachable", "reason" }`。`id` 由目标生成：`peer:<虚拟地址>` 或 `subnet:<网段>`，路径列表改变时同一目标的 `id` 不变。`target` 为 `{ "peer": 成员 id }` 或 `{ "subnet": 网段 }`；`via` 为成员 `id` 列表，与配置顺序相同。目标或途经点的虚拟地址当前没有对应成员时，该项给出虚拟地址原文 |
| `path.state` | `pending`（能力查询尚未全部有结果，或途经点序列正在预热；不排队时通常不超过 11 + k 秒（k 为封装途经点数），因探测预算或查询排队顺延的时间另计；按默认选路发送，界面不提示；规范 §17.2.3、§17.2.6 第 7 条；最长 60 秒，超时转为 `fallback`（`pending_timeout`））、`active`（严格按途经点）、`first_hop_only`（只保证开头一段，规范 §17.2.3）、`fallback`（已回落默认选路）。客户端遇到不认识的取值时不提示回落 |
| `path.unreachable` | `fallback` 与 `first_hop_only` 时为涉及的成员 `id`（需求 R9，规范 §17.2.7）：`fallback` 时为连不上或不支持的节点，`first_hop_only` 时为第一个不再保证经过的途经点；`active` 与 `first_hop_only` 时目的本身不可达（路径错误码 2 且本机同样到不了目的）为目的成员 `id`（`first_hop_only` 时此项优先于第一个不再保证的途经点）；其余为 `null` |
| `path.reason` | `fallback` 时为 `unreachable`（途经点不可达、能力查询超时、途经点报告下一段或目的不可达）、`no_echo`（路径探测连续缺失回显，而拓扑中仍可达；界面提示"途经节点 C 未响应路径探测"，与连不上区分）、`pending_timeout`（能力查询或预热 60 秒仍未完成；界面提示"途经节点 C 未完成路径准备，已改用默认路径"）、`unsupported`（第一个途经点不支持封装且不是直连邻居，或安全模式下目的与本机直连且不是我方节点，此时 `unreachable` 为目的成员）、`not_relay`（第一个途经点不中转且不是直连邻居）、`hop_limit`（按本机拓扑预估超过 8 段）；`first_hop_only` 时为第一个不再保证经过的途经点的原因（`unsupported`、`not_relay` 或 `unreachable`）；其余为 `null`。规范 §17.2.7。客户端不认识的取值按 `unreachable` 显示 |
| `members[].pathState` 取值规则（0.5） | 该成员有 `to_peer` 路径时取该路径的 `state`：`active` 记为 `custom`，`pending` 记为 `auto`，`first_hop_only`、`fallback` 原样；`unreachable` 同该路径。只被 `to_subnet` 路径覆盖的成员仍为 `auto`，子网的路径状态看 `paths[]`。`custom` 与 `first_hop_only` 时 `path` 为按本机拓扑展开的预计路径（经各途经点，途经点之间取默认选路），`hops` 为其中的中转次数；`first_hop_only` 只展开到最后一个保证经过的途经点，之后按本机拓扑的默认选路估计 |
| 宿主组（0.5） | 组内虚拟机（`members[].vms`）没有单独的路径状态。组地址段在 `subnets[]` 中的 `path` 按该地址段匹配到的路径给出：有包含它的 `to_subnet` 路径时按最长前缀的那一条，否则按到网关的路径（规范 §17.2.2 第 6 条，需求 R25） |
| `subnet.state` | `ok`、`unreachable`、`refused`（内网范围外，列出但不装路由，需求 R17） |
| `subnet.route` | `mesh`、`local`（与本机网络重叠时默认 `local`） |
| `subnet.kind`（0.4） | `lan`（成员通告的局域网子网，缺省值）、`host_group`（宿主组地址段）、`external`（外部网络地址，规范 §15.12）、`summary`（边界节点通告的其他地区汇总网段，规范 §15.6 第 3 条）。按下列顺序取第一条成立的：① `cidr` 与本网络配置 `host_groups[].cidr` 完全相同，且当前在用的通告者是该组的网关或备用网关 → `host_group`；② `cidr` 与配置 `external_routes[].cidr` 完全相同，且当前在用的通告者是该项的 `bridge` → `external`；③ 当前在用的通告者全部是本区域的边界节点（`role = border`），且 `cidr` 不在本网络虚拟网段内 → `summary`；④ 其余 → `lan`。只看配置与通告者是否吻合，通告者不符时按 `lan` 显示，不提示冒用。缺省或不认识的取值，客户端按 `lan` 显示（这是「未知枚举按 `other`」的例外） |
| `subnet.hostGroup`（0.4） | 只在 `kind = host_group` 时给出：`{ "gateway", "backupGateway" }`，为配置中的成员实例 ID（快照成员的 `id`）；没有备用网关时 `backupGateway` 为 `null`。组内设备列表见 `members[].vms` |
| `subnet.region`（0.4） | `kind = summary` 时为该网段所属的其他地区代码：边界节点上取骨干汇总路由交换（规范 §17.3.3）中通告者所在地区；普通成员上取顶层 `regions[]` 中虚拟子网包含该网段的地区，查不到（例如其他地区的业务网段）时为 `null`。其他 `kind` 为本区域代码或 `null` |
| `subnet.bridge`、`subnet.name`（0.4，能力 `mesh_external_routes`） | 只在 `kind = external` 时给出：`bridge` 为配置中的桥接节点实例 ID，`name` 为配置中的显示名，未配置时为 `null`。只用于显示，不影响路由与访问控制 |
| `members[].bridgesExternal`（0.4，能力 `mesh_external_routes`） | 布尔：该成员是本网络某个 `kind = external` 子网的当前在用通告者时为 `true`，否则为 `false`。不与顶层 `externalBridge`（本机桥接配置摘要）混用 |
| `self.regionRequest`（0.4） | `null`，或 `{ "id", "region", "state", "reason", "rejectReason" }`：本机在该网络最新一次迁区申请（需求 R24，规范 §15.8 第 5 条）。`state` 为 `pending`（已提交、等待网络管理者处理）或 `rejected`（被拒绝，`rejectReason` 为管理者填写的原因，没有填写时为空串；`pending` 时为 `null`）。来源：本机 `mesh_request_region` 记下的申请在被 Agent 取走前直接给出 `pending`；取走之后由面板经 Agent 下发的网络配置 `region_request`（见 `mesh-module.md`）给出，内核未列出 `mesh_region_request_state` 时 Agent 不下发该节，此时申请被取走后为 `null`。申请被批准后迁移开始，面板不再下发该节，字段为 `null`；撤回（`mesh_withdraw_region_request`）后立即为 `null`。界面提示「迁区后虚拟地址将变化」 |
| `self.regionSuggestion`（0.4） | `null`，或 `{ "region", "currentMedianMs", "suggestedMedianMs", "since" }`：规范 §15.8 第 5 条的迁移建议，`region` 为建议的地区代码，两项为最近一次测量的中位 RTT（整数毫秒），`since` 为条件开始连续成立的时间（RFC 3339，UTC）。条件不再成立、已有 `pending` 申请或节点已在该地区时为 `null`。只是提示，不会自动迁移 |
| `suggestedSubnets` | `[{ "cidr", "interface", "public" }]`：只在桌面与服务器的完整节点给出；`public` 为 `true` 的不可通告 |
| `ipForwarding` | `on`、`off`、`not_needed`；只在完整节点给出 |
| `tunnel.routes` | 应进入隧道的网段（CIDR 列表）：所有已加入网络的虚拟网段，加上当前路由到组网的通告子网（与本机网络冲突、内网范围外、或用户设为 `local` 的不在内），再按 `routing.system_routes` 限制。本机网卡网段在网络启动后成功读取之前，通告子网一律不列入（规范 §15.4）。去重，顺序稳定 |
| `tunnel.routesVersion` | 整数，`routes` 每变一次加一；引擎重启后从 1 起 |
| `names[]` | `{ "name", "addresses": [地址], "source": "panel" \| "member", "duplicate", "answerable" }`：本网络的内网域名名单（不含后缀），一个名字的每种来源各一条。`duplicate` 为 `true` 时该名对应多个成员或条目，解析返回全部地址，下发来源在前（需求 R28）；同名中有 `member` 来源时界面提示可能冒名。`answerable` 为 `false` 时地址不在可应答的网段内，不会应答。`source` 以后可能出现 `backbone`、`gateway`，按 `other` 处理 |
| `refusedNames[]` | `{ "name", "address", "reason": "not_intranet" \| "invalid_name" }`：配置里跳过的名字条目，原因分别为地址在内网范围外、名字不是规范化后的 `名.地区代码` |
| `regionRequests[]` | `{ "id", "network", "region", "reason" }`：本机 `mesh_request_region` 记下、尚未被取走的入区申请；每个网络最多一条，新申请替换旧的。0.4 起另有可省的 `withdraw`：为 `true` 时表示撤回该网络的申请（由 `mesh_withdraw_region_request` 记下，此时 `region` 为空串、`reason` 为空串），面板取消该网络待处理的申请 |
| `externalBridge` | 三态：**对象**为本机已生效的桥接配置摘要（见下）；**显式 `null`** 表示内核确知本网络当前没有桥接（未配置 `external_bridge`、配置中移除该节、网络停止，或桥接规则已全部撤除），面板以此作为释放桥接相关资源的依据之一；**键缺省**表示状态未知（内核读取防火墙状态失败、配置被拒、网络暂缓等），面板不得据此释放地址占用，也不得视为已应用。Agent 转发规则：内核给出对象或显式 `null` 时原样上报；Agent 已读到内核状态、且内核 `features` 未列出 `mesh_external_bridge` 时，为每个网络（含 `legacy` 与被扣下的网络）上报显式 `null`，只有面板向该网络下发过 `external_bridge` 节时另附告警 `external_bridge_unsupported`（这样的内核不会装桥接规则；Agent 合成的 `null` 以规范 §15.12 第 9 条的规则清理为前提）；网络带告警 `external_bridge_downgrade_residue` 或 `external_bridge_lock_held` 时（见下文 `features` 一行）Agent 省略该键，不合成 `null`，也不附 `external_bridge_unsupported`；内核列出该能力但省略该键，或 Agent 读取内核状态失败时，上报中省略该键。面板把「缺少该键且同一网络带告警 `external_bridge_unsupported`」按显式 `null` 处理，这是「键缺省即未知」的唯一例外（规范 §15.12 第 8 条）。对象即本机已生效的桥接配置摘要（规范 §15.12 第 4 条）：`allowDigest` 为 `allow` 名单的摘要，`routesDigest` 为 `routes` 的摘要，`allowCount` 为名单条目数，`appliedAt` 为生效时间（RFC 3339，UTC）。摘要算法：把各条目规范化为 CIDR 文本（IPv4 点分十进制，IPv6 按 RFC 5952 小写压缩，单个地址也写出前缀长度），去重后按字节序排序，以换行符 `\n` 连接（末尾无换行），取 SHA-256 的小写十六进制。只在新配置的防火墙规则全部装好后才更新；装失败时保持旧值并告警。Agent 原样上报，面板对自己下发的名单按同样算法计算，相等即视为桥接节点已应用；判断「已应用」时，时间以面板收到该上报的观测时间为准（须晚于名单变更时刻），不比较节点时钟给出的 `appliedAt`，`appliedAt` 只供展示 |
| `tunnel.dns` | `null`，或 `{ "servers": [地址], "matchDomains": [后缀] }`：内网域名开启时只对这些后缀生效（需求 R28）。`matchDomains` 含后缀和内核推算的反向解析区（规范 §15.9.2 第 1 条），客户端只使用这里给出的域，不自行推算；内网域名关闭时为 `null` |

**`externalBridge` 摘要测试向量**（面板与内核共用；`routesDigest` 用同一算法）。输入是已通过配置校验的条目，主机位非零的网段（如 `192.168.1.5/24`）在校验时已被拒绝，不进入摘要。规范化时没有前缀长度的单个地址补 /32 或 /128，IPv6 改为 RFC 5952 小写压缩形式，去重后按字节序排序，各条以单个换行符（0x0A）连接，末尾不加换行，对 UTF-8 字节取 SHA-256：

| 输入（下发顺序） | 规范化后（`\n` 表示换行） | `allowDigest` |
|---|---|---|
| （空名单） | 空串 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `10.0.0.5` | `10.0.0.5/32` | `65078d8a7bd32b6934150b573cfa67ab5eace9b47601e86deb978ac3be4ba6fc` |
| `10.0.0.5/32`、`192.168.1.0/24`、`10.0.0.5` | `10.0.0.5/32` `\n` `192.168.1.0/24` | `f8eb52bad06ba0dc556b78371a449a2fea20c61b8810fff1fff7fc5877065d06` |
| `FD7A:115C:A1E0:0:0:0:0:1`、`10.150.0.7/32`、`fd7a:115c:a1e0::1/128`、`192.168.10.0/24`、`FD00:AA:0:0::/64` | `10.150.0.7/32` `\n` `192.168.10.0/24` `\n` `fd00:aa::/64` `\n` `fd7a:115c:a1e0::1/128` | `f4843004a47d48528d070b5e98e8526e14e22a0b73c7b907f2622f0c009e947b` |
| `10.150.0.2/32`、`10.127.0.0/24`、`fd7a:115c:a1e0::5/128`、`10.150.0.128/32`（面板实现所用） | `10.127.0.0/24` `\n` `10.150.0.128/32` `\n` `10.150.0.2/32` `\n` `fd7a:115c:a1e0::5/128` | `c2125301582f23d00252ec7ea3ae881359c66f9333fcae94ba95c64931257366` |

### 失败与冲突原因

`network.failure.code` 与 `anixops-mesh run` 退出时 stderr 末行 JSON 的 `conflict`（见 `mesh-module.md`）用同一套取值：

| code | 含义 |
|---|---|
| `secret_mismatch` | 对端的网络名或密钥与本机不一致 |
| `security_mismatch` | 对端的安全模式与本网络不一致（规范 §5.2，不回退） |
| `unencrypted_refused` | 对端不加密而本机未显式选择 `none` |
| `port_in_use` | 监听端口被占用，`detail` 为传输与端口 |
| `tun_in_use` | 虚拟网卡名称已被占用 |
| `native_keys_pending` | `managed` 网络暂缓：`network.native_keys` 缺省、为空或不含本机在该网络的静态公钥（规范 §8.3.1 第 1 条）。`detail` 为 `empty`（缺省或为空）或 `self_missing`（不含本机公钥）。此时 `network.state` 为 `not_joined`，不建链路、不启动虚拟网卡；`self.staticKey` 与 `static_keys` 照常给出，供 Agent 上报。只影响该网络，不使 `anixops-mesh run` 退出；面板下发含本机公钥的清单后自动启动 |
| `peer_not_native` | `managed` 网络中，对端经握手认证的静态公钥不在 `network.native_keys` 中，握手被拒（规范 §8.3.1）。只记录最近一次，`detail` 为对端节点 ID；不改变 `network.state`，不使 `anixops-mesh run` 退出。通常是原版节点或尚未列入清单的新节点，后者在清单下发后自动恢复 |
| `route_overlap` | 虚拟网段或要装的路由与本机已有路由冲突，`detail` 为网段 |
| `address_in_use` | 虚拟地址已被本机其他接口使用 |
| `identity_online` | 同一节点身份已在别处在线 |
| `permission_denied` | 没有创建虚拟网卡或修改路由的权限 |
| `unreachable_peers` | 所有初始对端都连不上 |
| `external_bridge_lock_held` | 告警，不是网络失败：Linux 节点程序取不到主机级锁 `/run/anixops-mesh-host.lock`（同一主机上另有持锁、声明该能力的进程），因此不声明 `mesh_external_bridge`、不清理桥接表（规范 §15.12 第 9 条）。同时出现在 `GET /v1/mesh` 顶层 `alerts` 与每个网络的 `alerts` 中（没有运行任何网络时只在顶层），进程退出前不消除 |
| `subnet_router_lock_held` | 告警，不是网络失败：Linux 节点程序取不到主机级锁 `/run/anixops-mesh-host.lock`，因此不安装子网通告的转发规则、不清理路由表（`docs/architecture/mesh-module.md`「Linux 主机改动」），本机配置的通告子网不发出（不通告无法转发的网段）。出现位置与消除时机同 `external_bridge_lock_held` |
| `ipv6_forwarding_off` | 告警：Linux 完整节点配置了 IPv6 通告子网，而系统 IPv6 转发未开启。内核不改 IPv6 转发设置，这些 IPv6 子网不通告，IPv4 子网照常；`detail` 列出未通告的网段 |
| `reverse_zones_truncated` | 告警，不是网络失败：该网络推算出的反向解析区超过 256 个，超出部分不推算、不应答，`detail` 为未推算的区数，`address`、`peer` 为空串（规范 §15.9.2 第 1 条） |

新增取值属于兼容变更，读取方遇到未知取值按失败处理。

## 隧道生命周期（需求 R23）

组网的加入开关与代理的连接开关互相独立，任一开启即建立 VPN。

- **只开组网**：客户端照常下发普通 profile，不需要专门的模式标记。profile 里只有组网出站、没有代理出站时，路由规则只把 `tunnel.routes` 指向组网，其余流量不进隧道（手机上 `includedRoutes` 只放 `tunnel.routes`，桌面只装这些路由）。
- **加入与退出是热操作**：`mesh_save_network`、`mesh_join`、`mesh_leave`、`mesh_remove_network` 都不重启引擎，也不影响代理出站。
- **代理开关不打断组网**：代理连上或断开时，客户端重新下发 profile（增加或去掉代理出站）。只要网络配置没变，组网实例按 `network.id` 保留，会话与成员连接不断；配置变了才重建该网络。
- **路由由引擎给出**：客户端不自己算网段，通告子网是动态的。客户端在组网加入期间读取 `mesh_status`（前台每 2 秒、后台每 10 秒，或在现有状态变化通知到来时），`tunnel.routesVersion` 变化时重新应用一次隧道网络设置（手机上的 `includedRoutes`、DNS 匹配域），重新应用之间至少间隔 1 秒。
- 组网与代理都关闭时，客户端关闭 VPN。

## 节点程序管理 API

服务器、OpenWrt 等由 Agent 驱动的节点，Agent 经 `anixcore` 现有的本机管理 API 读写组网（字段名与 `anix-agent` 的 `docs/mesh.md`「内核接口」、`anix-control` 的 `agent-contract.md` 一致）：

| 接口 | 内容 | 自哪个内核版本 |
|---|---|---|
| `GET /v1/status` 的 `features` | `mesh`；`mesh_dns`（网络配置接受 `dns` 节）；`mesh_host_groups`（接受 `host_groups` 节）；`mesh_region_requests`（提供下面的申请接口）；`mesh_external_bridge`（接受 `external_bridge` 配置，规范 §15.12，内核 0.4；只在 `anixcore` 运维开关 `mesh_external_bridge` 开启（默认关闭）且试装成功时列出；内核未列出时 Agent 扣下该网络的 `external_bridge` 节，其余配置照常下发，并向面板上报告警 `external_bridge_unsupported`；Linux 上的 Agent 记录过某网络曾在声明该能力的内核上实际作为桥接生效，而当前内核未列出 `mesh_external_bridge` 时，对该网络上报告警 `external_bridge_downgrade_residue`（可能有残留桥接规则）。告警存在期间，Agent 对该网络省略 `externalBridge`（未知），不合成显式 `null`，也不附 `external_bridge_unsupported`；面板不得以任何依据（包括连续两次上报）释放该网络的地址保留。声明该能力的内核运行并完成清理后，或运维手工清除桥接表并删除 Agent 的该项记录后，告警消除。）；`mesh_resolver_address`（`dns` 节接受 `resolver_address`，规范 §15.9.2 第 8 条，内核 0.4；未列出时 Agent 或面板省略该字段）；`mesh_native_keys`（按规范 §8.3.1 处理 `network.kind` 与 `native_keys`：准入、清单未就绪时暂缓并报 `native_keys_pending`、拒绝清单外对端并报 `peer_not_native`，并给出 `static_keys` 与 `self.staticKey`）。`mesh_external_routes`（网络配置接受 `external_routes`，快照给出 `subnets[].kind = external` 的 `bridge`、`name` 与 `members[].bridgesExternal`，内核 0.4；未列出时 Agent 省略该节，不告警，客户端把这些网段显示为 `lan`）；`mesh_region_request_state`（网络配置接受 `region_request`，提供 `mesh_withdraw_region_request` 与撤回记录，内核 0.4；未列出时 Agent 省略 `region_request`，客户端不显示撤回按钮）；`mesh_paths`（按规范 §17.2 应用 `routing.paths`：途经点封装、能力查询服务 `MeshPathRpc`、回落与 `paths[]` 状态，接受 `mesh_set_paths`，内核 0.5；未列出的内核虽然接受 `routing.paths` 的语法但不应用，Agent 与面板不向它下发路径，客户端不显示路径编辑）。Agent 只向列出 `mesh_native_keys` 的内核下发 `kind = managed` 的网络；内核未列出时不下发该网络，向面板上报告警 `native_keys_unsupported`（`legacy` 网络照常下发）；面板下发的 `kind` 不是 `managed` 或 `legacy` 时不下发该网络，上报告警 `invalid_kind`。所有能力都以 `features` 实际列出为准，不按内核版本号推断 | `mesh`、`mesh_dns`、`mesh_native_keys` 0.3；`mesh_paths` 0.5；其余 0.4 |
| `PUT /v1/mesh` | 每个网络一份 `config_version: 1` 配置，`dns`、`host_groups` 与 `subnets`、`routing` 同级 | 0.3 |
| `GET /v1/mesh` 顶层 `instance_id` | 本设备的实例 ID：1–64 位 ASCII 字母、数字或连字符，首字符必须是字母或数字（`^[0-9A-Za-z][0-9A-Za-z-]{0,63}$`，规范 §1），由内核生成，等于快照的 `self.id`；整台设备一个、各网络共用，与节点静态密钥一起持久保存，只有删除节点数据重新入网才变；网络暂缓或未运行时也给出 | 0.3 |
| `GET /v1/mesh` 顶层 `static_keys` | `[{ "network", "static_key" }]`：本机各网络的安全模式静态公钥，`network` 为该网络配置的 `network.name`，`static_key` 编码同快照的 `self.staticKey`；旧模式网络不列出。Agent 在每个网络实例的状态上报中原样带上 `static_key`，面板只采信 Agent 通道的值来生成 `native_keys`（规范 §8.3.1 第 7 条） | 0.3 |
| `GET /v1/mesh` 的 `networks[].failure` | `{ "code", "detail" }` 或 `null`，与该网络快照的 `network.failure` 同值（例如 `native_keys_pending`、`peer_not_native`）；Agent 转为告警上报 | 0.3 |
| `GET /v1/mesh` 的 `networks[].paths` | 与该网络快照的 `paths[]` 同结构同值（`{ "id", "target", "via", "state", "unreachable", "reason" }`，按配置顺序；未配置路径时为空数组）。只有 `features` 列出 `mesh_paths` 的内核给出；Agent 原样转述给面板，内核未列出 `mesh_paths` 时 Agent 下发 `routing.paths = []`，不读取该字段 | 0.5 |
| `GET /v1/mesh` 顶层 `region_requests` | `[{ "id", "network", "region", "reason" }]`，`network` 为该网络配置的 `network.name`，即快照的 `network.id`；每个网络最多一条待处理申请，新申请替换旧的，保留到被删除为止 | 0.4 |
| `GET /v1/mesh` 顶层 `alerts` | 可选，节点级告警：元素格式与 `networks[].alerts` 相同（`{ "code", "address", "peer", "detail" }`，与网络无关的告警 `address`、`peer` 为空串），缺省或空数组表示没有。用于与具体网络无关、内核没有运行任何网络时也要让 Agent 看到的状态；目前只有 `external_bridge_lock_held`。内核在持锁失败期间把该告警同时放在顶层 `alerts` 与每个网络的 `alerts` 中；Agent 在任一处看到即按持锁处理（规范 §15.12 第 9 条） | 0.4 |
| `DELETE /v1/mesh/region_requests/{id}` | 删除一条申请；`id` 由内核在记下申请时生成，为 1–64 位 ASCII 字母、数字或连字符，首字符必须是字母或数字（`^[0-9A-Za-z][0-9A-Za-z-]{0,63}$`），不存在时返回 404 | 0.4 |

`PUT /v1/mesh` 与 `GET /v1/mesh` 的具体形态（networkcore issue #300，实现见 node-runtime `mesh`、outbound-mesh `status`）：

- 请求体 `{"networks": [网络配置]}`：每项是上面的 `config_version: 1` 配置，另带同级的 `tag`，取值 `mesh-<地区代码>`（地区代码与面板一致：2–16 位小写字母、数字或连字符，字母开头，不以连字符结尾）。边界节点同时加入多个网络，所以是数组（需求 R18、R19），最多 64 项。请求体上限 32 MiB（64 项、每项 4096 个 `native_keys` 约 13 MiB）。
- 整体替换：这组网络取代当前运行的全部网络，未变的网络不中断；`{"networks": []}` 停止全部。任一项无效（字段缺失或未知、配置校验不过、`tag` 不合规或重复、`network.name` 重复）时返回 400，整个请求体都不应用，与 `/v1/network`、`/v1/egress` 一致。网络启动不了（R12：端口占用、虚拟网卡或路由冲突、同一节点身份已在线）不算请求无效：应答 200，该网络 `running` 为 `false`，带 `start_refused` 告警。
- 应答与 `GET` 相同：`{"instance_id", "alerts", "networks": [...]}`（`alerts` 为可选的节点级告警，见上表），每项依请求顺序给出 `tag`、`running`、`error`（运行时为空串）、`address`（本机虚拟地址带前缀长度，如 `10.150.0.5/16`，没有时为空串）、`forward_secrecy`、`peers[{ "address", "subnets", "via", "hops", "latency_ms", "forward_secrecy" }]`（`via` 为途经的中继虚拟地址，直连为空；`latency_ms` 未测到为 `null`，需求 R16）、`failure`（同快照的 `network.failure`：`null` 或 `{ "code", "detail" }`，取值与优先级见上；暂缓的网络 `running` 为 `false`、`failure.code` 为 `native_keys_pending`，**不**发 `start_refused` 告警，Agent 只把 `failure` 转为同码告警上报面板）、`rejected_advertisements`（被拒的子网通告数）、`overlaps`（重叠网段，R16、R17）、`alerts[{ "code", "address", "peer", "detail" }]`。内核给出的 `code`：`address_conflict`、`address_unmanaged`（R29）、`start_refused`（`detail` 写原因）、`system_routes_truncated`（可路由网段超过系统路由上限，成员按跳数由近到远公平分配，`detail` 为未安装的条数）、`peer_key_changed`（成员路由信息中的公钥与其节点 ID 已绑定的公钥不同，未采用，`detail` 为节点 ID，即「节点公钥变更被拒」）、`rpc_oversize`（超过 4 MiB 的 RPC 未发送，`detail` 为累计次数）、`sync_oversize`（同步超限，网络运行期间各类各自保留最后一次，同一网络可同时带多条：规范 §11.2 经认证直连从邻居收到的路由同步调用 body 超过 8 MiB 被丢弃，`detail` 以 `received:` 开头，写已达到的字节数与该邻居节点 ID（其他服务的超限调用、或包头 `from` 不是该连接认证的邻居时只计数、不告警，以免成员冒用他人 ID 触发告警或干扰建桥前的规模判断）；或 §12.2 连接图截短一半后仍未在第二个 60 秒内送达、与邻居的同步会话被关闭，`detail` 以 `undelivered:` 开头，列出最近一次检查中被关闭的全部邻居节点 ID，并注明也可能由链路或对端应答错误引起，附错误应答累计次数；或节点信息表已满（4095 条，§12.3、§12.4）而拒收新节点、为直连邻居淘汰可达节点，或超过 16 MiB 存储预算而拒收，`detail` 以 `capacity:` 开头，写两类累计次数，此时成员数不会超过上限，不能据此判断规模；或发出的连接图截去了最远的行（§12.4 上限或 §12.2 截半），`detail` 以 `cut:` 开头，写累计次数，被截去的行之后重发。前两种附累计次数。独立运行（`anixops-mesh run`）的状态行同样输出 `sync_oversize` 及上述计数，供建桥前实测旧网规模）；`address`、`peer`（成员实例 ID）不适用时为空串。字段名与面板 `mesh.status` 一致，Agent 把 `tag` 换回地区代码后原样上报。
- `PUT /v1/mesh/subnet_route`：请求体 `{"tag", "cidr", "route"}`，`route` 为 `local` 或 `mesh`，`cidr` 须带前缀长度、不能是 `/0`，按网络地址保存（`192.168.10.7/24` 存为 `192.168.10.0/24`）。保存为该网络的本机覆盖（规范 §15.4），立即交给运行中的网络，网络重启、移出列表再加回都保留，不改网络配置；每个网络最多 256 条 `mesh` 覆盖。成功应答与 `GET` 相同；没有该 `tag` 的网络 404，请求体无效或超出条数 400，保存失败 500（覆盖不变）。与 `PUT /v1/mesh` 依次执行，不并发。
- 内核不持久化这些网络：重启后 Agent 重新发送最后一次 `PUT`。内核只在状态目录（`anixcore` 配置的 `mesh_state_dir`，缺省 `/var/lib/anixcore/mesh`，权限 0700）保存本设备的 `instance_id` 与各网络的静态密钥（`keys/` 下按 `network.name` 的摘要命名，0600；配置带 `node.private_key` 时用它）与子网路由覆盖（`overrides/` 下同样命名，0600）。网络移出列表时密钥保留，再次加入仍用同一密钥，面板已列入的 `native_keys` 不失效。状态目录不可用时内核不列 `mesh`。
- 实现（Linux，`apps/mesh-node` 的 `managed`）：每个运行中的网络各有一组监听、一块虚拟网卡（`anixmesh-<n>`，取最小未用编号）和一个驱动。`PUT` 中与上次相同的网络不中断；只有 `native_keys` 变化的运行中网络把新清单交给驱动，不重启：清单外对端的直连与中继会话断开、路由信息删除，其余照常；新清单不再含本机公钥时该网络停下并转为暂缓。启动失败的网络在下一次 `PUT` 时重试。端口占用、网卡占用、无权限分别给出 `failure.code` `port_in_use`、`tun_in_use`、`permission_denied`，其余为 `start_refused`，都带 `start_refused` 告警。
- `peers[]` 每项取该成员的第一个虚拟地址；`latency_ms` 只给直连成员（经中继的成员为 `null`）；`alerts` 中的 `address_conflict` 为声称本机虚拟地址的成员（`peer` 暂为空串）。`foreign_route_overlap` 为与本机上其他组网程序的路由重叠、因而保持 `route = local` 的通告子网（`detail` 为该子网；与本机网卡网段重叠的不报此告警，规范 §15.4）。`address_unmanaged` 待地址分配（0.4）实现。
- `secret` 不出现在任何应答、错误信息和日志中：错误信息只指出第几项、哪条规则或哪个字段名，不回显取值。
- 内核未编入组网驱动时 `features` 不列 `mesh`，`GET`、`PUT /v1/mesh` 都返回 404。

### Agent 告警码

Agent 自己产生、上报面板的告警（不经内核），与内核给出的 `failure.code`、`alerts[].code` 并列：

| `code` | 含义 |
|---|---|
| `native_keys_unsupported` | 内核 `features` 不含 `mesh_native_keys`：`kind = managed` 的网络不下发（包括内核重启后的重发），`legacy` 网络照常 |
| `invalid_kind` | 面板下发的 `network.kind` 不是 `managed` 或 `legacy`：Agent 扣下该网络，不交给内核 |
| `peer_not_native` | 由内核 `failure.code = peer_not_native` 转来，另带 `peer`（内核给出的 `detail`，被拒对端的节点 ID） |
| `external_bridge_unsupported` | 网络带 `external_bridge`，但内核 `features` 不含 `mesh_external_bridge`：Agent 照常下发该网络，去掉 `external_bridge` 节，并对该网络上报此告警（面板 #647 审计 M-2，anix-agent #203） |
| `paths_unsupported` | 网络配置了 `routing.paths`，但内核 `features` 不含 `mesh_paths`：Agent 对该网络下发 `routing.paths = []`，其余配置照常，并对该网络上报此告警（anix-agent #211） |

`mesh.status` 中每个网络的 `externalBridge` 有三种情况（anix-agent #202 审计 M1、#203）：

- 摘要对象：内核给出的桥接摘要，原样上报。
- `null`：内核明确给出 `null`，表示该网络没有运行桥接，原样上报。
- 不带该键：Agent 不知道内核当前的桥接情况（网络被扣下、下发失败、等待接管、读不到内核、内核应答没有这个键）。缺省**不能**当作「无桥接」。

## 命令

| 命令 | 参数 | 自哪个内核版本 |
|---|---|---|
| `mesh_status` | `network`（可省略，见「快照」） | 0.3 |
| `mesh_join` / `mesh_leave` | `network` | 0.3 |
| `mesh_save_network` | `config`：`config_version: 1` 网络配置（见 `mesh-module.md`；密钥由钥匙串注入） | 0.3 |
| `mesh_remove_network` | `network` | 0.3 |
| `mesh_set_dns` | `enabled`、可省的 `suffix`；本机覆盖，优先于网络配置的 `dns`，`suffix` 须位于 `internal` 之下且至少两个标签（规范 §15.9.2 第 1 条，见 `mesh-module.md`），不合规时拒绝该次设置 | 0.3 |
| `mesh_set_subnet_route` | `network`、`cidr`、`route`（`local` \| `mesh`）；作为本机覆盖保存，不改网络配置。`mesh` 使与本机网段（或其他组网软件路由）重叠、因而为 `route = local` 的已接受通告子网（与 `cidr` 完全相同的网段）照常路由并装入系统路由；`local` 撤销覆盖。内核入口为节点程序管理 API 的 `PUT /v1/mesh/subnet_route`（见下）；独立运行（`anixops-mesh run`）没有覆盖 | 0.3 |
| `mesh_set_relay` / `mesh_set_host_mode` | `network`、`enabled`；仅完整节点 | 0.4 |
| `mesh_advertise` / `mesh_withdraw` | `network`、`cidr`；仅完整节点，须在内网范围内 | 0.4 |
| `mesh_request_region` | `network`、`region`、可省的 `reason`（去掉首尾空白后截到 500 个字符）；由网络管理者批准。内核生成申请 `id`，每个网络只保留最新一条 | 0.4 |
| `mesh_withdraw_region_request` | `network`；撤回本机在该网络的迁区申请：替换未被取走的申请记录为一条 `withdraw: true` 的记录（没有记录时新建一条），由 Agent 取走后转给面板。没有待处理申请时返回 `not_found` | 0.4（能力 `mesh_region_request_state`） |
| `mesh_set_policy` | `network`、`policy` | 0.5 |
| `mesh_set_paths` | `network`、`paths`（与 `routing.paths` 同结构） | 0.5 |
| `mesh_join_credential` | `credential`：一次性入网凭据 | 0.5 |

成功返回 `{"ok":true}`，`mesh_status` 返回快照。失败返回 `{"ok":false,"error":{"code","detail"}}`。`code` 为 `unsupported`、`invalid_argument`、`not_found`、`not_allowed`（例如接入节点通告子网），或上面的失败原因之一。
