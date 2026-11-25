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
| `self` | `addressManaged`、`region`、`regionBasis`、`regionState`、`hostMode` | 0.4 |
| `members[]` | `id`、`name`、`role`、`state`、`address`、`domain`、`connection`、`hops`、`transport`、`latencyMs`、`path`、`pathState`、`unreachable`、`subnets`、`duplicateOf` | 0.3 |
| `members[]` | `region`、`addressManaged`、`vms` | 0.4 |
| `network` | `kind`、`limitations` | 0.3 |
| `members[]` | `implementation` | 0.3 |
| `subnets[]` | `cidr`、`advertisers[{member,inUse}]`、`latencyMs`、`path`、`state`、`overlaps`、`localOverlap`、`route` | 0.3 |
| `subnets[]` | `region` | 0.4 |
| `tunnel` | `routes`、`routesVersion`、`dns` | 0.3 |
| 顶层 | `names`、`refusedNames` | 0.3 |
| 顶层 | `regionRequests` | 0.4 |

### 取值

| 字段 | 取值 |
|---|---|
| `network.state` | `joined`、`joining`、`partial`（部分成员不可达）、`not_joined`、`failed` |
| `network.security` | `forward_secrecy`（安全模式）、`standard`（默认模式，未启用前向保密）、`none`（显式选择的不加密，需求 R14） |
| `network.kind` | `managed`、`legacy`（配置里的 `network.kind`，规范 §5.2） |
| `network.limitations` | 字符串列表，空列表表示没有限制；只在安全模式网络上给出，旧模式网络为空列表（旧模式另由 `security` 标出）。`reference_peers`：`network.kind` 为 `legacy`（旧网本来就由原版节点组成），或至少一个在线成员的 `implementation` 为 `reference`；与这些成员之间的会话保密性以参考实现为上限（规范 §19.2 第 5 条），界面显示「含原版节点，保密性受限」。`unverified_peers`：`managed` 网络中没有 `reference` 成员，但至少一个在线成员为 `unknown`；界面显示较弱的提示「无法确认对端实现」 |
| `members[].implementation` | `native`（我方节点程序）、`reference`（原版实现）、`unknown`（尚不能判断）。判定用的是**经握手认证**的对端静态公钥：直连邻居取 Noise XX 握手中认证的静态公钥，经中继的成员取已建立的中继会话（Noise IK）中认证的静态公钥；还没有会话的成员只有路由信息字段 18 中的自报公钥，一律为 `unknown`。认证后的公钥与配置 `network.native_keys`（面板经 Agent 下发的我方节点静态公钥清单，见 `mesh-module.md`）比较：在清单中为 `native`；清单存在但不在其中为 `reference`；配置没有该清单（独立节点等）时为 `unknown`。旧模式网络没有静态公钥认证，一律为 `unknown` |
| `network.failure` | `null` 或 `{ "code", "detail" }`，`code` 见下表；`detail` 只给人看 |
| `network.joining` | `null` 或 `{ "stage": "connecting" \| "assigning_address" \| "measuring_regions", "peersConnected" }` |
| `routingPolicy` | `hops`、`latency` |
| `role` | 0.3：`server`（完整节点）、`client`（接入节点）；0.4 起另有 `border`、`gateway`、`host` |
| `id`（成员与本机） | 不透明字符串，取节点实例 UUID，重启后不变；不用每次启动都会变的数字节点号 |
| `member.state` | `online`、`unreachable` |
| `connection` | `self`、`direct`、`relay`（`hops` 为中转次数）、`unreachable`；0.4 起另有 `cross_region`、`via_host`、`via_gateway` |
| `transport` | `tcp`、`udp` |
| `latencyMs` | 整数毫秒；未测到为 `null` |
| `path` | 成员 `id` 列表，从第一跳到目的 |
| `pathState` | `auto`；0.5 起另有 `custom`、`fallback`（`unreachable` 为连不上的成员 `id`，需求 R9）、`first_hop_only` |
| `subnet.state` | `ok`、`unreachable`、`refused`（内网范围外，列出但不装路由，需求 R17） |
| `subnet.route` | `mesh`、`local`（与本机网络重叠时默认 `local`） |
| `suggestedSubnets` | `[{ "cidr", "interface", "public" }]`：只在桌面与服务器的完整节点给出；`public` 为 `true` 的不可通告 |
| `ipForwarding` | `on`、`off`、`not_needed`；只在完整节点给出 |
| `tunnel.routes` | 应进入隧道的网段（CIDR 列表）：所有已加入网络的虚拟网段，加上当前路由到组网的通告子网（与本机网络冲突、内网范围外、或用户设为 `local` 的不在内），再按 `routing.system_routes` 限制。去重，顺序稳定 |
| `tunnel.routesVersion` | 整数，`routes` 每变一次加一；引擎重启后从 1 起 |
| `names[]` | `{ "name", "addresses": [地址], "source": "panel" \| "member", "duplicate", "answerable" }`：本网络的内网域名名单（不含后缀），一个名字的每种来源各一条。`duplicate` 为 `true` 时该名对应多个成员或条目，解析返回全部地址，下发来源在前（需求 R28）；同名中有 `member` 来源时界面提示可能冒名。`answerable` 为 `false` 时地址不在可应答的网段内，不会应答。`source` 以后可能出现 `backbone`、`gateway`，按 `other` 处理 |
| `refusedNames[]` | `{ "name", "address", "reason": "not_intranet" \| "invalid_name" }`：配置里跳过的名字条目，原因分别为地址在内网范围外、名字不是规范化后的 `名.地区代码` |
| `regionRequests[]` | `{ "id", "network", "region", "reason" }`：本机 `mesh_request_region` 记下、尚未被取走的入区申请；每个网络最多一条，新申请替换旧的 |
| `tunnel.dns` | `null`，或 `{ "servers": [地址], "matchDomains": [后缀] }`：内网域名开启时只对这些后缀生效（需求 R28） |

### 失败与冲突原因

`network.failure.code` 与 `anixops-mesh run` 退出时 stderr 末行 JSON 的 `conflict`（见 `mesh-module.md`）用同一套取值：

| code | 含义 |
|---|---|
| `secret_mismatch` | 对端的网络名或密钥与本机不一致 |
| `security_mismatch` | 对端的安全模式与本网络不一致（规范 §5.2，不回退） |
| `unencrypted_refused` | 对端不加密而本机未显式选择 `none` |
| `port_in_use` | 监听端口被占用，`detail` 为传输与端口 |
| `tun_in_use` | 虚拟网卡名称已被占用 |
| `route_overlap` | 虚拟网段或要装的路由与本机已有路由冲突，`detail` 为网段 |
| `address_in_use` | 虚拟地址已被本机其他接口使用 |
| `identity_online` | 同一节点身份已在别处在线 |
| `permission_denied` | 没有创建虚拟网卡或修改路由的权限 |
| `unreachable_peers` | 所有初始对端都连不上 |

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
| `GET /v1/status` 的 `features` | `mesh`；`mesh_dns`（网络配置接受 `dns` 节）；`mesh_host_groups`（接受 `host_groups` 节）；`mesh_region_requests`（提供下面的申请接口） | `mesh`、`mesh_dns` 0.3；其余 0.4 |
| `PUT /v1/mesh` | 每个网络一份 `config_version: 1` 配置，`dns`、`host_groups` 与 `subnets`、`routing` 同级 | 0.3 |
| `GET /v1/mesh` 顶层 `instance_id` | 本设备的实例 ID：1–64 位 ASCII 字母、数字或连字符，首字符必须是字母或数字（`^[0-9A-Za-z][0-9A-Za-z-]{0,63}$`，规范 §1），由内核生成，等于快照的 `self.id`；整台设备一个、各网络共用，与节点静态密钥一起持久保存，只有删除节点数据重新入网才变；网络暂缓或未运行时也给出 | 0.3 |
| `GET /v1/mesh` 顶层 `region_requests` | `[{ "id", "network", "region", "reason" }]`，`network` 为该网络配置的 `network.name`，即快照的 `network.id`；每个网络最多一条待处理申请，新申请替换旧的，保留到被删除为止 | 0.4 |
| `DELETE /v1/mesh/region_requests/{id}` | 删除一条申请；`id` 由内核在记下申请时生成，为 1–64 位 ASCII 字母、数字或连字符，首字符必须是字母或数字（`^[0-9A-Za-z][0-9A-Za-z-]{0,63}$`），不存在时返回 404 | 0.4 |

`PUT /v1/mesh` 与 `GET /v1/mesh` 的具体形态（networkcore issue #300，实现见 node-runtime `mesh`、outbound-mesh `status`）：

- 请求体 `{"networks": [网络配置]}`：每项是上面的 `config_version: 1` 配置，另带同级的 `tag`，取值 `mesh-<地区代码>`（地区代码与面板一致：2–16 位小写字母、数字或连字符，字母开头，不以连字符结尾）。边界节点同时加入多个网络，所以是数组（需求 R18、R19），最多 64 项。
- 整体替换：这组网络取代当前运行的全部网络，未变的网络不中断；`{"networks": []}` 停止全部。任一项无效（字段缺失或未知、配置校验不过、`tag` 不合规或重复、`network.name` 重复）时返回 400，整个请求体都不应用，与 `/v1/network`、`/v1/egress` 一致。网络启动不了（R12：端口占用、虚拟网卡或路由冲突、同一节点身份已在线）不算请求无效：应答 200，该网络 `running` 为 `false`，带 `start_refused` 告警。
- 应答与 `GET` 相同：`{"instance_id", "networks": [...]}`，每项依请求顺序给出 `tag`、`running`、`error`（运行时为空串）、`address`（本机虚拟地址带前缀长度，如 `10.150.0.5/16`，没有时为空串）、`forward_secrecy`、`peers[{ "address", "subnets", "via", "hops", "latency_ms", "forward_secrecy" }]`（`via` 为途经的中继虚拟地址，直连为空；`latency_ms` 未测到为 `null`，需求 R16）、`rejected_advertisements`（被拒的子网通告数）、`overlaps`（重叠网段，R16、R17）、`alerts[{ "code", "address", "peer", "detail" }]`。内核给出的 `code`：`address_conflict`、`address_unmanaged`（R29）、`start_refused`（`detail` 写原因）；`address`、`peer`（成员实例 ID）不适用时为空串。字段名与面板 `mesh.status` 一致，Agent 把 `tag` 换回地区代码后原样上报。
- 内核不持久化这些网络：重启后 Agent 重新发送最后一次 `PUT`。
- `secret` 不出现在任何应答、错误信息和日志中：错误信息只指出第几项、哪条规则或哪个字段名，不回显取值。
- 内核未编入组网驱动时 `features` 不列 `mesh`，`GET`、`PUT /v1/mesh` 都返回 404。

## 命令

| 命令 | 参数 | 自哪个内核版本 |
|---|---|---|
| `mesh_status` | `network`（可省略，见「快照」） | 0.3 |
| `mesh_join` / `mesh_leave` | `network` | 0.3 |
| `mesh_save_network` | `config`：`config_version: 1` 网络配置（见 `mesh-module.md`；密钥由钥匙串注入） | 0.3 |
| `mesh_remove_network` | `network` | 0.3 |
| `mesh_set_dns` | `enabled`、可省的 `suffix`；本机覆盖，优先于网络配置的 `dns`，`suffix` 须位于 `internal` 或 `home.arpa` 之下（见 `mesh-module.md`） | 0.3 |
| `mesh_set_subnet_route` | `network`、`cidr`、`route`（`local` \| `mesh`）；作为本机覆盖保存，不改网络配置 | 0.3 |
| `mesh_set_relay` / `mesh_set_host_mode` | `network`、`enabled`；仅完整节点 | 0.4 |
| `mesh_advertise` / `mesh_withdraw` | `network`、`cidr`；仅完整节点，须在内网范围内 | 0.4 |
| `mesh_request_region` | `network`、`region`、可省的 `reason`（去掉首尾空白后截到 500 个字符）；由网络管理者批准。内核生成申请 `id`，每个网络只保留最新一条 | 0.4 |
| `mesh_set_policy` | `network`、`policy` | 0.5 |
| `mesh_set_paths` | `network`、`paths`（与 `routing.paths` 同结构） | 0.5 |
| `mesh_join_credential` | `credential`：一次性入网凭据 | 0.5 |

成功返回 `{"ok":true}`，`mesh_status` 返回快照。失败返回 `{"ok":false,"error":{"code","detail"}}`。`code` 为 `unsupported`、`invalid_argument`、`not_found`、`not_allowed`（例如接入节点通告子网），或上面的失败原因之一。
