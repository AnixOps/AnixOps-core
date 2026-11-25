# 组网外部网络桥接（`crates/mesh-bridge`）

规范：`docs/protocols/intranet-mesh.md` §15.12（需求 R36，内核 0.4）。配置字段见 `docs/architecture/mesh-module.md`，状态字段 `externalBridge` 与摘要算法见 `docs/architecture/mesh-status.md`。

本文只说明内核侧的实现。公开文本与界面中统一称「外部网络」，不出现任何第三方组网软件的名称。

## 范围

- 只用于 Linux 完整节点：源地址转换与连接跟踪用系统的 nftables 实现。其他平台不列出能力 `mesh_external_bridge`，Agent 不向它们下发 `external_bridge`。
- 本 crate 只读取 `outbound-mesh` 的 `IpNet` 与内网白名单，不修改组网模块。把 `external_bridge` 接入网络配置、把 `routes` 并入本节点路由信息字段 5、在网络启动与停止时安装与拆除、上报 `externalBridge` 与告警、列出能力名，在 `outbound-mesh` 与 `apps/mesh-node` 中另行接入（下文「接入要求」）。

## 配置校验（`config`）

`external_bridge { interface, routes, allow }` 是每个网络的顶层字段（与 `subnets`、`routing` 同级，规范 #332 V4），拒绝未知字段。任何一项不合规，整份网络配置以 `invalid_argument` 拒绝，原因码如下：

| 原因码 | 条件 |
|---|---|
| `external_bridge_interface` | 网卡名为空、超过 15 字节、为 `.` 或 `..`，或含 ASCII 字母、数字、`-`、`_`、`.` 以外的字节 |
| `external_bridge_no_routes` | `routes` 为空 |
| `external_bridge_too_many_routes` | `routes` 超过 64 项（与面板上限相同） |
| `external_bridge_too_many_allow` | `allow` 超过 1024 项（面板至多 256 个来源，每个展开为一个前缀，留余量） |
| `external_bridge_syntax` | 不是地址或 `地址/前缀`，或为 IPv4 映射的 IPv6 地址 |
| `external_bridge_host_bits` | 前缀以下的主机位不为零（如 `192.168.1.5/24`） |
| `external_bridge_default_route` | 前缀长度为 0 |
| `external_bridge_not_intranet` | 不在 §15.4 白名单内（10/8、172.16/12、192.168/16、100.64/10、fc00::/7） |
| `external_bridge_overlay_range` | `routes` 中的网段（非单个地址）与 100.64.0.0/10 或 fd7a:115c:a1e0::/48 重叠或覆盖它们；这两个范围内只允许单个地址（/32、/128） |
| `external_bridge_allow_overlaps_route` | `allow` 中的条目与某条 `routes` 重叠 |
| `external_bridge_same_interface` | 外部网卡就是本网络的组网网卡 |
| `external_bridge_route_overlaps_mesh` | `routes` 与本网络的虚拟子网或本机虚拟地址重叠 |

不带前缀的单个地址按 /32、/128 处理。通过校验后两份名单按规范化 CIDR 文本去重排序，即摘要使用的顺序。

`routes` 并入字段 5 时仍走组网模块对 `subnets.advertise` 的既有检查（白名单、与虚拟子网不重叠）；100.64.0.0/10 内单个地址的例外只属于桥接配置，不放宽 `subnets.advertise` 本身。

## 防火墙规则（`ruleset`）

每个组网网卡一张 `inet` 表，名为 `anixops_bridge_` 加网卡名字节的十六进制（不同网卡名不会共用一张表）。每次应用都在一个 `nft -f` 事务中整表替换：新名单要么全部生效，要么加载失败、旧规则原样保留。

| 链 | 钩子 | 规则 |
|---|---|---|
| `forward` | filter forward | 组网网卡 → 外部网卡：来源在 `allow`、目的在 `routes` 的放行；其余全部丢弃并计入 `source_denied`。外部网卡 → 组网网卡：只放行我方发起连接的回程（`established,related`），其余丢弃并计入 `inbound_denied` |
| `input` | filter input | 从外部网卡进来、目的为本机在该网络中的虚拟地址的新连接丢弃并计入 `inbound_denied` |
| `postrouting` | nat postrouting（srcnat） | 组网网卡 → 外部网卡、来源在 `allow`、目的在 `routes` 的流量做 `masquerade`，源地址变为本节点在外部网络中的地址；回程由连接跟踪还原 |

- 来源检查在 `forward` 链，先于源地址转换（规范 §15.12 第 4 条）。检查对每个包生效，不只是新连接：名单去掉某个来源后，该来源已有的连接也随即中断。
- 名单中被其他条目覆盖的条目（如宿主组地址段内的单个成员地址）在集合中省略，因为 nftables 区间集合不接受重叠元素；摘要仍按下发的完整名单计算。
- 规则只放行或丢弃本表涉及的流量，从不修改其他表与链。nftables 中一张表的放行不能推翻另一张表的丢弃：主机上若另有防火墙在 forward 方向默认丢弃（例如某些容器运行时或主机防火墙的默认策略），桥接流量会被它丢弃，见 `docs/manual-intervention.md`「外部网络桥接节点的主机防火墙与 IPv6 转发」。
- 桥接节点不在外部网络中通告我方任何网段，也不修改外部组网软件的配置（规范 §15.12 第 2 条）。

## 应用、转发与状态（`apply`、`status`）

- `Bridge::apply` 先检查与本网络的冲突，再按需打开 IPv4 转发，然后加载规则。只有规则全部加载成功后才更新 `status()`（即 `externalBridge`）；失败时保留旧规则与旧状态，并给出告警 `external_bridge_apply_failed`（附 nft 的错误输出）。
- `Bridge::remove` 删除整张表；之后 `status()` 为 `None`（状态接口中为 `null`），面板以此释放桥接相关资源。`Bridge` 被丢弃时也会尽力删除。
- IPv4 转发由全进程共用的 `Forwarding` 管理：第一个带 IPv4 `routes` 的桥接安装时，若 `/proc/sys/net/ipv4/ip_forward` 为 0 则置 1；最后一个桥接拆除后，只有当初是本进程打开的才恢复为 0。原本就打开的保持不变。
- IPv6 转发从不修改：打开 `net.ipv6.conf.all.forwarding` 会让 Linux 在 `accept_ra = 1` 的网卡上忽略路由通告，主机自己的 IPv6 默认路由可能因此失效。桥接带 IPv6 `routes` 而 IPv6 转发未打开时，给出告警 `external_bridge_ipv6_forwarding_off`，IPv6 条目在运维人员打开转发前不生效。
- **连接跟踪（#356 复核 X3）**：源地址转换与「只放行回程」都依赖连接跟踪。名单或通告地址收窄、桥接拆除时，删除原始方向来源属于被移出来源（或仍在名单内的来源、目的属于被移出的通告地址）的连接跟踪条目，否则已建立的连接会继续经桥接通信直到条目超时。内核经 ctnetlink 直接读取并按条目自己的原始元组与 zone 删除，不依赖 `conntrack` 程序。删除失败时新规则已生效（逐包来源检查照常丢弃），但 `externalBridge` 保持旧值并告警 `external_bridge_apply_failed`（详情以 `conntrack:` 开头），待删除的范围保留到下一次应用或拆除时重试；拆除时同样在条目删除成功后才置为 `null`。启动清理先读出残留表中的名单再删表，然后删除对应的条目；残留表的名单读不出时照样删表，并报错而不扩大删除范围。
- **规则清理（规范 §15.12 第 9 条）**：`cleanup_all` 列出本机全部 nftables 表，删除 `inet` 族中名称为 `anixops_bridge_` 加偶数位小写十六进制（至多 30 位）的表，即本模块的标记，全部在一个事务中完成；其他表（包括名称相近但不符合该格式的表、其他族中同名的表）一律不动。没有安装 `nft` 的主机视为没有残留。节点程序在启动时、安装任何桥接之前调用一次，清除上一次运行（含崩溃）残留的规则；退出时先丢弃各 `Bridge`，再调用一次。崩溃后 IPv4 转发保持桥接打开时的状态：清理无法判断主机原先是否打开，所以不改转发，见 `docs/manual-intervention.md`。
- `Bridge::counters` 读取两个丢弃计数（`source_denied`、`inbound_denied`），供状态与诊断使用。
- `nft` 只从固定路径查找（`/usr/sbin/nft`、`/sbin/nft`、`/usr/bin/nft`），以空环境运行，不经 `PATH`。

## 接入要求（集成步骤）

由内核线程的 #331 合并后另行提交：

1. `outbound-mesh` 的网络配置加顶层可选字段 `external_bridge`（类型 `mesh_bridge::ExternalBridgeConfig`）；只有 `role = full` 的 Linux 节点接受，其他情况以 `invalid_argument` 拒绝。
2. 校验通过后，`routes` 并入本节点路由信息字段 5，与 `subnets.advertise` 合并去重。
3. 节点程序（声明 `mesh_external_bridge` 时）启动时先调用 `cleanup_all`，退出时在丢弃全部 `Bridge` 之后再调用一次；`apps/mesh-node` 在网络启动成功之后调用 `Bridge::apply`（参数为本网络的组网网卡名、虚拟子网与本机虚拟地址），配置更新时再次调用，网络停止（正常停止与丢弃两条路径）时调用 `Bridge::remove`。应用失败映射为网络失败码 `start_refused`（详情为告警原因），并上报告警。
4. Linux 的 `FEATURES` 加 `mesh_external_bridge`；`networks[].externalBridge` 取 `Bridge::status()`。

## 验证

- 单元测试：配置校验（各原因码、面板示例、规范化）、摘要（`mesh-status.md` 的共用测试向量）、规则脚本、转发开关的引用计数与恢复、失败时状态不变。
- CI 作业「Mesh external bridge (nftables)」（`.github/scripts/mesh-bridge-netns.sh`）：在三个网络命名空间（成员、桥接节点、外部网络）中把规则加载进真实的 nftables，检查名单内来源可达外部地址且经过源地址转换（外部网络没有回到我方网段的路由）、名单外来源与非通告地址被丢弃并计数、外部网络即使有路由也不能发起到成员和桥接节点虚拟地址的连接、新名单整体替换、越界配置被拒且不影响已装规则、拆除幂等；模拟崩溃留下两张表后，清理只删除这两张，其他程序的表（含名称相近的表与 `ip` 族的同名表）保留，第二次清理无事可做；名单收窄后被移出来源的连接跟踪条目被删除、外部网络自身的条目保留，崩溃残留的条目在启动清理时删除（脚本用 `conntrack -L` 观察）。单元测试另覆盖启动清理（崩溃残留）与退出清理。
