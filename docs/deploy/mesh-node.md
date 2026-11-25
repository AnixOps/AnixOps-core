# 组网节点部署：接管、导入与安装

`anixops-mesh`（`apps/mesh-node`）是只含组网模块的独立程序。Agent、无 Agent 机器的一条命令安装和 OpenWrt 软件包都用它，接管与导入逻辑只有这一份（需求 R12、R13、R15、R31、R32、R35）。节点运行子命令 `run` 由组网模块提供，见 [组网模块设计](../architecture/mesh-module.md)。

本程序不包含任何其他组网程序的名称、路径或配置格式。识别一种现有程序所需的全部信息写在**接管数据文件**（profile）里，由部署层维护并在运行时用 `--profile` 传入。公开仓库只带一份虚构程序 `demo-meshd` 的样例：[`apps/mesh-node/testdata/demo-profile.json`](../../apps/mesh-node/testdata/demo-profile.json)。

## 子命令

| 子命令 | 作用 | 退出码 |
| --- | --- | --- |
| `capabilities` | 输出版本和本构建支持的子命令（JSON）。安装器只有在列表含 `run` 时才执行接管 | 0 |
| `detect --profile F` | 列出本机的现有安装（服务、启动脚本、自启行、手动进程、容器）。只输出参数名，不输出任何取值 | 0；2 用法错误 |
| `import --profile F [--out-dir D] [--report R] [--allow-unencrypted] [--address CIDR] [-- ARGS…]` | 按检测结果（或 `--` 后手动给出的命令行）生成我方配置和导入报告 | 0 全部可用；3 未发现；5 有需确认项；6 有无法自动迁移的实例 |
| `takeover --profile F --state-dir S [--dry-run] [--report R]` | 停用并停止现有安装，记录到 `S/takeover.json` | 0 完成或无事可做；1 失败且已回滚；7 失败且回滚也失败 |
| `rollback --state-dir S [--report R]` | 按记录逆序恢复 | 0；7 部分步骤失败 |

用法错误、数据文件错误和状态目录错误的退出码为 2，标准错误最后一行是一行 JSON：`{"error":"<类别>","detail":"…"}`。`detail` 只给人看。

## 检测（Linux）

| 来源 | 方法 |
| --- | --- |
| systemd 服务 | 单元目录中名称在 `detect.services` 里、或 `ExecStart` 运行 `detect.executables` 的单元；模板单元按 `*.wants/` 中已启用的实例展开。用 `systemctl show` 取单元文件、drop-in、`UnitFileState`、`ActiveState` |
| OpenRC / SysV / procd 脚本 | `/etc/init.d/` 下名称匹配或内容引用程序名的脚本；OpenRC 读 `command`、`command_args` 和 `/etc/conf.d/<名称>`，运行级别取自 `rc-update show -v` |
| 自启行 | `/etc/rc.local`、`/etc/crontab`、`/etc/cron.d/*`、`/var/spool/cron/**` 中启动该程序的行 |
| 手动进程 | `/proc/*/exe` 与命令行匹配、且不属于以上任何一项的进程。进程所在的 systemd 单元不是程序自己的服务（名称不在 `detect.services` 里，`ExecStart` 也不运行该程序，例如 `cron.service`、`rc-local.service`）时，只记为宿主单元，接管时只结束该进程，绝不停用或停止宿主单元 |
| 容器 | cgroup 属于容器的进程，以及镜像名匹配 `detect.images` 的容器。只报告，不接管 |

命令行优先取自正在运行的进程（最准确），其次取自服务定义。服务定义里有无法确定的变量展开、或服务启动的是包装脚本时，该实例标为「无法确定启动参数」，需人工处理；报告只给出参数位置，不输出参数取值。

读取的配置文件、单元文件和脚本单个不超过 1 MiB，配置目录不超过 64 个文件；超出时该文件或目录记为无法读取。

## 导入（R13、R14、R15）

导入是单向转换，输出 `"type": "mesh"` 出站的 config v1（`config_version: 1`），每个网络实例一个文件，写入 `--out-dir`，权限 0600（含网络密钥）。设置的来源按「配置文件 → 环境变量 → 命令行」合并，后者覆盖前者；数据文件可声明列表项追加（`merge: append`）。一个目录中的多个配置文件各是一个实例，命令行只覆盖网络名相同的那个实例。

| 我方字段 | 规则 |
| --- | --- |
| `network.name` / `network.secret` | 原样导入；缺失或为空时无法迁移。密钥不进报告 |
| `network.kind` | 一律写 `legacy`（迁移中的现有网络，允许默认握手模式） |
| `network.secure_mode` | 原样导入；同一网络的各实例不一致时整网停止导入 |
| `network.cipher` | 规范化为 `aes-gcm`、`aes-256-gcm`、`chacha20`；没有完整性保护（如 xor）或无法识别的算法拒绝导入 |
| 关闭加密 | 默认拒绝；`--allow-unencrypted` 显式选择后以 `cipher: none` 导入并标为需确认 |
| `node.address` / `address_v6` | 必须在内网范围（10/8、172.16/12、192.168/16、100.64/10、fc00::/7），不能是网络地址或广播地址；未写前缀按 /24 并标为需确认；自动分配地址的节点无法迁移，除非用 `--address` 给出当前实际地址（R29）；`--address` 与原配置的固定地址不同时按 `--address` 导入并标为需确认（`address_overridden`） |
| `node.listen` | 只保留 TCP 和 UDP，简写（只写端口、地址或传输名）按数据文件的 `listener_shorthand` 展开 |
| `peers` | 只保留 TCP 和 UDP；没写端口且数据文件没有默认端口的对端需确认并跳过（`peer_port_unknown`）；地址在主机和端口之后还有路径或参数时，这部分不导入并标为需确认（`peer_options_dropped`）；同一主机另有其他传输地址时只记录；没有可用对端但有监听地址时按只等待连接的节点导入，两者都没有时无法迁移 |
| `subnets.advertise` | 只保留内网网段（规范化为网络地址）；带映射网段的实例无法自动迁移（R15）；公网网段不通告并标为需确认 |
| `routing.policy` | 延迟优先为 `latency`，否则 `hops` |
| `node.hostname` | 是一个 DNS 标签（字母、数字、连字符，最长 63 字节）时导入，否则需确认并使用系统主机名 |
| `node.mtu` | 1280–9000 时导入（等于默认值 1380 时不写），超出范围需确认 |
| `node.relay` | 原节点关闭中转时写 `false` |
| `routing.system_routes` | 只保留内网网段（规范化为网络地址）；其他网段需确认 |

数据文件 `drop` 列出的设置按原因归类：出口、端口转发、本机代理、VPN 接入网关、访问规则为需确认；远程配置服务器和凭据入网为无法迁移；管理接口、压缩、原有内网域名、打洞、限速等只记录。数据文件未覆盖的键、参数和带 `env_prefix` 的环境变量一律列为需确认，不会被默默忽略。位置参数只按位置报告，不输出取值。报告中的对端和监听地址去掉用户名、密码和主机端口之后的部分。

### 导入报告

```json
{
  "report_version": 1,
  "tool_version": "0.2.0",
  "profile_label": "现有组网程序",
  "instances": [
    {
      "id": "systemd:example.service",
      "status": "ready | needs_confirmation | blocked",
      "origin": { "kind": "systemd", "unit": "example.service", "unit_file_state": "enabled", "active": true },
      "config_file": "/etc/example/a.toml",
      "output": "/etc/anixops-mesh/imported/systemd_example.service.json",
      "network": { "name": "office", "secure_mode": false, "encrypted": true, "cipher": "aes-gcm" },
      "items": [
        { "field": "network.secret", "status": "imported", "code": "imported", "message": "已导入（不在报告中显示）。", "source": "file /etc/example/a.toml: identity.secret" }
      ]
    }
  ],
  "notes": []
}
```

`items[].status` 取 `imported`、`dropped`、`needs_confirmation`、`blocked`；`code` 是稳定的原因代码，`message` 只给人看。`network` 供 Agent 跨机器比较同一网络各节点的模式是否一致。同一网络和地址被发现两次（例如服务和它的进程）时，后一个实例只带 `duplicate_of`。

## 接管与回滚（R12）

顺序：备份将要修改的文件 → 关闭全部开机自启（`systemctl disable`，仍可被拉起的单元再 `mask`；`rc-update del`；`update-rc.d`、`chkconfig` 或 procd 脚本的 `disable`；自启行改为以 `#[anixops-mesh takeover] ` 开头的注释）→ 停止服务 → 对仍在运行的进程先 TERM、10 秒后 KILL → 确认没有残留进程。程序文件和原配置不删除，容器不碰。

每一步完成后立即写入 `state-dir/takeover.json`（0600，含被结束进程的命令行、完整环境变量、用户和组，以便回滚时以原身份原样重启）。任一步失败时，本次已做的步骤按逆序撤销，退出码 1；撤销也失败时退出码 7，记录只保留没撤销成功的步骤（以及它们需要的备份），之后的 `rollback` 只重试这些步骤。同一状态目录有锁（固定文件 `takeover.lock` 上的内核建议锁），不能并发执行；持有进程退出时锁由内核释放，锁文件保留，不存在需要判断或删除的陈旧锁。

OpenRC 服务只在有运行中的进程时才计划停止。宿主单元的 `Restart=` 不是 `no` 时，结束进程后先等待该单元的重启间隔（`RestartUSec`）再加 2 秒，然后确认程序没有被再次启动；间隔未知或超过 60 秒时不作猜测，本次接管失败并回滚。此类以包装命令启动程序的服务应写进数据文件的 `detect.services`，按程序自己的服务接管。`takeover` 本身不读取导入报告：R15 的拦截（远程配置、映射网段等无法迁移的实例）由调用方负责。安装脚本在导入退出码为 6 时终止；Agent 调用时也必须先执行 `import`，退出码为 6 时不得执行 `takeover`。

`rollback` 逆序恢复：重新启用并启动服务、恢复运行级别、恢复自启行（文件在接管后未被改动、且备份可读时从备份恢复，否则只还原被注释的那一行；该行已被手工还原时视为已恢复）、按原命令行、环境变量和身份（用户、组与附加组）重启手动进程；宿主单元（如 `cron.service`）不会再次启动它，因此宿主单元中的进程同样由本程序重启。systemd 主机上重启的进程放入独立的临时 scope（`anixops-mesh-restored-<pid>.scope`），不随执行回滚的 SSH 会话或 Agent 服务一起结束；无法创建 scope 时进程照常运行，结果中注明。执行回滚前先停止我方节点。全部恢复后清空记录。

## 安装（Linux）

[`apps/mesh-node/install/install-linux.sh`](../../apps/mesh-node/install/install-linux.sh) 是一条命令安装脚本：下载程序并校验 SHA-256（值由面板生成的安装命令给出），可选下载并校验接管数据文件，执行导入预检；程序支持 `run` 时才接管、注册 systemd 或 OpenRC 服务并启动，启动失败自动停止我方服务并回滚接管。`--uninstall` 停止并删除我方服务后回滚接管。下载只走 https：curl 限定 `--proto =https`，GNU wget 加 `--https-only`（BusyBox wget 不支持跳转限制，由哈希校验兜底）。CI 对脚本做 `sh -n` 与 shellcheck 检查。

### 尚未覆盖的安全项

- 程序与数据文件只校验面板给出的 SHA-256，尚未校验发布签名；面板应以构建证明（`actions/attest`）核对发布产物后再生成安装命令。签名校验与一次性入网凭据流程在内核 0.4 与上报一起设计。
- `run` 启动前与现有程序的端口、网卡冲突检查属于节点运行侧（退出码 3），见 outbound mesh 的运行文档。

### 发布产物

每个 `v*` 标签的发布附带以下文件，各有 `.sha256` 和 GitHub 制品证明：

| 文件 | 内容 |
| --- | --- |
| `anixops-mesh-<版本>-x86_64-unknown-linux-musl` | 静态程序，无动态依赖 |
| `anixops-mesh-<版本>-aarch64-unknown-linux-musl` | 同上 |
| `anixops-mesh-<版本>-install-linux.sh` | 本节的安装脚本 |

构建脚本是 [`.github/scripts/build-mesh-node.sh`](../../.github/scripts/build-mesh-node.sh)，CI 的「Mesh node static build」在每次 Rust 改动时用同一脚本构建两种架构，确认程序静态链接、x86_64 版本可运行。32 位 ARM 与 MIPS 随 OpenWrt 软件包（内核 0.5）提供。

## 接管数据文件格式

```json
{
  "profile_version": 1,
  "label": "现有组网程序",
  "source_version": "1.0",
  "detect": { "executables": ["…"], "services": ["…"], "packages": ["…"], "images": ["…"] },
  "config": {
    "file_flags": ["-c"], "file_env": "…", "dir_flags": ["…"], "dir_env": "…",
    "stdin_name": "-", "env_prefix": "…", "ignore_file_keys": ["…"]
  },
  "fields": {
    "network_name": { "file": "a.b", "flags": ["--x"], "env": "…" },
    "peers": { "file": "peer", "file_item": "uri", "flags": ["-p"], "split": ",", "greedy": true, "merge": "append" },
    "encryption": { "file": "flags.x", "set": [{ "flags": ["-u"], "value": false }] }
  },
  "listener_shorthand": { "default_port": 0, "transports": [{ "name": "tcp", "offset": 0 }] },
  "default_listeners": ["…"],
  "default_peer_ports": { "tcp": 0 },
  "drop": [{ "file": ["…"], "flags": ["…"], "env": ["…"], "takes_value": true, "reason": "exit_node" }]
}
```

- `fields` 的键是我方字段：`network_name`、`network_secret`、`secure_mode`、`secure_private_key`、`encryption`、`cipher`、`ipv4`、`ipv6`、`auto_address`、`listeners`、`peers`、`subnets`、`latency_first`、`relay_disabled`、`system_routes`、`mtu`、`enable_ipv6`、`hostname`、`instance_name`。前三项和 `ipv4` 必填。
- 布尔字段的参数是开关（可跟 `true`/`false`）；`set` 声明「出现即设为某值」的开关，只能设布尔或空列表。
- 列表项是表时，`file_item` 指定取值的键，`file_item_mapped` 指定映射网段的键，`file_item_confirm` 列出需确认的附加键。
- 每个参数只能有一个含义，未知键一律报错，数据文件写错会在加载时失败。
- `drop[].reason` 取值：`exit_node`、`port_forward`、`local_proxy`、`vpn_portal`、`management_port`、`remote_config`、`credential_mode`、`transport_proxy`、`compression`、`name_resolution`、`access_rules`、`shared_relay`、`nat_traversal`、`rate_limit`、`local_detail`、`obsolete`、`logging`、`mapped_listeners`。

## 分阶段

| 版本 | 内容 |
| --- | --- |
| 内核 0.3 / 客户端 1.1 | 本文的检测、导入、接管与回滚（Linux）；Linux 安装脚本 |
| 内核 0.4 / 客户端 1.2 | Windows 服务与 macOS launchd 的检测、接管与安装；只读上报在线与延迟 |
| 内核 0.5 / 客户端 1.3 | OpenWrt 软件包（musl 静态、procd、UCI）与网页插件；软件包安装方式的检测与停用 |
