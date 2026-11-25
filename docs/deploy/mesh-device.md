# 无 Agent 组网设备（R31、R32、R35）

未安装 Agent 的机器（服务器、路由器、OpenWrt）由独立程序 `anixops-mesh` 直接接入面板。面板一侧的接口见 anix-control `docs/design/mesh-regions/agent-contract.md` §4，本页是程序一侧的约定。接管与导入见 [`mesh-node.md`](mesh-node.md)，状态字段见 [`mesh-status.md`](../architecture/mesh-status.md)。

原则：设备只**读取**本机成员信息、只**上报**状态与时延，不接受面板的任何指令（R31）；不新增网络监听端口（R11）。网络运行与 Agent 路径共用同一套代码：面板下发的扁平网络按与 Agent 相同的方式转为分层的 `config_version: 1` 配置并加 `tag = mesh-<id>`，即本机管理 API `PUT /v1/mesh` 的请求体（`dns`、`dns.resolver_address` 按本机能力决定是否带上），交给同进程的受管组网（`ManagedMesh::apply`）；上报取同一受管组网的状态（与 `GET /v1/mesh` 应答同构）。准入（`native_keys`）、暂缓与失败码因此与 Agent 节点完全一致。

## 子命令

| 子命令 | 作用 | 退出码 |
|---|---|---|
| `enroll --control URL --token-file FILE --state-dir DIR [--latency CODE=MS]... [--ca-file FILE]` | 以一次性凭据接入，保存设备令牌与首份配置 | 0 成功；2 用法或状态目录错误；8 凭据被拒（401、409）；9 面板不可达或应答无效 |
| `device --state-dir DIR` | 常驻服务：运行网络、每分钟读取配置、每分钟上报 | 0 收到停止信号；8 令牌失效（需重新接入）；1 其他错误 |
| `subnet-request --state-dir DIR [--cidr CIDR]...` | 申请通告局域网网段（仅完整节点；至多 16 个内网网段；不带 `--cidr` 为撤回），由管理员在面板批准后经配置下发；面板不提供申请状态查询，LuCI 对比下发的 `subnets.advertise` 自行判断；LuCI 经 rpcd 调用 | 0 已提交（202）；2 用法或状态目录错误（含主机位非零的网段，不做规范化）；8 令牌失效（401）；9 面板不可达或应答无效；10 面板拒绝（400 `invalid_request`，或接入端申请时 409 `mesh_conflict`），标准错误末行 JSON 的 `detail` 带面板返回的 `code` |
| `device-status --state-dir DIR` | 经本机状态套接字读取快照（JSON），供 LuCI 与排障 | 0；1 服务未运行 |

`capabilities` 的命令列表包含 `enroll`、`device`、`device-status` 时，安装器才走无 Agent 路径。受管组网目前只在 Linux 编译，所以这三个命令首先在 Linux 与 OpenWrt 提供；macOS、Windows 的无 Agent 运行在受管组网移植后再列出。

凭据从文件读取（安装器写入 0600 临时文件，用后删除），不从命令行参数读取，避免出现在进程列表与 shell 历史中。

## 状态目录

默认 `/var/lib/anixops-mesh/device`，与同机 anixcore 的 `/var/lib/anixcore/mesh` 分开，避免共用实例 ID。目录要求与接管状态目录相同（本用户所有、各级上级目录不可被其他用户写、不是符号链接），每次读写都以不跟随符号链接的方式逐级打开。

| 文件 | 权限 | 内容 |
|---|---|---|
| `device.json` | 0600 | `{"schema_version":1,"control":"https://…","device_id":5,"device_key":"…"}` |
| `token` | 0600 | 设备令牌 `msd_…` |
| `config.json` | 0600 | 最近一份通过校验的 `networks`（含网络密钥） |
| `instance_id`、`keys/` | 0600 | 受管组网的实例 ID 与各网络静态密钥（布局同 anixcore） |
| `status.sock` | 0660，属组 `anixops-mesh` | 本机状态套接字（见下文） |

`device_key`：首次接入时由系统随机数生成 32 字节，标准 base64 编码（44 个字符），此后一直沿用；重新接入同一设备必须使用同一值（面板以之核对）。删除状态目录即放弃该设备身份，需要管理员为新设备签发凭据。

## 接入

1. 读取凭据文件，去掉首尾空白后必须以 `mse_` 开头、只含 ASCII 可见字符、不超过 256 字节。
2. `POST {control}/api/v5/mesh/device/enroll`，请求体 `{"token","device_key","latencies","features"}`；不带 `static_key`（网络公钥在取得配置后才生成，由首次上报提交）。
   - `latencies`：`--latency` 给出的地区时延；未给出时为空对象。无 Agent 安装应由管理员在签发凭据时指定地区（完整节点必须指定），面板无法核实设备自报的时延。
   - `features`：本程序受管组网支持的能力名单，与 `GET /v1/status` 的 `features` 同一来源。
3. 201：校验应答（见「配置校验」），依次写入 `device.json`、`token`、`config.json`（各自先写临时文件再改名）。应答丢失或写入失败时，同一凭据与同一 `device_key` 在 10 分钟内可以重试（面板保证），程序不自动重试，由安装器提示重新执行。
4. 401、409：退出码 8，不写任何文件。其他状态码、超时或应答无效：退出码 9。

## 常驻服务

启动时没有 `token`（从未接入或令牌已失效）即以退出码 8 结束，不建网络、不写任何文件。否则先应用 `config.json`（面板暂时不可达时网络照常运行），再进入循环：

- **读取配置**：每 60 秒（加 0–5 秒随机偏移）`GET {control}/api/v5/mesh/device/config?features=…`。通过校验的配置与当前不同时调用 `apply` 并写入 `config.json`（内容不变时不写，减少闪存写入）；`networks` 为空表示地区已停用，停止全部网络。校验不通过时保留现有配置，记录 `config_rejected`（只写字段名与规则，不写取值），下次照常读取。
- **上报**：每 60 秒，以及受管组网状态变化时（至多每 10 秒一次），`POST {control}/api/v5/mesh/device/report`。请求体为 `{"instance_id","networks":[…],"features":[…]}`：`networks` 每项取受管组网状态中的一项，把 `tag` 换回地区代码作为 `id`，并按网络名附上 `static_key`（字段与 Agent 的 `mesh.status` 相同，见 agent-contract §3）。接管记录存在时另带 `takeover: {"found","stopped","error"}`。只认 204，应答体一律忽略。
- **令牌失效**：读取配置或上报返回 401 时，停止全部网络、删除 `token`，以退出码 8 结束。服务单元把 8 设为不重启（systemd `RestartPreventExitStatus=8`，procd 由 init 脚本判断），等待管理员签发新凭据重新接入。面板吊销设备时已把它的公钥移出 `native_keys`，网络本来也会被其他成员拒绝。
- **面板不可达**：超时、连接失败、5xx 时保留现有网络，按 60 秒、120 秒、240 秒直到 10 分钟的间隔退避，成功后恢复 60 秒。连续失联只记录，不停止网络。
- **限流**：429 按 `Retry-After`（至多 10 分钟）推迟，未给出时按上面的退避。

## 配置校验

面板不经此接口下发指令，设备也拒绝任何多余内容（R31）：

- 应答必须是 `{"data":{"networks":[…]}}`；接入应答为 `{"data":{"device_id","device_token","config":{"networks":[…]}}}`。其他顶层字段、`data` 中的其他字段都使整份应答无效。
- 每个网络只允许 `id`、`name`、`kind`、`native_keys`、`secret`、`secure_mode`、`cipher`、`address`、`role`、`listen`、`peers`、`subnets`、`routing`、`dns`，出现其他字段（包括 Agent 才有的 `host_groups` 与顶层 `takeover`）即整份无效。
- `id` 为地区代码（2–16 位小写字母、数字或连字符，字母开头，不以连字符结尾），不重复，至多 64 项；`name` 必须等于 `mesh-<id>`；`kind` 必须是 `managed`（设备只加入受管地区网络，不加入旧网络）。
- 其余字段的取值规则由受管组网的配置校验负责（与 `PUT /v1/mesh` 相同，任一项无效则整份不应用）。
- 应答体上限 1 MiB；状态码不是 200（接入为 201）时不解析应答体。

## 传输

- 只用 HTTPS。`--control` 必须是 `https://主机[:端口]`，不带路径、查询、用户信息；不跟随重定向。
- 证书按内置的公共根证书校验（静态程序不依赖系统证书库，OpenWrt 上也可用）；面板使用私有 CA 时以 `--ca-file` 指定，接入时写入 `device.json` 的 `ca_file`，此后只信任该文件中的证书。
- 连接超时 10 秒，整个请求 30 秒。`User-Agent` 为 `anixops-mesh/<版本>`。
- 令牌、凭据、网络密钥不出现在日志、错误信息与 `device-status` 输出中。

## 本机状态套接字

`device` 在 `status.sock`（Unix 域套接字，0660，属组 `anixops-mesh`）上回答一行 JSON 请求 `{"cmd":"mesh_status"}`，应答为受管组网状态加上设备字段：

```json
{"ok":true,"device":{"device_id":5,"control":"https://…","last_config":"2026-11-25T21:00:00Z","last_report":"2026-11-25T21:00:03Z","control_state":"ok"},"mesh":{"instance_id":"…","networks":[…]}}
```

`control_state`：`ok`、`unreachable`（最近一次读取或上报失败）、`rejected`（最近一份配置未通过校验）。只接受这一条命令，其他请求回 `{"ok":false,"error":{"code":"unsupported"}}`；不监听 TCP 或 UDP 端口（R11）。实现放在 `apps/mesh-node/src/local_status.rs`，`run` 路径以同一文件经 `serve_with` 的观察回调提供 `mesh-status.md` 的快照。

## OpenWrt（R35，内核 0.5）

- 软件包 `anixops-mesh`（ipk 与 apk 各一份），只含本程序、procd 脚本与默认 UCI 配置；musl 静态构建，目标 `aarch64`、`arm`（armv7）、`mips`/`mipsel`、`x86_64`，安装后占用不超过 4 MiB 闪存。
- UCI `/etc/config/anixops-mesh`：

  ```
  config device 'main'
  	option enabled '1'
  	option control 'https://panel.example.com'
  	option state_dir '/etc/anixops-mesh'
  ```

  OpenWrt 的 `/var` 在内存中，状态目录放在 `/etc/anixops-mesh`，并列入 `/lib/upgrade/keep.d/anixops-mesh`，系统升级后保留设备身份。
- procd 服务运行 `anixops-mesh device --state-dir …`，`respawn` 遇到退出码 8 时不再拉起（init 脚本检查退出码，记录日志后停止）。
- LuCI 插件 `luci-app-anixops-mesh`：页面经 rpcd 调用 `anixops-mesh device-status` 读取成员、子网、路径与时延，以查看为主；填入凭据时调用 `enroll`（凭据经 rpcd 写入 0600 临时文件）。插件不新增监听端口。通告哪些局域网网段由管理员在面板确认（`PUT /api/v4/kernel/mesh/devices/{id}/subnets`），设备经 `subnet-request`（面板 `POST /api/v5/mesh/device/subnet-request`）提交申请，批准前 LuCI 显示为「待管理员确认」；设备不能自行通告。
- 接管原程序的三种装法（软件包、自写启动脚本、手动运行）沿用 `takeover`；OpenWrt 的 procd 与 `/etc/init.d` 检测随 0.5 加入。

## 卸载

`anixops-mesh rollback --state-dir <接管状态目录>` 恢复原程序，然后删除服务、程序与设备状态目录。卸载不通知面板：管理员在面板吊销或删除该设备，其公钥随之移出准入清单。
