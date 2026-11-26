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

`capabilities` 的命令列表包含 `enroll`、`device`、`device-status` 时，安装器才走无 Agent 路径。受管组网在 Linux（含 OpenWrt）、macOS、Windows 上编译，这四个命令（含 `subnet-request`）在这三个平台的构建中都列出，行为与退出码在三个平台上相同；平台之间只有状态目录、本机状态接口与服务管理不同（见下文）。`--state-dir` 省略时为默认状态目录。实现见 `apps/mesh-node/src/device_run.rs`（传输 `https.rs`，本机状态接口 `local_status.rs`，Windows 访问控制 `win_security.rs`）。

凭据从文件读取（安装器写入 0600 临时文件，用后删除），不从命令行参数读取，避免出现在进程列表与 shell 历史中。

## 状态目录

| 平台 | 默认状态目录 | 权限 |
|---|---|---|
| Linux | `/var/lib/anixops-mesh/device`（OpenWrt 见下文） | 0700，root 所有 |
| macOS | `/Library/Application Support/AnixOps/mesh/device` | 安装器建为 0710，root 所有，属组 `admin`（管理员只能穿过目录访问状态套接字，不能列出目录；其中文件均为 0600，读不到内容）；程序自行创建时为 0700，此时只有 root 能用状态套接字 |
| Windows | `%ProgramData%\AnixOps\Mesh\device` | 只有 SYSTEM 与 Administrators 有访问权，不继承上级目录的权限 |

Linux 的默认目录与同机 anixcore 的 `/var/lib/anixcore/mesh` 分开，避免共用实例 ID。目录要求与接管状态目录相同：

- Linux、macOS：本用户所有、各级上级目录不可被其他用户写、不是符号链接，每次读写都以不跟随符号链接的方式逐级打开。macOS 的 `/etc`、`/var`、`/tmp` 是符号链接，所以状态目录放在 `/Library` 下。
- Windows：目录及各级上级目录不是链接或联接点，属于 SYSTEM、Administrators 或 TrustedInstaller；目录本身只有这些账户可以修改，上级目录不允许其他账户替换其中内容。`enroll` 在目录不存在时一次性创建它并带上上述访问列表（`D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`），之间没有对其他账户开放的时刻；已存在的目录不改动，由上述检查决定能否使用（安装器在接入前把访问列表改成同样的内容）。目录中的文件继承这份访问列表，表中的 0600 在 Windows 上即指此。

| 文件 | 权限 | 内容 |
|---|---|---|
| `device.json` | 0600 | `{"schema_version":1,"control":"https://…","device_id":5,"device_key":"…"}` |
| `token` | 0600 | 设备令牌 `msd_…` |
| `config.json` | 0600 | 最近一份通过校验的 `networks`（含网络密钥） |
| `instance_id`、`keys/` | 0600 | 受管组网的实例 ID 与各网络静态密钥（布局同 anixcore） |
| `status.sock` | 0660，属组 `anixops-mesh`（macOS 为 `admin`） | 本机状态套接字（见下文；Windows 上不是文件，改用命名管道） |
| `device.log`、`device.log.1` | 继承目录 | 仅 Windows：服务方式运行时的标准错误输出（见「服务管理」） |
| `device.lock` | 0600 | `device` 运行期间持有的排他锁，防止同一状态目录上同时运行两个服务（由系统在进程退出时释放） |

`device_key`：首次接入时由系统随机数生成 32 字节，标准 base64 编码（44 个字符），此后一直沿用；重新接入同一设备必须使用同一值（面板以之核对）。删除状态目录即放弃该设备身份，需要管理员为新设备签发凭据。

## 接入

1. 读取凭据文件，去掉首尾空白后必须以 `mse_` 开头、只含 ASCII 可见字符、不超过 256 字节。
2. `POST {control}/api/v5/mesh/device/enroll`，请求体 `{"token","device_key","latencies","features"}`；不带 `static_key`（网络公钥在取得配置后才生成，由首次上报提交）。
   - `latencies`：`--latency` 给出的地区时延；未给出时为空对象。无 Agent 安装应由管理员在签发凭据时指定地区（完整节点必须指定），面板无法核实设备自报的时延。
   - `features`：本程序受管组网支持的能力名单，与 `GET /v1/status` 的 `features` 同一来源。
3. 发出请求之前先写入 `device.json`（还没有 `device_id`）：状态目录里已有 `device.json` 时沿用其中的 `device_key`，否则新生成一个。这样应答丢失后重新执行时用的是同一个 `device_key`。
4. 201：校验应答（见「配置校验」），依次写入带 `device_id` 的 `device.json`、`token`、`config.json`（各自先写临时文件再改名）。应答丢失或写入失败时，同一凭据与同一 `device_key` 在 10 分钟内可以重试（面板保证），程序不自动重试，由安装器提示重新执行。成功时标准输出为 `{"ok":true,"device_id":5,"networks":1}`。
5. 401、409：退出码 8，除第 3 步的 `device.json` 外不写任何文件。其他状态码、超时或应答无效：退出码 9。

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

## 本机状态接口

`device` 在本机状态接口上回答一行 JSON 请求 `{"cmd":"mesh_status"}`：

- Linux、macOS：状态目录中的 `status.sock`（Unix 域套接字，0660，属组 Linux 为 `anixops-mesh`、macOS 为 `admin`）。上次运行留下的套接字会被替换，同名的其他文件则拒绝绑定。
- Windows：命名管道 `\\.\pipe\anixops-mesh-device-<16 位十六进制>`，十六进制为 `<状态目录>\status.sock` 的绝对路径转小写后 SHA-256 的前 8 字节（管道名是全机共用的命名空间，按状态目录区分）。访问列表 `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;BU)`：SYSTEM 与 Administrators 完全控制；本机 Users 只能连接、读取和写入请求（`FILE_GENERIC_READ | FILE_WRITE_DATA`），不能创建管道实例、修改访问列表或取得所有权。拒绝远程客户端。服务以「首个实例」方式创建管道；管道已存在（已有服务在运行，或服务停止期间被其他程序抢先创建）时记录一次 `status_socket`，此后每 10 秒重试，网络照常运行（其他平台绑定失败时同样重试）。客户端只请求 `FILE_GENERIC_READ | FILE_WRITE_DATA` 打开管道，不请求通用写权限（其中的追加权限对管道即创建实例）。`device-status` 只接受所有者为 SYSTEM、Administrators 或调用者本人的管道，并以 `SECURITY_IDENTIFICATION` 连接，服务端只能识别、不能冒充调用者。

应答为受管组网状态加上设备字段：

```json
{"ok":true,"device":{"device_id":5,"control":"https://…","last_config":"2026-11-25T21:00:00Z","last_report":"2026-11-25T21:00:03Z","control_state":"ok","advertise":["192.168.1.0/24"]},"mesh":{"instance_id":"…","networks":[…]}}
```

`control_state`：`ok`、`unreachable`（最近一次读取或上报失败）、`rejected`（最近一份配置未通过校验）。`advertise`：`config.json` 各网络 `subnets.advertise` 的并集，即面板已批准并下发的通告网段（按网段排序去重；未接入或没有配置时为空数组），LuCI 据此区分「已批准」与「待管理员批准」。`device-status` 连接时读写超时各 3 秒，服务未运行或无应答时以退出码 1 结束，不会挂住调用方（rpcd 同步调用）。只接受这一条命令，其他请求回 `{"ok":false,"error":{"code":"unsupported"}}`；不监听 TCP 或 UDP 端口（R11）。实现放在 `apps/mesh-node/src/local_status.rs`，`run` 路径以同一文件经 `serve_with` 的观察回调提供 `mesh-status.md` 的快照。

## 服务管理

`device` 收到停止请求（SIGTERM、SIGINT、Ctrl+C，或 Windows 服务管理器的停止与关机通知）时停止全部网络、删除状态套接字并以 0 退出。令牌失效（退出码 8）不应被自动重启：

| 平台 | 服务 | 退出码 8 |
|---|---|---|
| Linux | systemd：`Restart=on-failure`，`RestartPreventExitStatus=8` | 不重启 |
| OpenWrt | procd（见下文） | init 脚本判断后不再拉起 |
| macOS | launchd 系统守护进程 `com.anixops.mesh.device`（`/Library/LaunchDaemons/com.anixops.mesh.device.plist`），`RunAtLoad`，`KeepAlive` 为 `PathState`：`<状态目录>/token` 存在时保持运行，`ThrottleInterval` 30 秒；`Umask` 077；标准错误写入 `/Library/Logs/anixops-mesh-device.log`（安装器建为 root:admin 0640，`--purge` 删除；日志只在出错与退避时写入，不轮转） | 程序已删除 `token`，launchd 不再拉起；重新接入写回 `token` 后由 launchd 自动启动。`token` 存在但内容无效时同样以 8 退出，launchd 每 30 秒重试一次，直至重新接入 |
| Windows | 服务 `AnixOpsMeshDevice`（LocalSystem，自动启动），恢复操作为失败后 5 秒重启，`sc failureflag 1` | 程序向服务管理器报告为正常停止（`WIN32_EXIT_CODE` 0），恢复操作不生效；从控制台运行时退出码仍为 8 |

Windows 服务没有控制台：由服务管理器启动时，`device` 把标准错误改写到状态目录的 `device.log`（追加；每次启动时超过 1 MiB 的旧日志改名为 `device.log.1`，覆盖更早的一份）。日志内容与其他平台的标准错误相同，不含令牌、凭据与网络密钥。

受管组网在 macOS、Windows 上与 Linux 一样只建立虚拟网卡与路由，不改动主机转发、源地址转换或防火墙；作为完整节点通告局域网网段、或在 Windows 上接受入站连接，需要的主机改动与完整节点 `run` 的做法（`forward_macos.rs`、`forward_windows.rs`）在受管组网中尚未接入，见后续事项。

## 安装（macOS、Windows）

安装器把程序放到独立位置，接入后注册并启动服务；已接入（状态目录中有 `token` 与 `device.json`）时不再接入，只替换程序并重启服务。凭据只从文件读取或在终端隐藏输入，不出现在命令行中；安装器用后即删除临时凭据文件。面板使用私有 CA 时，CA 文件复制到状态目录旁（macOS `/Library/Application Support/AnixOps/mesh/control-ca.pem`，Windows `%ProgramData%\AnixOps\Mesh\device-control-ca.pem`）再传给 `--ca-file`。

- macOS（root 运行）：`install-device-macos.sh (--binary-url URL | --binary-file FILE) --binary-sha256 HEX --control URL [--token-file FILE] [--latency CODE=MS]... [--ca-file FILE]`。程序在 `/Library/Application Support/AnixOps/mesh/bin/anixops-mesh`。
- Windows（管理员运行）：`install-device-windows.ps1 (-BinaryUrl URL | -BinaryFile FILE) -BinarySha256 HEX (-WintunUrl URL | -WintunFile FILE) -WintunSha256 HEX -Control URL [-TokenFile FILE] [-Latency CODE=MS,...] [-CaFile FILE]`。程序与 `wintun.dll`（核对架构）在 `%ProgramFiles%\AnixOps\Mesh\device`，程序只从自身目录加载 `wintun.dll`。

下载只接受 https，并核对 SHA-256；程序的 `capabilities` 必须列出 `enroll`、`device`、`device-status`。接入退出码 8 时提示向管理员索取新凭据，9 时提示在 10 分钟内用同一凭据重试。服务启动后以 `device-status` 确认在 10 秒内应答，否则停止并删除服务（接入结果保留，可重新运行安装器）。

卸载：`install-device-macos.sh --uninstall [--purge]`、`install-device-windows.ps1 -Uninstall [-Purge]`：停止并删除服务与程序；状态目录（设备身份）默认保留，`--purge`/`-Purge` 一并删除。卸载不通知面板，管理员需在面板吊销该设备。

CI（`mesh-node-desktop` 作业）在 macos-26 与 windows-latest 上以模拟面板（私有 CA）走完安装、接入、上报、重复安装、令牌吊销与卸载，并检查状态目录权限与状态接口（`.github/scripts/mesh-device-smoke-macos.sh`、`mesh-device-smoke-windows.ps1`）。

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
