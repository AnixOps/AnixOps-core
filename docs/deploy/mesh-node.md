# 组网节点部署：接管、导入与安装

`anixops-mesh`（`apps/mesh-node`）是只含组网模块的独立程序。Agent、无 Agent 机器的一条命令安装和 OpenWrt 软件包都用它，接管与导入逻辑只有这一份（需求 R12、R13、R15、R31、R32、R35）。节点运行子命令 `run` 由组网模块提供，见 [组网模块设计](../architecture/mesh-module.md)。

本程序不包含任何其他组网程序的名称、路径或配置格式。识别一种现有程序所需的全部信息写在**接管数据文件**（profile）里，由部署层维护并在运行时用 `--profile` 传入。公开仓库只带一份虚构程序 `demo-meshd` 的样例：[`apps/mesh-node/testdata/demo-profile.json`](../../apps/mesh-node/testdata/demo-profile.json)。

## 子命令

| 子命令 | 作用 | 退出码 |
| --- | --- | --- |
| `run --config F [--interface N]` | 运行节点（Linux）：读取导入或面板写入的组网配置，绑定监听端口，创建 TUN 网卡（默认 `anixmesh0`），直到 SIGTERM/SIGINT。静态私钥取配置的 `node.private_key`，没有时用配置旁的 `<配置>.key`（首次运行生成，0600）。`managed` 网络的 `native_keys` 缺省、为空或不含本机公钥时暂缓（规范 §8.3.1）：不监听、不建网卡，输出一行 `{"state":"not_joined","reason":"native_keys_pending","static_key":…}` 后等待信号，退出码 0；Agent 上报公钥、面板下发含本机公钥的清单后重启服务即入网。状态行带 `static_key`（旧模式为 `null`）与最近一次被拒的非我方节点 `not_native`。与第三方节点的互通测试在 CI 中通过前，`run` 不列入 `capabilities`，安装器因此不会接管现有网络 | 0 收到信号正常停止；1 运行错误；2 用法或配置错误；3 端口或网卡被占用 |
| `capabilities` | 输出版本和本构建支持的子命令（JSON）。安装器只有在列表含 `run` 时才执行接管 | 0 |
| `detect --profile F` | 列出本机的现有安装（服务、启动脚本、自启行、手动进程、容器）。只输出参数名，不输出任何取值 | 0；2 用法错误 |
| `import --profile F [--out-dir D] [--report R] [--allow-unencrypted] [--address CIDR] [-- ARGS…]` | 按检测结果（或 `--` 后手动给出的命令行）生成我方配置和导入报告 | 0 全部可用；3 未发现；5 有需确认项；6 有无法自动迁移的实例 |
| `takeover --profile F --state-dir S [--dry-run] [--report R]` | 停用并停止现有安装，记录到 `S/takeover.json`。`--dry-run` 只列计划，但同样做改动前的检查 | 0 完成、已计划或无事可做；1 失败且已回滚，或在任何改动之前拒绝（`outcome` 为 `refused`，不写记录）；7 失败且回滚也失败 |
| `rollback --state-dir S [--forget-process PID… --confirm] [--report R]` | 按记录逆序恢复；`--forget-process` 见下文 | 0；7 部分步骤失败或记录无法保存 |

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

数据来源按程序所运行的系统选择，而不是看某个路径是否存在：`/proc`、`/etc`、`/var/spool/cron`、`/run/systemd` 只在 Linux 上读取（init 脚本、自启行与容器在其他 Unix 上也读取），macOS 只读进程表与 launchd，Windows 只读进程表、服务、计划任务与登录自启项。Windows 上这些 Unix 路径是系统盘根目录下的普通目录（如 `C:\proc`、`C:\etc`），任何本地用户都能创建，读取它们会让该用户伪造进程、自启行与导入的配置。

## 检测（macOS）

macOS 没有 `/proc`，进程从系统进程表读取：程序路径用 `proc_pidpath`，命令行与环境变量用 `KERN_PROCARGS2`（与内核保存的完全一致），实际用户与组用 `proc_pidinfo`，附加组按该用户登录时的组（`getgrouplist`，与 launchd 和登录 shell 给进程的组一致）。进程表中没有容器、cgroup 与网络命名空间，相关检查在 macOS 上不适用。

| 来源 | 方法 |
| --- | --- |
| 系统守护进程 | `/Library/LaunchDaemons/*.plist`，域 `system` |
| 用户代理 | `/Users/<用户>/Library/LaunchAgents/*.plist`（按用户安装的软件包管理器把服务放在这里），域为文件属主的 `gui/<uid>`；属主为 root 的文件忽略 |
| 所有用户共用的代理 | `/Library/LaunchAgents/*.plist`：每个登录用户各加载一份，只报告，不接管，列入需人工处理 |
| 手动进程 | 进程表中程序名匹配、且不属于以上任何任务的进程 |

任务文件用 `plutil -convert json` 读取（XML 与二进制格式都支持），读不出的文件跳过。`Program` 或 `ProgramArguments[0]` 的文件名在 `detect.executables` 里、`sh`/`bash`/`zsh`/`dash -c` 的命令以该程序开头、或 `Label` 在 `detect.services` 里时视为该程序的任务。是否已加载及其进程取自 `launchctl print <域>/<Label>`；是否被关闭取自 `launchctl print-disabled <域>`（`launchctl disable`/`enable` 的覆盖值优先于任务文件的 `Disabled` 键）。命令行优先取自任务的进程，其次取自任务文件。任务的进程是 launchd 给出的 pid 及其子孙进程（如 shell 启动的程序）；以相同命令行手工启动的另一份不算任务的进程。

## 检测（Windows）

进程从系统进程表读取：`CreateToolhelp32Snapshot` 列出进程与父进程，程序路径用 `QueryFullProcessImageNameW`，命令行用 `NtQueryInformationProcess`（按 C 运行库规则拆分），工作目录与完整环境变量从进程参数块读取（64 位），运行账户取自进程令牌（SID）。程序名比较不区分大小写，`name.exe` 与 `name` 相同。

| 来源 | 方法 |
| --- | --- |
| 服务 | 一次 PowerShell 查询 `Win32_Service`（名称、命令行、启动方式、状态、进程）。命令行运行该程序、或服务名在 `detect.services` 里（以包装程序启动的服务）时视为该程序的服务；服务的进程是服务进程及其子孙进程（包装程序可能经 `cmd` 再启动程序）。查询结果没有延迟启动标志时（较旧的系统），从服务注册表项的 `DelayedAutostart` 读取 |
| 计划任务 | 一次 PowerShell 查询 `Get-ScheduledTask`（路径、名称、状态、可执行操作）与任务计划程序服务的进程。某个操作的程序名匹配、或任务名在 `detect.services` 里时视为该程序的任务；运行中任务的进程是任务计划程序服务的直接子进程（数据文件点名的包装任务为其子孙进程） |
| 登录自启项 | 一次 PowerShell 查询：本机 `Run` 键（64 位与 32 位）、已加载配置的每个用户的 `Run` 键、公共启动文件夹与每个用户配置文件的启动文件夹（快捷方式读取目标、参数与工作目录），以及各项在 `Explorer\StartupApproved` 下的当前值。命令行的程序名匹配时视为该程序的自启项。不检测：未登录用户（配置未加载）的 `Run` 键、`RunOnce`、`Policies\Explorer\Run` 与 Winlogon 的 `Userinit`/`Shell`（后两者不受 `StartupApproved` 控制）；这些位置启动的原程序需人工停用（#330 复审 L2，下一个小版本补报告） |
| 手动进程 | 进程表中程序名匹配、且不属于以上任何一项的进程 |

未登录用户的 `Run` 键不在已加载的注册表中，不读取；其启动文件夹中的项只报告，列入需人工处理。经 `cmd /c` 等包装的自启项不识别，它启动的进程按手动进程处理。

## 导入（R13、R14、R15）

导入是单向转换，输出 `"type": "mesh"` 出站的 config v1（`config_version: 1`），每个网络实例一个文件，写入 `--out-dir`，权限 0600（含网络密钥）。设置的来源按「配置文件 → 环境变量 → 命令行」合并，后者覆盖前者；数据文件可声明列表项追加（`merge: append`）。一个目录中的多个配置文件各是一个实例，命令行只覆盖网络名相同的那个实例。

| 我方字段 | 规则 |
| --- | --- |
| `network.name` / `network.secret` | 原样导入；缺失或为空时无法迁移。密钥不进报告 |
| `network.kind` | 一律写 `legacy`（迁移中的现有网络，允许默认握手模式）。导入与接管不产生 `managed` 网络，也不提供把原版节点直接迁入 `managed` 网络的路径 |
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

原版节点（未换成我方内核的节点）一律留在 `legacy` 网络，经我方桥接节点与区域网络互通；换成我方内核之后，才能加入 `managed` 网络。部署层不提供跳过桥接、把原版节点直接加入 `managed` 网络的做法。

旧网不拆分，超大旧网不建桥（规范 §11.2「接收」与 §15.11.1）。桥接节点的旧网实例要接收原版节点对整个旧网的全量同步，上限为 4096 个节点、8 MiB。规模在桥接节点上实测，不在导入时估算（`import` 只看到本机一个原版节点的配置，看不到整个旧网）：

1. 桥接节点先以普通成员加入旧网：只加入 `legacy` 网络，不通告任何区域网段，也不加入区域网络。
2. 同步稳定后（加入后至少 5 分钟，且最近 2 分钟成员数没有变化），读取该网络快照的 `members` 数。成员数（含本机）超过 4096，或该网络出现过同步超限告警（`alerts` 中的 `sync_oversize`：收到的同步重组或解压后超过 8 MiB 被丢弃，或连接图截短后仍送达不了、同步会话被关闭，`detail` 分别以 `received:`、`undelivered:` 开头，见规范 §11.2、§12.2），即判定为超大旧网。
3. 超大旧网：不启用桥接，桥接节点退出该旧网，向面板报告原因 `legacy_network_too_large`，`detail` 写成员数或超限的大小；不改原版节点的配置，也不尝试拆分。处理方式见 `docs/manual-intervention.md`「超大旧网不能直接建桥」：先挑一部分节点接管、迁入区域网络，旧网缩小到上限以内再建桥。
4. 未超限：再加入区域网络并通告区域网段，开始桥接。桥接期间旧网成员数超过上限或出现同步超限告警时，同样报告 `legacy_network_too_large`，由管理员决定是否停用桥接。

这项检查由建桥的一方执行（Agent 按面板下发的桥接配置执行，或管理员手工操作时按上面的步骤）。`anixops-mesh` 的接管与导入不建桥，不做这项检查。

换成我方内核的节点加入区域网络时，在面板把本机的静态公钥列入该网络的 `native_keys` 之前，该网络处于 `native_keys_pending`（见 `docs/architecture/mesh-status.md`）：不建立链路，但 `anixops-mesh run` 不退出，服务保持运行。部署层、安装脚本与运维不应据此判定安装失败或回滚；以面板列入公钥后网络转为正常为准。

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

每一步完成后立即写入 `state-dir/takeover.json`（0600，含被结束进程的命令行、完整环境变量、用户和组，以便回滚时以原身份原样重启）。任一步失败时，本次已做的步骤按逆序撤销，退出码 1；撤销也失败时退出码 7，记录只保留没撤销成功的步骤（以及它们需要的备份），之后的 `rollback` 只重试这些步骤。状态目录必须是本用户所有、其他用户不可写的真实目录（不是符号链接），而且从 `/` 到它的每一级上级目录都必须属于 root 或本用户、其他用户不可写（带粘滞位的目录如 `/tmp` 除外），否则拒绝执行。状态目录应使用默认的 `/var/lib/anixops-mesh/takeover` 这类只有 root 可写的路径，不要放在 `/tmp` 下或经符号链接的路径上（后者会被拒绝）。记录文件超过 1 MiB 时不会写入（否则回滚无法读回），该步骤按失败处理并回滚。每次读写锁文件、`takeover.json` 与 `backup/` 下的备份时，都从 `/` 起逐级以不跟随符号链接的方式打开目录并检查，再相对最后得到的目录句柄打开文件（写入先建临时文件，再经同一句柄改名；上次崩溃留下的同名临时文件会先删除），检查与读写之间无法替换。同一状态目录有锁（固定文件 `takeover.lock` 上的内核建议锁，打开时不跟随符号链接），不能并发执行；持有进程退出时锁由内核释放，锁文件保留，不存在需要判断或删除的陈旧锁。

OpenRC 服务只在有运行中的进程时才计划停止。宿主单元的 `Restart=` 不是 `no` 时，结束进程后先等待该单元的重启间隔再加 2 秒（取 `RestartUSec` 与下一次间隔 `RestartUSecNext` 中较大者；设了 `RestartSteps=` 递增间隔时取上限 `RestartMaxDelayUSec`，上限为 infinity 即视为未知），然后确认程序没有被再次启动；这项判定在结束任何进程之前完成，间隔未知或超过 60 秒时不作猜测，不结束任何进程即失败并回滚；结束进程途中失败时（某个进程结束不了），其余进程照常结束并全部记录，然后先等过该间隔再撤销（systemd 默认间隔为 100 毫秒，包装服务常见 1–30 秒；等待期间原网络已中断，上限 1 分钟以限制中断时长）。此类以包装命令启动程序的服务应写进数据文件的 `detect.services`，按程序自己的服务接管。`takeover` 本身不读取导入报告：R15 的拦截（远程配置、映射网段等无法迁移的实例）由调用方负责。安装脚本在导入退出码为 6 时终止；Agent 调用时也必须先执行 `import`，退出码为 6 时不得执行 `takeover`。

`rollback` 逆序恢复：重新启用并启动服务、恢复运行级别、恢复自启行（文件在接管后未被改动、且备份可读时从备份恢复，否则只还原被注释的那一行；该行已被手工还原时视为已恢复）、按原命令行、环境变量和身份（用户、组与附加组）重启手动进程；宿主单元（如 `cron.service`）不会再次启动它，因此宿主单元中的进程同样由本程序重启。systemd 主机上重启的进程在执行程序之前就放入独立的临时 scope（`anixops-mesh-restored-<pid>.scope`，新进程先等待，确认已进入 scope 后才继续），它和它派生的子进程都不随执行回滚的 SSH 会话或 Agent 服务一起结束；无法创建 scope 时进程照常运行，结果中注明。同一程序以相同命令行、相同用户、在容器之外且与原进程同一网络命名空间（接管时记录；旧记录与 PID 1 比较）中已在运行时（例如宿主单元已把它重新拉起）不再启动第二份。挂载命名空间不比较：带 `PrivateTmp=`、`ProtectSystem=` 等选项的单元，以及执行回滚的服务本身，都可能在独立的挂载命名空间中。命令行相同、但程序、用户、cgroup 或网络命名空间读不到（例如安全模块限制）的进程无法判断是否为副本，此时不启动，该步骤保留，之后的 `rollback` 重试。

macOS 上的顺序：备份任务文件 → 已加载的任务先 `launchctl bootout <域>/<Label>`（停止并卸载，有的系统版本卸载成功也报错，以 `launchctl print` 确认已不再加载为准）→ 开机仍会加载的任务再 `launchctl disable <域>/<Label>`（已被关闭、或覆盖值不存在且任务文件 `Disabled` 为真时跳过）→ 结束剩余进程。先卸载后关闭，是因为回滚逆序执行，而 launchd 不加载被关闭的任务：回滚先 `launchctl enable`，再 `launchctl bootstrap <域> <任务文件>`（已加载时跳过）。原来没有覆盖值的任务回滚后留下 `enable` 覆盖值，开机行为与原来一致（只有任务文件未关闭时才会被关闭）。属于已接管任务的进程由重新加载任务启动，回滚时不再单独启动；其他进程按原命令行、环境变量与身份重启。结束了任何进程后，先等 launchd 的默认限流间隔 10 秒再加 2 秒，确认没有未列入数据文件的任务把程序重新拉起。用户代理的 `bootstrap` 需要该用户已登录图形会话，否则该步骤保留，之后的 `rollback` 重试。原来没有覆盖值的任务回滚后保留 `enable` 覆盖值，此后改任务文件的 `Disabled` 键不再生效，需要关闭时用 `launchctl disable`。

Windows 上的顺序：运行中的服务先 `sc.exe stop` 并等待其停止（最长 30 秒）→ 自动、延迟自动或手动启动的服务再 `sc.exe config <名称> start= disabled` → 结束剩余进程（先 `taskkill` 请求关闭，10 秒后 `TerminateProcess`）。先停止后关闭，是因为 Windows 不启动被禁用的服务：回滚先恢复原启动方式，再 `sc.exe start`。驱动类服务（`boot`、`system`）只报告。服务的进程（含包装程序的子孙进程）由重新启动服务恢复，不单独重启；手动进程按原命令行、工作目录与环境变量重启。Windows 无法在没有密码的情况下以其他账户启动进程，因此由其他账户运行、或读不出运行账户的手动进程不会被结束：这项检查在第一步改动之前完成，发现即失败，由操作员手工停止。记录中保存手动进程的运行账户（SID），执行回滚的账户与之不同时（例如管理员接管、以 SYSTEM 运行的 Agent 回滚）不启动该进程，该步骤保留并报告，由原账户执行回滚，或手工启动后 `--forget-process`。结束了任何进程后同样先等 12 秒再确认。

计划任务：运行中的任务先 `schtasks.exe /End /TN <任务>` 并等待其不再运行（最长 30 秒）→ 未关闭的任务再 `schtasks.exe /Change /TN <任务> /DISABLE`。回滚先 `/ENABLE`，原来在运行的任务再 `/Run`（已在运行时跳过）；任务的进程由任务恢复，不单独重启。登录自启项按 Windows 自己的启动项设置关闭：在 `Explorer\StartupApproved\Run`（32 位 `Run` 键为 `Run32`，启动文件夹为 `StartupFolder`）下写入以 `03` 开头的值（`reg.exe add`），写入前再读一次，与检测时不同即失败；`Run` 值与快捷方式本身不改。回滚时该值仍是我方写入的值才恢复原值（原来没有则删除），已被他人改动时保留现状并注明。用户在接管后已注销、其配置不在注册表中时，以 `reg.exe load` 把该用户的 `NTUSER.DAT` 临时加载到 `HKU\anixops-mesh-<SID>`，在其中恢复后立即卸载；加载不了（例如配置文件夹找不到、文件被占用）时该步骤失败并保留在记录中，`rollback` 以退出码 7 结束，下次再试，不会当作「已被他人改动」。已关闭的自启项跳过。接管停用计划任务前以 `schtasks.exe /Query /XML` 导出任务定义存入记录（超过 64 KiB 不存），回滚启用后再导出比较（不计启用标志），不同时在报告中注明，需人工核对（`/Change` 会重新注册任务）。自启项启动的进程按手动进程结束与重启（同样只结束本账户的进程）。

在其他网络命名空间中运行的手动进程（例如用 `ip netns exec` 启动）不会被结束：回滚只能在主机网络中重新启动程序，无法放回原命名空间。程序自身服务中的进程不在此列（例如单元带 `NetworkNamespacePath=`、`PrivateNetwork=`，或 init 脚本以 `ip netns exec` 启动）：它们由服务管理器停止，回滚时由服务管理器在原命名空间重新启动。改动前的检查还包括：Windows 上其他账户运行的手动进程（见上文），以及记录大小，即把所有将被结束的进程（含完整环境变量）写入记录后是否仍在 1 MiB 读取上限内（留 64 KiB 余量），否则回滚无法读回。这些检查在第一步改动之前完成，`--dry-run` 也做：不通过时报告原因并以退出码 1 结束（`outcome` 为 `refused`），不备份、不停用服务、不结束任何进程，也不写记录；需要接管时先手工停止相应进程。安装脚本在安装程序、配置与服务之前先以 `--dry-run` 运行这些检查，不通过即终止并保存 `takeover-check.json`（此前已建立数据目录与状态目录，并写入导入报告）。接管返回 1（拒绝，或失败后已全部撤销）与 7（撤销也未完成）时，安装脚本给出不同的提示：后者需要按报告处理后执行 `rollback`。

回滚的某一步始终无法自动完成（例如安全模块一直隐藏同名进程，或旧记录中的进程曾在其他网络命名空间运行）时，`rollback` 每次都以退出码 7 结束并保留记录。此时由操作员手工处理：按报告中的命令行、用户和网络命名空间手工启动该进程（或确认已有副本在运行），然后执行 `anixops-mesh rollback --state-dir S --forget-process <原 pid> --confirm`。该命令把这一记录移除而不启动，再照常撤销其余步骤；不带 `--confirm` 时拒绝执行，原 pid 不在记录中时报错且不做任何改动。移除的进程（pid、程序、命令行、用户、时间）保留在 `takeover.json` 的 `forgotten` 列表里；执行时应同时加 `--report` 保存报告，供事后核对。执行回滚前先停止我方节点。全部恢复后清空记录中的步骤与运行次数，`takeover.json` 本身与 `forgotten` 列表保留（只保留最近 64 条，更早的以各次 `--report` 保存的报告为准）。接管撤销后或回滚后记录无法保存时（例如超过上限），报告中有一条 `ok` 为假的「save record」步骤，退出码 7，此时以本次报告为准手工核对。

## 安装（Linux）

[`apps/mesh-node/install/install-linux.sh`](../../apps/mesh-node/install/install-linux.sh) 是一条命令安装脚本：下载程序并校验 SHA-256（值由面板生成的安装命令给出），可选下载并校验接管数据文件，执行导入预检；程序支持 `run` 时才接管、注册 systemd 或 OpenRC 服务并启动，启动失败自动停止我方服务并回滚接管。`--uninstall` 停止并删除我方服务后回滚接管。下载只走 https：curl 限定 `--proto =https`，GNU wget 加 `--https-only`（BusyBox wget 不支持跳转限制，由哈希校验兜底）。CI 对脚本做 `sh -n` 与 shellcheck 检查。

## 安装（macOS）

[`apps/mesh-node/install/install-macos.sh`](../../apps/mesh-node/install/install-macos.sh) 与 Linux 脚本流程相同（以 root 运行）：下载并以 `shasum -a 256` 校验程序与数据文件（只走 https），执行导入预检；程序支持 `run` 时才接管，写入 launchd 系统守护进程 `/Library/LaunchDaemons/com.anixops.mesh.plist`（`plutil -lint` 校验；非正常退出时重启），`launchctl enable` 后 `bootstrap` 启动，5 秒后仍未运行则卸载我方守护进程并回滚接管。`--uninstall` 卸载并删除守护进程后回滚接管。macOS 的 `/etc`、`/var`、`/tmp` 是符号链接，状态目录不能经过链接；`/usr/local/bin` 可能属于按用户安装软件包管理器的那个用户，放在那里的程序可被该用户替换后以 root 运行，因此程序、配置和状态都放在 `/Library/AnixOps/mesh`（root 所有，0700；程序在其下 `bin/anixops-mesh`），日志写入 `/Library/Logs/anixops-mesh.log`。CI 对脚本做 `sh -n` 与 shellcheck 检查。节点的虚拟网卡是系统分配的 `utunN`（不是 `anixmesh0`），`run --interface` 只接受 `utunN` 形式；守护进程配置不指定网卡名。

## 安装（Windows）

[`apps/mesh-node/install/install-windows.ps1`](../../apps/mesh-node/install/install-windows.ps1) 以管理员身份运行，流程与 Linux 脚本相同：下载并以 `Get-FileHash` 校验程序与数据文件（只走 https），执行导入预检；程序支持 `run` 时才接管，注册服务 `AnixOpsMesh`（自动启动，失败后 5 秒重启；程序以服务专用错误报告非零退出，所以同时设 `sc.exe failureflag AnixOpsMesh 1`，否则重启动作不生效），启动 5 秒后仍未运行则删除我方服务并回滚接管。`-Uninstall` 停止并删除服务后回滚接管。程序放在 `%ProgramFiles%\AnixOps\Mesh`，旁边放 `wintun.dll`（节点只从程序所在目录加载它）：程序支持 `run` 时必须给出 `-WintunUrl` 与 `-WintunSha256`（发布中对应架构的 `wintun.dll`），脚本校验 SHA-256 并核对其 PE 机器类型与本机架构一致；虚拟网卡别名默认 `anixmesh0`。配置与状态放在 `%ProgramData%\AnixOps\Mesh`。任何用户都能在 `%ProgramData%` 下建目录，因此脚本对 `AnixOps`、`Mesh` 与 `state` 逐级处理：已存在的目录是链接或联接、或属主不是 Administrators、SYSTEM 或 TrustedInstaller 时拒绝安装；然后把属主设为 Administrators，并以新的访问列表整体替换（关闭继承，只有 SYSTEM 与 Administrators 完全控制），不保留原有条目。

程序在 Windows 上每次读写状态文件与锁之前检查状态目录及其每一级上级目录（直到盘符根目录）：都不能是链接或联接；属主必须是 SYSTEM、Administrators 或 TrustedInstaller；状态目录本身不允许其他账户有任何写入、删除、改权限或改属主的权限；上级目录允许其他账户新建条目（`C:\` 与 `C:\ProgramData` 默认如此，他人新建的条目属于他人，不影响我方目录），但不允许删除子项、删除自身、改权限或改属主。不满足即拒绝执行。CI 用 PowerShell 解析器检查脚本语法。

### 尚未覆盖的安全项

- 程序与数据文件只校验面板给出的 SHA-256，尚未校验发布签名；面板应以构建证明（`actions/attest`）核对发布产物后再生成安装命令。签名校验与一次性入网凭据流程在内核 0.4 与上报一起设计。
- `run` 启动前与现有程序的端口、网卡冲突检查属于节点运行侧（退出码 3），见 outbound mesh 的运行文档。

### 发布产物

每个 `v*` 标签的发布附带以下文件，各有 `.sha256` 和 GitHub 制品证明：

| 文件 | 内容 |
| --- | --- |
| `anixops-mesh-<版本>-x86_64-unknown-linux-musl` | 静态程序，无动态依赖 |
| `anixops-mesh-<版本>-aarch64-unknown-linux-musl` | 同上 |
| `anixops-mesh-<版本>-armv7-unknown-linux-musleabihf`、`-armv7-unknown-linux-musleabi`、`-arm-unknown-linux-musleabihf`、`-arm-unknown-linux-musleabi` | 同上，32 位 ARM（ARMv7、ARMv6，各含硬件浮点与软件浮点），供 OpenWrt 软件包使用 |
| `anixops-mesh_<版本>-r1_<架构>.ipk`、`.apk`，`luci-app-anixops-mesh_<版本>-r1_all.ipk`、`.apk`，`anixops-mesh-<版本>-openwrt-SHA256SUMS` | OpenWrt 软件包与网页插件，见 [`openwrt.md`](openwrt.md) |
| `anixops-mesh-<版本>-aarch64-apple-darwin` | macOS 程序（Apple 芯片），只链接系统自带的库 |
| `anixops-mesh-<版本>-x86_64-apple-darwin` | 同上（Intel） |
| `anixops-mesh-<版本>-x86_64-pc-windows-msvc.exe` | Windows 程序，C 运行库静态链接，不需要 Visual C++ 运行库 |
| `anixops-mesh-<版本>-aarch64-pc-windows-msvc.exe` | 同上（ARM64） |
| `anixops-mesh-<版本>-x86_64-pc-windows-msvc-wintun.dll`、`-aarch64-pc-windows-msvc-wintun.dll` | Wintun 0.14.1 驱动库原样随附（与客户端同一份，固定包的 SHA-256，CI 先核对架构），装在 Windows 程序旁边 |
| `anixops-mesh-<版本>-wintun-LICENSE.txt` | Wintun 许可证 |
| `anixops-mesh-<版本>-install-linux.sh` | Linux 安装脚本 |
| `anixops-mesh-<版本>-install-macos.sh` | macOS 安装脚本 |
| `anixops-mesh-<版本>-install-windows.ps1` | Windows 安装脚本 |
| `anixops-mesh-<版本>-<目标>.buildinfo.json` | 构建所用的确切工具链（`rustc -V`、`rustc -Vv`、`cargo -V`）与提交，供复现；随程序一起证明 |

构建脚本是 [`.github/scripts/build-mesh-node.sh`](../../.github/scripts/build-mesh-node.sh)。CI 在每次 Rust 改动时用同一脚本构建全部目标：「Mesh node static build」构建全部 Linux 架构（x86_64、aarch64 与 32 位 ARM），确认静态链接、x86_64 版本可运行；「Mesh node desktop build」在 macOS 与 Windows 机器上构建，确认 macOS 程序只链接 `/usr/lib` 与 `/System/Library` 下的库、Windows 程序不导入 `vcruntime`、`msvcp`、`ucrtbase` 与 `api-ms-win-crt-*`，与机器同架构的版本可运行。发布签名（Apple 公证、Windows 代码签名）尚未提供，安装命令以面板给出的 SHA-256 与构建证明为准。32 位 ARM 随 OpenWrt 软件包提供，ARMv5 与 MIPS 随后加入（见 [`openwrt.md`](openwrt.md)）。

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
| 内核 0.4 / 客户端 1.2 | macOS launchd 的检测、接管与安装；Windows 服务的检测、接管与安装；无 Agent 设备的接入、配置读取与只读上报（[`mesh-device.md`](mesh-device.md)） |
| 内核 0.5 / 客户端 1.3 | OpenWrt 软件包（musl 静态、procd、UCI）与网页插件；软件包安装方式的检测与停用 |
