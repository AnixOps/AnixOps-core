# OpenWrt 软件包与网页插件（R32、R35）

OpenWrt 路由器以无 Agent 设备接入组网：软件包只含独立组网程序 `anixops-mesh`、procd 服务、防火墙规则维护与默认 UCI 配置，网页插件在路由器后台显示状态、接入设备、申请通告网段。设备的网络、地址、对端与通告网段全部由面板下发（见 [`mesh-device.md`](mesh-device.md)），UCI 不保存任何组网配置。源文件在 [`apps/mesh-node/openwrt/`](../../apps/mesh-node/openwrt/)。

## 软件包

| 软件包 | 架构 | 内容 | 依赖 |
|---|---|---|---|
| `anixops-mesh` | 每个 OpenWrt 架构一份，见 [`arches.txt`](../../apps/mesh-node/openwrt/arches.txt) | `/usr/bin/anixops-mesh`（musl 静态构建）、`/etc/init.d/anixops-mesh`、`/usr/libexec/anixops-mesh/service`、`/usr/libexec/anixops-mesh/firewall`、`/usr/share/anixops-mesh/firewall.uc`、`/etc/uci-defaults/90-anixops-mesh`、`/lib/upgrade/keep.d/anixops-mesh` | `kmod-tun`、`ucode`、`ucode-mod-fs`、`ucode-mod-uci`（后三者随 fw4 已在系统中） |
| `luci-app-anixops-mesh` | `all` | 两个页面（状态、设置）、菜单、权限、rpcd 后端、简体中文翻译 | `luci-base`、`rpcd-mod-ucode`、`anixops-mesh` |

每个软件包提供 ipk（opkg，OpenWrt 23.05、24.10）与 apk（OpenWrt 25.12 起）两种格式，由 [`.github/scripts/package-openwrt.sh`](../../.github/scripts/package-openwrt.sh) 生成：ipk 由脚本直接写出（归档内容按名称排序、属主 root、时间取提交时间，文件与目录权限由脚本设定、不取构建机的 umask，可重复构建），apk 由 apk-tools 3 的 `apk mkpkg` 写出（文件时间同样取提交时间，可重复构建）（与 OpenWrt 构建系统在主机上使用的工具相同；设备上的 apk 不含 mkpkg），架构无关的包按 apk 的约定标记为 `noarch`，并在 25.12 设备上实际安装验证。安装与卸载脚本与 OpenWrt 自身构建系统生成的模板相同，由设备的 `/lib/functions.sh` 处理用户组、开机自启与 `uci-defaults`。

程序是静态构建，同一指令集的所有 OpenWrt 架构共用一份构建，只是包的架构标记不同（OpenWrt 只安装架构在本机列表中的包）。当前提供：

| OpenWrt 架构 | 程序构建 |
|---|---|
| `x86_64` | `x86_64-unknown-linux-musl` |
| `aarch64_generic`、`aarch64_cortex-a53`、`aarch64_cortex-a72`、`aarch64_cortex-a76` | `aarch64-unknown-linux-musl` |
| 带浮点单元的 ARMv7：`arm_cortex-a5_vfpv4`、`arm_cortex-a7_neon-vfpv4`、`arm_cortex-a7_vfpv4`、`arm_cortex-a8_vfpv3`、`arm_cortex-a9_neon`、`arm_cortex-a9_vfpv3-d16`、`arm_cortex-a15_neon-vfpv4` | `armv7-unknown-linux-musleabihf`（硬件浮点） |
| 不带浮点单元的 ARMv7：`arm_cortex-a7`、`arm_cortex-a9` | `armv7-unknown-linux-musleabi`（软件浮点） |
| `arm_arm1176jzf-s_vfp` | `arm-unknown-linux-musleabihf`（ARMv6，硬件浮点） |
| `arm_mpcore` | `arm-unknown-linux-musleabi`（ARMv6，软件浮点） |

ARMv5（`arm_arm926ej-s`、`arm_xscale`）与 MIPS（`mips_24kc`、`mipsel_24kc`）随后加入：这两类处理器没有 64 位原子操作，组网模块需先改为不依赖它；MIPS 在 Rust 中为三级目标，需要 nightly 与 `build-std`。ARMv4（`arm_fa526`）没有对应的 Rust 目标，不提供。

### 版本

软件包版本是发布版本的第 1 版（`0.5.0-r1`）。预发布版本须排在正式版本之前，两种格式的写法不同：ipk 为 `0.5.0~rc.1-r1`（opkg 中 `~` 排在最前），apk 为 `0.5.0_rc1-r1`（apk 的预发布后缀）。文件名统一使用发布标签中的写法（`anixops-mesh_0.5.0-rc.1-r1_<架构>.ipk`），因为发布附件的文件名不能含 `~`。

### 安装

软件包随发布附带（每个架构的 ipk 与 apk、网页插件，以及列出全部软件包的 `anixops-mesh-<版本>-openwrt-SHA256SUMS`，均有构建证明），尚未进入签名的软件源，以本地文件安装。发布流程先检查该版本的程序是否提供 `enroll`、`device`、`device-status` 与 `subnet-request`，缺任何一项时该版本不附带 OpenWrt 软件包（发布说明注明原因），避免发出无法接入的软件包。

```sh
# OpenWrt 23.05、24.10
opkg update
opkg install ./anixops-mesh_<版本>_<架构>.ipk ./luci-app-anixops-mesh_<版本>_all.ipk

# OpenWrt 25.12 起（本地包未经 OpenWrt 构建密钥签名）
apk update
apk add --allow-untrusted ./anixops-mesh_<版本>_<架构>.apk ./luci-app-anixops-mesh_<版本>_all.apk
```

安装后服务默认关闭；在「服务 → 内网组网 → 设置」中接入设备后自动启用并启动。

### 升级与卸载

- 升级（opkg 安装更高版本的 ipk、`apk add` 更高版本的 apk）保留 UCI 配置、状态目录（设备身份）与防火墙区域；sysupgrade 同样保留状态目录（`/lib/upgrade/keep.d/anixops-mesh`）。CI 以同一构建打出 99.0.0 版本，测试从当前版本升级。
- 卸载时先停止服务，再删除防火墙规则与 `anixmesh` 区域，并删除整个状态目录 `/etc/anixops-mesh`（设备令牌、设备密钥、各网络密钥），避免转让或返修的路由器上留下有效凭据；UCI 配置 `/etc/config/anixops-mesh` 按 OpenWrt 惯例保留。opkg 的 `--force-reinstall` 等同卸载后重新安装，同样删除设备身份，之后需要重新接入。
- 卸载不通知面板：面板上的设备仍然存在，管理员应在面板吊销该设备（吊销同时把它的公钥移出 `native_keys`）。

## UCI 配置

`/etc/config/anixops-mesh`，首次安装时由 `uci-defaults` 创建；已存在时不覆盖（升级、重装与 sysupgrade 均保留）。

```
config device 'main'
	option enabled '0'
	option control ''
	# list advertise '192.168.1.0/24'
```

| 选项 | 含义 |
|---|---|
| `enabled` | 服务是否运行。未接入（状态目录中没有设备令牌）时即使为 `1` 也不启动 |
| `control` | 接入时使用的面板地址，仅作显示；接入后程序以状态目录中的 `device.json` 为准 |
| `advertise` | 本机最近一次提交成功的通告网段申请，只供网页插件显示「待管理员批准」；是否生效以面板下发为准 |

网页插件对 UCI 有写权限（设置页的启用开关需要），该权限覆盖整个 `anixops-mesh` 配置，经 LuCI 的通用 UCI 接口或命令行写入的值不经插件校验。因此：

- 设备状态目录固定为 `/etc/anixops-mesh`，不是 UCI 选项：其中有设备令牌与密钥，若可配置，持有该权限的账户可把它改到网页根目录 `/www` 下而被未认证下载，或改到 `/tmp` 而在重启后丢失设备身份。OpenWrt 的 `/var` 位于内存中，因此放在 `/etc` 下，并列入 `/lib/upgrade/keep.d/anixops-mesh`，sysupgrade 后保留设备身份。早期软件包写入的 `state_dir` 选项在升级时删除，任何位置都不读取它。
- rpcd 后端读取 `control` 与 `advertise` 后重新按接入与申请时的规则校验，不符合的不返回给页面。
## procd 服务

`/etc/init.d/anixops-mesh`（`START=95`）在 `enabled=1` 且状态目录中有设备令牌时启动两个实例：`device` 运行 `/usr/libexec/anixops-mesh/service /etc/anixops-mesh`，后者运行 `anixops-mesh device --state-dir /etc/anixops-mesh`；`firewall` 维护防火墙规则（见下节）。未启用或没有令牌时不启动实例，并删除防火墙规则。修改 UCI 配置后 procd 自动重新加载服务。

- 程序异常退出时由 procd 重启：每次间隔 5 秒，不限次数（路由器须在上游网络等原因消除后自行恢复；有限次数用尽后服务会一直停止直到重启或手工操作）。状态页区分「已启用，未运行」与「已停用」。
- 退出码 8 表示面板已吊销设备令牌（程序已删除令牌）。重启无济于事，因此包装脚本停止服务、不再重启，并写一条系统日志；重新接入后服务再次启动。开机时没有令牌同样不启动。
- 停止服务时 procd 向包装脚本发送 SIGTERM，包装脚本转发给程序，等待程序关闭网络后退出。程序 25 秒内未退出时包装脚本自行强制结束它；procd 的等待上限（`term_timeout`）为 30 秒，超时后只强制结束包装脚本本身，因此程序必须先于此结束，否则会带着虚拟网卡与监听端口留在系统中。
- 服务以 root 运行，未使用 procd 的权限收敛：`no_new_privs` 与能力集合由 ujail 实现，而 ujail 不在默认固件中；程序需要 `CAP_NET_ADMIN`（虚拟网卡与路由）并写入 root 所有的状态目录。待程序支持以非 root 用户运行后，再评估以 ujail 仅保留 `CAP_NET_ADMIN` 与 `CAP_NET_BIND_SERVICE`。

## 防火墙

OpenWrt 默认防火墙（fw4）拒绝转发和 WAN 入站；不在任何区域中的虚拟网卡也无法与局域网互通。软件包维护以下规则，均写在 `/etc/config/firewall` 中（fw4 的标准配置），只改动名为 `anixmesh` 的区域与名称以 `anixmesh_` 开头的规则：

| 规则 | 内容 | 何时存在 |
|---|---|---|
| 区域 `anixmesh` | 设备 `anixmesh-+`（全部组网虚拟网卡，编号在启动时分配）；`input` REJECT（组网成员不能访问路由器自身的网页后台、SSH、DNS 等服务）；`output` ACCEPT；`forward` REJECT | 服务首次运行时创建，此后保留（管理员修改的选项不被覆盖），卸载时删除 |
| `anixmesh_wan_<协议>_<端口>` | 从 `wan` 区域接受面板下发的监听端口（`network.listen`，未给出端口时为 11010），只此端口与协议 | 本机在某个网络中是完整节点时 |
| `anixmesh_in_<网段>` | 从 `anixmesh` 转发到 `lan`，目的地址限于该网段 | 完整节点，且该网段是面板已批准下发的通告网段（`subnets.advertise`） |
| `anixmesh_out_<网段>` | 从 `lan` 转发到 `anixmesh`，源地址限于该网段 | 同上 |

规则由 `/usr/libexec/anixops-mesh/firewall`（`firewall.uc`，经 UCI 接口修改）按状态目录中的 `config.json` 生成：这是程序校验通过后保存的面板应答，含网络密钥，只以 root 读取，不复制到其他位置。procd 实例 `firewall` 每 30 秒同步一次（面板配置每分钟读取一次），只有规则变化时才提交并重新加载防火墙；服务停止时删除全部 `anixmesh_*` 规则（区域保留），不留开放的端口。接入端（`role` 为 `access`）不新增任何规则，组网流量全部由程序主动外连。

## 网页插件

菜单「服务 → 内网组网」，两个页面：

- **状态**：每 5 秒刷新。设备的接入状态、面板地址、服务状态、面板连接状态、最近读取配置与最近上报时间；每个网络的运行状态与失败原因、虚拟地址、前向保密、告警、重叠网段，以及成员列表（虚拟地址、网段、路径、跳数、延迟、前向保密）。字段与 `GET /v1/mesh` 应答一致，见 [`mesh-status.md`](../architecture/mesh-status.md)。未知的失败码与告警码显示为「未知故障：代码」「未知告警：代码」。
- 页面中来自页面以外的值（UCI、状态快照、接口名与网段）一律以文本节点插入：LuCI 的 `E()` 把数组中的字符串转为文本节点，单独的字符串子节点则写入 `innerHTML`。CI 以每个字段都含 HTML 标记的数据渲染两个页面，检查没有任何标记写入 `innerHTML`。
- **设置**：启用服务开关；接入设备（填写面板地址与一次性入网凭据）；通告的局域网网段申请。

后端是 rpcd 的 ucode 插件 `luci.anixops-mesh`，只在本机运行 `anixops-mesh` 子命令，不监听任何端口（R11）；面板只由程序自己访问。

| 方法 | 权限 | 作用 |
|---|---|---|
| `status` | 读 | 读取 UCI、程序能力与 `anixops-mesh device-status` 的快照。程序能力按程序文件（inode、大小、修改时间）缓存，不在每次刷新时运行程序；`device-status` 读写超时各 3 秒 |
| `lan_networks` | 读 | 本机各接口的私有 IPv4 网段，作为申请候选 |
| `enroll` | 写 | 接入设备 |
| `request_subnets` | 写 | 提交或撤回通告网段申请 |

### 接入

面板地址只接受 `https://主机[:端口]`，与程序的 `--control` 相同（见 [`mesh-device.md`](mesh-device.md)），不含路径、用户名、查询参数与需要转义的字符；入网凭据须以 `mse_` 开头、只含可见 ASCII 字符、不超过 256 字节。凭据写入 `/tmp`（内存）中权限 0600 的临时文件，以 `--token-file` 交给 `anixops-mesh enroll`，调用结束立即删除，不出现在任何命令行中，也不写入闪存。成功后保存面板地址、启用并重启服务。程序退出码 8 显示「面板拒绝了该入网凭据」，9 显示「无法连接面板」。

### 通告网段申请

设备的配置只来自面板，设备拒绝面板配置之外的内容（R31），因此网页插件不能直接修改通告网段，而是向面板提交申请（`anixops-mesh subnet-request`，面板接口 `POST /api/v5/mesh/device/subnet-request`），由管理员在面板批准后随下一次配置下发生效。

- 每次申请是完整的网段列表，覆盖此前待批准的申请；空列表撤回申请。批准即替换设备当前的通告网段。
- 只能申请私有 IPv4 网段（10/8、172.16/12、192.168/16 之内），前缀 8–30，主机位必须为零，至多 16 项，不得重复；插件先在本机检查，面板按其规则再次校验（与地区网段、宿主组地址范围、其他完整节点网段等的重叠）。
- 只有完整节点可以申请；面板以 `not_full_node` 拒绝时插件显示「仅完整节点可通告网段」。
- 状态列：面板下发的通告网段（`device-status` 的 `device.advertise`）中包含的为「已批准」；本机申请过但尚未下发的为「待管理员批准」。

### 文案

界面源文本为英文，简体中文翻译在 `po/zh_Hans/anixops-mesh.po`，打包时转为网页界面读取的 `.lmo` 目录文件（`anixops-mesh.zh-cn.lmo`）。CI 检查每条界面文本都有翻译、模板与翻译一致、没有多余条目。

## CI

[`.github/workflows/openwrt.yml`](../../.github/workflows/openwrt.yml) 在 `apps/mesh-node/**`、组网模块、`Cargo.lock` 或打包脚本变化时运行，各项检查是并行的独立任务：

| 任务 | 内容 |
|---|---|
| 软件包文件与网页插件 | 脚本 `sh -n` 与 shellcheck；JSON 有效；页面按网页界面的方式（函数体）解析；页面渲染测试（外部值只以文本节点插入）；权限文件与 rpcd 后端方法一一对应（读写分开）；翻译完整；目录文件的散列与 luci-base 的 C 实现逐条一致 |
| 静态程序 | x86_64、aarch64、ARMv7 与 ARMv6（各含硬件浮点与软件浮点）musl 静态构建（与发布同一脚本），其他架构的程序在用户态模拟下运行 `capabilities`，在任务摘要中报告程序与压缩后大小 |
| 打包 | 生成全部 ipk 与 apk，第二次打包的 ipk 与 apk 必须逐字节相同；检查归档内容属主为 root、只安装到 `/etc`、`/lib`、`/usr`、`/www`；以预发布版本再打包一次，检查 ipk 版本写法与 apk 接受其版本；以 99.0.0 再打包一次供升级测试 |
| 安装测试 | 在 OpenWrt 23.05、24.10（opkg）与 25.12（apk）的官方根文件系统镜像中安装（x86_64；aarch64 与 ARMv7 `arm_cortex-a15_neon-vfpv4` 在用户态模拟下运行），检查文件、属主与目录权限、默认配置、用户组、开机自启、procd 服务定义（关闭或未接入时不启动实例，UCI 无法改变状态目录）、包装脚本对退出码 8、其他退出码、SIGTERM 与不响应 SIGTERM 的程序（30 秒内强制结束）的处理、防火墙规则（经 fw4 生成规则集，核对区域、监听端口、转发网段，接入端无规则，停止时删除）、经真实 ubusd 与 rpcd 调用后端的全部方法（含输入校验、凭据文件的权限与删除、命令行中不出现凭据、UCI 中的非法值不返回给页面）、经网页界面自身的目录加载器核对全部翻译、重装保留配置、升级保留配置与设备身份、卸载后不留程序、自启、防火墙规则与设备身份 |

## 尚未完成

- **程序侧的设备子命令**：`enroll`、`device`、`device-status`、`subnet-request` 由 networkcore #365 实现，合并前已安装的程序不提供这些子命令，软件包无法接入或运行；网页插件此时显示「当前安装的程序版本不支持此功能」，发布流程也不附带软件包（见「安装」）。#365 合并后，CI 增加以真实程序（而非桩程序）运行的接入、状态与网段申请测试（对本地测试面板），之后才算 R35 第 1、2 条完成。
- ARMv5 与 MIPS 构建（见上文「软件包」）。
- 软件包进入签名的软件源（opkg 使用 usign、apk 使用 OpenWrt 的签名密钥）；之前以本地文件安装，校验发布附带的 SHA-256 与构建证明。
- 体积上限：需求以 16 MB 闪存路由器可安装为准；CI 先报告大小，跨架构的实际数值出来后设定硬性上限。
- 服务的权限收敛（见「procd 服务」）。
- rpcd 后端同步调用程序：`device-status` 最长 3 秒，多个页面同时打开时占用 rpcd；改为异步调用待评估。

## 接管软件包安装的原程序（R35 第 3 条）

原程序以软件包安装、服务由 procd 管理时（`/etc/init.d/` 下首行含 `/etc/rc.common` 且含 `USE_PROCD=1` 的脚本），检测与接管按下列方式处理：

- 服务状态取自 procd（`ubus call service list`）：是否运行、各实例的进程号和命令行；进程以进程号关联到脚本，不再按命令行猜测。所属软件包取自 opkg 或 apk 的文件清单（`/usr/lib/opkg/info/*.list`、`/lib/apk/packages/*.list`），记入检测结果的说明。
- 开机自启只在原来已开启（`/etc/rc.d` 中有对应的 `S` 链接）时才关闭；原来未开启的服务不执行关闭，回滚也就不会把它开启。
- 服务经 procd 停止（执行脚本的 `stop`），procd 不会再将其拉起；回滚时启动脚本，并精确恢复接管前的状态。
- 升级或重装原软件包会再次启动其服务（软件包的安装脚本执行 `start`）。接管后不要升级或重装原软件包；确认不再需要回滚后，可将其卸载。
