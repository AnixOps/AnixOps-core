# OpenWrt 软件包与网页插件（R32、R35）

OpenWrt 路由器以无 Agent 设备接入组网：软件包只含独立组网程序 `anixops-mesh`、procd 服务与默认 UCI 配置，网页插件在路由器后台显示状态、接入设备、申请通告网段。设备的网络、地址、对端与通告网段全部由面板下发（见 [`mesh-device.md`](mesh-device.md)），UCI 不保存任何组网配置。源文件在 [`apps/mesh-node/openwrt/`](../../apps/mesh-node/openwrt/)。

## 软件包

| 软件包 | 架构 | 内容 | 依赖 |
|---|---|---|---|
| `anixops-mesh` | 每个 OpenWrt 架构一份，见 [`arches.txt`](../../apps/mesh-node/openwrt/arches.txt) | `/usr/bin/anixops-mesh`（musl 静态构建）、`/etc/init.d/anixops-mesh`、`/usr/libexec/anixops-mesh/service`、`/etc/uci-defaults/90-anixops-mesh`、`/lib/upgrade/keep.d/anixops-mesh` | `kmod-tun` |
| `luci-app-anixops-mesh` | `all` | 两个页面（状态、设置）、菜单、权限、rpcd 后端、简体中文翻译 | `luci-base`、`rpcd-mod-ucode`、`anixops-mesh` |

每个软件包提供 ipk（opkg，OpenWrt 23.05、24.10）与 apk（OpenWrt 25.12 起）两种格式，由 [`.github/scripts/package-openwrt.sh`](../../.github/scripts/package-openwrt.sh) 生成：ipk 由脚本直接写出（归档内容按名称排序、属主 root、时间取提交时间，可重复构建），apk 由 apk-tools 3 的 `apk mkpkg` 写出（与 OpenWrt 构建系统在主机上使用的工具相同；设备上的 apk 不含 mkpkg），架构无关的包按 apk 的约定标记为 `noarch`，并在 25.12 设备上实际安装验证。安装与卸载脚本与 OpenWrt 自身构建系统生成的模板相同，由设备的 `/lib/functions.sh` 处理用户组、开机自启与 `uci-defaults`。

程序是静态构建，同一指令集的所有 OpenWrt 架构共用一份构建，只是包的架构标记不同（OpenWrt 只安装架构在本机列表中的包）。当前提供 `x86_64` 与 `aarch64_*`；32 位 ARM（armv7、armv5/6）与 MIPS（`mips_24kc`、`mipsel_24kc`）随交叉构建加入。

### 安装

软件包尚未进入签名的软件源，以本地文件安装：

```sh
# OpenWrt 23.05、24.10
opkg update
opkg install ./anixops-mesh_<版本>_<架构>.ipk ./luci-app-anixops-mesh_<版本>_all.ipk

# OpenWrt 25.12 起（本地包未经 OpenWrt 构建密钥签名）
apk update
apk add --allow-untrusted ./anixops-mesh_<版本>_<架构>.apk ./luci-app-anixops-mesh_<版本>_all.apk
```

安装后服务默认关闭；在「服务 → 内网组网 → 设置」中接入设备后自动启用并启动。

## UCI 配置

`/etc/config/anixops-mesh`，首次安装时由 `uci-defaults` 创建；已存在时不覆盖（升级、重装与 sysupgrade 均保留）。

```
config device 'main'
	option enabled '0'
	option control ''
	option state_dir '/etc/anixops-mesh'
	# list advertise '192.168.1.0/24'
```

| 选项 | 含义 |
|---|---|
| `enabled` | 服务是否运行。未接入（状态目录中没有设备令牌）时即使为 `1` 也不启动 |
| `control` | 接入时使用的面板地址，仅作显示；接入后程序以状态目录中的 `device.json` 为准 |
| `state_dir` | 设备状态目录。OpenWrt 的 `/var` 位于内存中，重启即丢失，因此默认放在 `/etc/anixops-mesh`，并列入 `/lib/upgrade/keep.d/anixops-mesh`，sysupgrade 后保留设备身份 |
| `advertise` | 本机最近一次提交成功的通告网段申请，只供网页插件显示「待管理员批准」；是否生效以面板下发为准 |

## procd 服务

`/etc/init.d/anixops-mesh`（`START=95`）在 `enabled=1` 且状态目录中有设备令牌时启动一个实例，运行 `/usr/libexec/anixops-mesh/service <state_dir>`，后者运行 `anixops-mesh device --state-dir <state_dir>`。修改 UCI 配置后 procd 自动重新加载服务。

- 程序异常退出时由 procd 重启：每次间隔 5 秒，一小时内至多 5 次。
- 退出码 8 表示面板已吊销设备令牌（程序已删除令牌）。重启无济于事，因此包装脚本停止服务、不再重启，并写一条系统日志；重新接入后服务再次启动。开机时没有令牌同样不启动。
- 停止服务时 procd 向包装脚本发送 SIGTERM，包装脚本转发给程序，等待程序关闭网络后退出（至多 10 秒）。

## 网页插件

菜单「服务 → 内网组网」，两个页面：

- **状态**：每 5 秒刷新。设备的接入状态、面板地址、服务状态、面板连接状态、最近读取配置与最近上报时间；每个网络的运行状态与失败原因、虚拟地址、前向保密、告警、重叠网段，以及成员列表（虚拟地址、网段、路径、跳数、延迟、前向保密）。字段与 `GET /v1/mesh` 应答一致，见 [`mesh-status.md`](../architecture/mesh-status.md)。
- **设置**：启用服务开关；接入设备（填写面板地址与一次性入网凭据）；通告的局域网网段申请。

后端是 rpcd 的 ucode 插件 `luci.anixops-mesh`，只在本机运行 `anixops-mesh` 子命令，不监听任何端口（R11）；面板只由程序自己访问。

| 方法 | 权限 | 作用 |
|---|---|---|
| `status` | 读 | 读取 UCI、程序能力与 `anixops-mesh device-status` 的快照 |
| `lan_networks` | 读 | 本机各接口的私有 IPv4 网段，作为申请候选 |
| `enroll` | 写 | 接入设备 |
| `request_subnets` | 写 | 提交或撤回通告网段申请 |

### 接入

面板地址只接受 `https://主机[:端口][/路径]`，不含用户名、查询参数与需要转义的字符；入网凭据须以 `mse_` 开头、只含可见 ASCII 字符、不超过 256 字节。凭据写入 `/tmp`（内存）中权限 0600 的临时文件，以 `--token-file` 交给 `anixops-mesh enroll`，调用结束立即删除，不出现在任何命令行中，也不写入闪存。成功后保存面板地址、启用并重启服务。程序退出码 8 显示「面板拒绝了该入网凭据」，9 显示「无法连接面板」。

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
| 软件包文件与网页插件 | 脚本 `sh -n` 与 shellcheck；JSON 有效；页面按网页界面的方式（函数体）解析；权限文件与 rpcd 后端方法一一对应（读写分开）；翻译完整；目录文件的散列与 luci-base 的 C 实现逐条一致 |
| 静态程序 | x86_64、aarch64 musl 静态构建（与发布同一脚本），在任务摘要中报告程序与压缩后大小 |
| 打包 | 生成全部 ipk 与 apk，第二次打包的 ipk 必须逐字节相同；检查归档内容属主为 root、只安装到 `/etc`、`/lib`、`/usr`、`/www` |
| 安装测试 | 在 OpenWrt 23.05、24.10（opkg）与 25.12（apk）的官方根文件系统镜像中安装（x86_64；aarch64 在用户态模拟下运行），检查文件与属主、默认配置、用户组、开机自启、procd 服务定义（关闭或未接入时不启动实例）、包装脚本对退出码 8、其他退出码与 SIGTERM 的处理、经真实 ubusd 与 rpcd 调用后端的全部方法（含输入校验、凭据文件的权限与删除、命令行中不出现凭据）、经网页界面自身的目录加载器核对全部翻译、重装保留配置、卸载后不留程序与自启 |

## 尚未完成

- 32 位 ARM 与 MIPS 交叉构建（MIPS 在 Rust 中为三级目标，需要 nightly 与 `build-std`），以及发布流程附带软件包。
- 软件包进入签名的软件源（opkg 使用 usign、apk 使用 OpenWrt 的签名密钥），之前以本地文件安装，校验发布附带的 SHA-256 与构建证明。
- 体积上限：需求以 16 MB 闪存路由器可安装为准；CI 先报告大小，跨架构的实际数值出来后设定硬性上限。
- 接管 OpenWrt 上现有组网程序的三种装法（软件包、自写启动脚本、手动运行，R35 第 3 条）由 [`mesh-node.md`](mesh-node.md) 的检测与接管负责，软件包安装方式的检测随后加入。
