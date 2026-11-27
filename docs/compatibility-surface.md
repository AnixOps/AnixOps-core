# 兼容性承诺清单

本文列出内核对外的接口、0.x 阶段对每一类接口的承诺，以及仍可能变化的部分。发布节奏、候选版与补丁规则见 [Release Strategy](release-strategy.md#版本节奏与候选版)。

适用版本：`v0.3.0` 起。1.0 之前，“承诺”指同一小版本线内（例如 `v0.3.0` 到 `v0.3.x`）不做不兼容改动；跨小版本（`v0.3` 到 `v0.4`）允许不兼容改动，但必须写进该小版本发布说明的“从上一个小版本升级”小节，并给出迁移与回退步骤。

## 总则

| 规则 | 补丁版（`X.Y.Z` → `X.Y.Z+1`） | 小版本（`0.Y` → `0.Y+1`） |
| --- | --- | --- |
| 删除或重命名接口、字段、命令、参数 | 不允许 | 允许，发布说明列出并给出替代 |
| 改变已有字段的含义、单位、默认值 | 不允许（安全修复除外，须在发布说明中单列） | 允许，发布说明列出 |
| 新增可选字段、命令、能力位 | 不允许（修复所需的最小新增除外） | 允许 |
| 旧版本写出的配置与状态文件 | 必须原样可读 | 必须可读，或在首次加载时迁移并保留备份 |
| 回退到上一个版本 | 必须可直接回退 | 发布说明写明回退步骤，迁移不可逆时须说明 |

“不兼容改动”指：已按旧版本写好的配置、调用方代码或脚本，在新版本上不能原样工作。

“安全修复改变行为”指：为修复漏洞必须拒绝原先接受的输入（例如管理接口只许回环地址）。这类改动可以进补丁版，但发布说明必须单列“行为变化”，写明受影响的配置与迁移方法。

## 1. Rust 公共 API

内核 crate 不发布到 crates.io（见 [Release Strategy](release-strategy.md#产物矩阵)）。唯一的外部 Rust 调用方是 AnixOps/anixops-net，它在 `Cargo.toml` 中以 git 提交固定引用以下 crate：

- `config-core`
- `control-domain`
- `engine-embedded`
- `inbound-mixed`
- `node-import`
- `platform-windows`

承诺：

- 同一小版本线内，上述 crate 中被客户端使用的公开项（类型、函数、trait、公开字段、错误枚举）不删除、不改签名。新增枚举变体只在标了 `#[non_exhaustive]` 的枚举上进行，否则视为不兼容改动。
- 其余 crate（协议出入站、传输、`node-runtime`、`outbound-mesh` 等）是内部实现，不对外承诺，任何版本都可以调整。
- 客户端仓库的 CI 是这一承诺的实际检验：内核小版本或补丁版发布前，客户端把固定提交改到候选提交后必须能通过构建。

0.x 期间仍可能变化：`engine-embedded` 中组网相关的 Rust 接口（多网络、地区、骨干、自定义路径将在 0.4、0.5 中加入）。

## 2. Apple 平台使用的 C ABI

头文件即接口定义，由 `crates/engine-embedded/tests/ffi_contracts.rs` 等合同测试检查与实现一致。

| 头文件 | 版本函数 | 当前值 |
| --- | --- | --- |
| `crates/engine-embedded/include/networkcore_ios_runtime.h` | `networkcore_ios_abi_version()` | ABI 1 |
| 同上 | `networkcore_ios_schema_version()` | 配置 schema 1 |
| 同上 | `networkcore_ios_feature_set_version()` | 能力集 7（7 起含 `capabilities` 命令；组网是否可用看 `capabilities.mesh`） |
| `crates/node-import/include/networkcore_import.h` | `networkcore_import_abi_version()` | ABI 1 |

规则：

- **ABI 版本**只在已有函数签名、结构体布局、返回码含义或内存所有权规则改变时递增。递增 ABI 版本是不兼容改动，只能出现在小版本中；调用方在初始化时比较 ABI 版本，不一致即拒绝加载（`NETWORKCORE_IOS_ERR_ABI_MISMATCH`）。
- **能力集版本**在新增函数或新增 JSON 命令时递增，不删除已有函数。调用方按能力集版本判断新函数是否可用。补丁版不递增能力集版本，除非修复本身需要新函数（须在发布说明中说明）。
- **返回码**：已有 `NETWORKCORE_IOS_*`、`NETWORKCORE_IMPORT_*` 返回码的数值与含义不变；新增返回码只在小版本中加入，调用方须把未知返回码当作失败处理。
- **内存所有权**：内核分配的缓冲区一律由对应的 `*_free_buffer` 释放，句柄由 `networkcore_ios_runtime_free_handle` 释放，这一规则不变。
- **经 C ABI 传递的 JSON**（运行配置、`networkcore_ios_runtime_control` 的请求与应答、状态、节点导入结果）：应答中只新增字段，不删除、不改名；调用方须忽略不认识的字段。请求与配置按 `deny_unknown_fields` 严格校验，所以调用方不得向旧内核发送新版本才有的字段，应先用能力集版本判断。
- **运行配置 `allow_mesh`**（0.3.0-rc.2 起接受，0.3 承诺面）：布尔，缺省 `false`（失败时关闭：调用方漏发时组网配置直接报错）。为 `false` 或缺省时，配置中任何 `"type": "mesh"` 出站（顶层 `outbound`、`routing.outbounds`、内联 `via` 链的任一层）都使整个配置被拒绝，错误码 `config_rejected`，消息固定为 `mesh outbounds are not allowed by this config`（`engine_embedded::config::MESH_NOT_ALLOWED`）；该运行实例的 `capabilities.mesh` 为 `false`，所有 `mesh_*` 命令（含 `mesh_save_network`、`mesh_join`）返回 `unsupported`。未编入 `mesh` feature 的构建同样接受该字段并按同样规则拒绝。C ABI 初始化只返回 `NETWORKCORE_IOS_ERR_CONFIG_REJECTED`，不带消息。能力集 7 的过渡提交（main 上 cbb3c844，未发布）不认识该字段，调用方以 0.3.0-rc.2 为下限。缺省值与语义在 0.3.x 内不变。
- **`mesh_status` 快照的内网域名字段**（嵌入式引擎 0.3.1 起，字段与取值见 `docs/architecture/mesh-status.md`）：`tunnel.dns`、顶层 `names[]` 与 `refusedNames[]`（0.3.0 不给出，客户端须把缺失当作空列表）。`names[]` 的可省字段 `duplicateNetworks`（0.3.1 新增登记）：同名也出现在其他运行中、后缀相同的网络时给出这些网络的 `id`，此时 `duplicate` 为 `true`；不出现时省略该字段。

0.x 期间仍可能变化：组网相关的控制命令与状态字段（0.4、0.5 的地区、骨干、自定义路径）；`networkcore_import_set_anx_license` 的入参格式随 ANX 规格定稿可能调整。

## 3. Linux CLI（`networkcore-linux`）

发布产物：`networkcore-linux-<版本>-x86_64-unknown-linux-gnu.tar.gz` 及其校验与清单。

承诺范围：

- 顶层命令：`version`、`capabilities`、`prepare-config`、`validate`、`core`、`subscription`、`node`、`proxy`、`service`、`connect`/`start`、`disconnect`/`stop`、`restart`、`reload`、`status`、`managed-status`、`managed-event`、`managed-log`/`logs`、`diagnostics`、`mitm`、`install-service`、`uninstall-service`、`run-url`、`run-catalog`，以及它们的子命令与长参数（`apps/linux-cli/src/cli_args.rs`）。
- 机器可读输出（JSON 模式）的字段：只新增，不删除、不改名；调用方须忽略不认识的字段。
- 退出码：成功为 0，失败非 0；已有的非 0 退出码含义不变。
- 配置文件与 profile 目录中的持久化文件：见第 6 节。

不承诺：人类可读输出的文字与排版；`--help` 文本。

## 4. `anixops-mesh`（组网节点程序）

发布产物：Linux musl、macOS、Windows 可执行文件与安装脚本（见 `docs/deploy/mesh-node.md`）。调用方是面板生成的安装命令、Agent 与 OpenWrt 软件包。

- 已发布的子命令 `version`、`capabilities`、`run`、`detect`、`import`、`takeover`、`rollback` 及其参数在同一小版本线内不删除、不改义。
- `capabilities` 的输出只新增能力名，调用方据此判断功能是否可用，不按版本号推断。
- `run` 的标准输出与标准错误是逐行 JSON 对象：只新增对象种类与字段，调用方忽略不认识的对象和字段（见 `docs/deploy/mesh-node.md`「`run` 的输出」）。
- 接管与回滚的报告文件、状态目录的格式向后可读：新版本能回滚旧版本做的接管。

0.x 期间仍可能变化：组网配置格式、地区与骨干相关的参数（0.4、0.5）；无 Agent 设备注册流程（R31）在 0.5 定稿前可能调整。

## 5. `anixcore`（节点内核）与管理接口

调用方是 anix-agent。命令行 `anixcore run|check -c <文件>` 与 `anixcore version` 保持不变。

管理接口（HTTP，Bearer 令牌，默认只许回环地址）：`/v1/status`、`/v1/inbounds` 及其下的 `users`、`traffic`、`online`、`destinations`、`targets`，`/v1/egress`、`/v1/network`、`/v1/qos`、`/v1/rules`、`/v1/rules/counters`、`/v1/tls-fingerprints`、`/v1/mesh`。

- 已有路径、方法与请求字段在同一小版本线内不删除、不改义；应答只新增字段。
- 新功能以 `GET /v1/status` 中的能力名公布，Agent 按能力名决定是否下发，不按版本号推断。
- `/v1/mesh` 的请求体随组网规格演进，规格变更先改 `docs/architecture/mesh-module.md`，再改代码。

0.x 期间仍可能变化：`/v1/mesh` 的配置体与状态体（0.4 多网络、地区、骨干，0.5 自定义路径）。

## 6. 配置文件与升级行为

| 配置 | 版本标识 | 承诺 |
| --- | --- | --- |
| `config-core` 配置文档 | `schema_version`（当前 1，缺省按当前版本处理） | 同一 schema 版本内只新增可选字段；schema 版本递增只在小版本中发生，且加载旧版本时自动迁移 |
| `engine-embedded` 运行配置（客户端经 C ABI 或 Rust 传入） | `schema_version`（当前 1） | 同上；schema 不一致时拒绝并返回 `NETWORKCORE_IOS_ERR_SCHEMA_MISMATCH`，不做猜测 |
| `anixcore` 配置文件 | 无单独版本号 | 已有字段不删除、不改义；新字段带默认值，不写即保持原行为 |
| `anixops-mesh` 配置与状态目录 | 随组网规格 | 新版本能读取并回滚旧版本写入的状态 |
| `networkcore-linux` profile 目录中的持久化文件 | 随 CLI | 新版本能读旧版本写入的文件；写入新格式前保留旧文件备份 |

升级与回退要求：

- 上一个小版本的配置在新版本上必须能原样加载并启动；做不到的字段必须在发布说明中列出升级前后的示例。
- 新版本不得在用户未操作的情况下把配置改写成旧版本读不了的格式；需要改写时先保留备份，发布说明给出回退步骤。
- 以上由每个小版本的候选版验收实际验证（脱敏的上一版本配置：加载、启动、实际连接、回退），结果写入发布说明。

## 7. 不在承诺范围内

- 内部 crate 与其 Rust 接口、测试辅助工具、`lab` 与基准程序。
- 日志文字、诊断报告的排版、错误信息的措辞（错误码与返回码除外）。
- 性能数字与资源占用（有回归门禁，但不是接口承诺）。
- 标为实验或未启用的功能；它们在发布说明中单列。

## 进入 1.0 的条件

1. 上文各节“0.x 期间仍可能变化”的条目全部定稿，组网迁移完成。
2. 本清单的承诺改为跨小版本有效：1.x 内不做不兼容改动，不兼容改动只出现在 2.0。
3. 至少一个小版本线按本清单完成过补丁维护，且没有违反承诺的发布。
