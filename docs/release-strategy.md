# Release Strategy

本文件定义真实平台产物进入 `.github/workflows/release.yml` 前必须满足的发布策略与门禁。逐版本能力边界见 [Alpha Release Feature Matrix](alpha-release-feature-matrix.md)，人工事项见 `docs/manual-intervention.md`。

## 当前发布状态

- 当前最新已发布 Linux artifact 是 `v0.2.0` 正式版（2026-10-26，tag 在 `a636b89`）；同一 stable 发布的产物包括 Linux CLI、Linux 图形客户端 tarball 与 `.deb`、Windows MSI 与 portable ZIP 四件套。上一个 stable 是 `v0.1.0`（Linux-only）。
- `v0.2.0` 之前最后的 prerelease 是 `v0.2.0-rc.2`；更早的 `v0.2.0-beta.5` 与 `v0.2.0-beta.4`（`v0.2.0-beta.3`、`v0.2.0-beta.4` 均为维护者授权的验收候选，未通过真实主机验收）。
- `v0.2.0-beta.5` 的真机验收没有完成，验收改在 `v0.2.0-rc.2` 上进行并已通过。
- 客户端已拆分到 [AnixOps/anixops-net](https://github.com/AnixOps/anixops-net)：此后本仓库每次 tag release 产出 Linux CLI 四件套（archive、sha256、manifest、manifest sha256）与 `anixops-mesh` 组网程序（Linux musl、macOS、Windows 可执行文件、安装脚本与 wintun，均带 attestation），release body 注明 Windows/Linux 桌面客户端、MSI 与 iOS App 由 AnixOps/anixops-net 发布。`v0.2.0` 及更早的 tag 曾在本仓库同时产出 Linux 图形客户端 tarball 与 `.deb`、Windows managed client MSI 和 Windows portable ZIP 四件套，只保留为历史记录。`workflow_dispatch` 只验证，不发布。
- 没有本机打包或发布路径；用户可下载状态以同名 tag workflow 成功结果为准。

Linux artifact release state consistency：

```text
linux-artifact-release-state=confirmed-release-path
linux-artifact-license-notice-status=confirmed
linux-artifact-publish-scope=tag-release-after-all-gates
```

`docs/manual-intervention.md` 中的 license/NOTICE marker 已为 `linux-artifact-license-notice-status=confirmed`。它只解除 license/NOTICE 人工门禁；若 marker 缺失、非法或回退到 pending，`linux-artifact-readiness` 必须失败，且不得继续构建、上传或发布。

## 发布原则

- CI/CD Only：所有 build、test、lint、security scan、package、sign、notarize、upload 都必须在 GitHub Actions 或官方平台完成；不在本机打包、签名、测试或发布。
- Source Of Truth：release 只能基于 Git tag、受控分支或手动指定版本，不接受本地构建产物。
- One Artifact, One Job：每类平台产物使用独立 job，避免一个失败路径污染其他平台。
- Reproducible Inputs：release job 必须记录 commit SHA、tag、workspace manifest、toolchain 和 artifact 名称。
- No Secret In Repo：签名证书、Provisioning Profile、App Store Connect、Windows signing、GitHub token 只能走 GitHub Secrets、Environments 或官方平台。
- Rollback First：每个产物都要有可描述的撤回、替换或禁用路径。

## 发布门禁

真实 artifact job 合入或发布前必须满足：

1. **CI gate**：`release-ci-gate`（job 级 `actions: read`）自动读取同 repository、同 commit、`main` 分支、`completed`/`success` 的 CI run 并校验 `CI summary` job。见 [Release CI success source contract](architecture/release-ci-success-source-contract.md)、[Release CI gate execution validation contract](architecture/release-ci-gate-execution-validation-contract.md)、[Release CI gate API implementation plan](architecture/release-ci-gate-api-implementation-plan.md)、[Linux package release CI gate activation validation contract](architecture/linux-package-release-ci-gate-activation-validation-contract.md)。
2. **源码与设计**：artifact 对应源码、平台设计和安装/卸载/回滚设计已存在，不发布 placeholder、空壳或本地产物。
3. **显式 job 输入**：每个 artifact job 声明 runner、toolchain、target triple、版本、输出文件名、staging 目录、checksum/manifest 文件；Linux 细则见下方 Linux 打包合同。
4. **受控 runner 与 bundle**：产物由 GitHub-hosted runner 生成，先上传同一 release run 的 workflow artifact bundle，再由 publish job 校验后上传 GitHub Release asset。
5. **Checksum**：至少输出 `artifact_name`、`artifact_path`、`checksum_algorithm`（默认 `sha256`）、`checksum_file`、`checksum_value`。
6. **签名/attestation**：输出 `signing_policy`、`signing_status`、`attestation_policy`、`attestation_status`、`provenance_policy`、`provenance_file`。Linux 保持 unsigned tarball，但必须有可验证的 GitHub artifact attestation。
7. **人工前置**：Apple、Windows 签名或商店发布的账号、证书、密钥和 Secrets 先完成并记录到 `docs/manual-intervention.md`。
8. **发布说明与回滚**：链接 CHANGELOG、CI run、release run，并输出 `rollback_scope`、`rollback_trigger`、`rollback_steps`、`replacement_version`、`rollback_owner`、withdrawal/replacement policy。
9. **Publish eligibility**：`publish-eligibility-gate` 聚合上述所有 gate，只有 `package_publish_eligibility_status=eligible` 才进入 `publish-github-release`；公开 asset 不得覆盖同名 tag，只能以新版本替换或发布撤回说明。

## Release workflow

当前 job 依次为：

1. `release-policy`：检查治理文档、版本格式和触发来源；`workflow_dispatch` 必须从 `main` 发起，tag release 必须使用同名版本。
2. `release-ci-gate`：见门禁 1。
3. `release-artifact-contract`、`release-signing-contract`、`release-rollback-contract`：固定 checksum、签名/attestation 和回滚输出字段。
4. 平台 readiness：`linux-artifact-readiness`（检查 Linux 源码、设计、全部打包合同和 license/NOTICE marker）。
5. `package-linux`：`ubuntu-latest` 上以受版本控制的 `Cargo.lock` 执行 `cargo build --locked --release --package networkcore-linux --bin networkcore-linux --target x86_64-unknown-linux-gnu`，组装 `networkcore-linux-${version}-${target}.tar.gz`、`.sha256`、manifest JSON 和 manifest `.sha256`。
6. `attest-linux`：下载同 run bundle，重新校验 checksum，对 archive、checksum、manifest、manifest checksum 生成 GitHub artifact attestation。
7. `post-release-summary`、`publish-eligibility-gate`：校验 release notes、rollback、withdrawal/replacement policy 与 eligibility。
8. `publish-github-release`：仅 tag push 时创建同名 GitHub Release 并上传符合 eligibility 的 Linux CLI 资产，release body 指向 AnixOps/anixops-net 的客户端发布。
9. `release-summary`：输出来源、各 gate 与合同状态、人工事项和回滚说明。

未来平台按需增加 `sign-*`（受控 runner 读取 Secrets）和 `notarize-*`（macOS notarization）。仍处 placeholder 的平台必须输出显式 blocked 说明，避免误认为对应 release 已可用。

### Linux 打包合同

`package-linux` 受以下合同约束（均在 [docs/README.md](README.md#linux-发布流水线合同) 中列出）：artifact pre-release design、installation/rollback design、artifact manifest design、license/NOTICE confirmation 与 transition validation、job preflight、build command、staging file、archive creation、checksum execution、manifest generation、manifest checksum、workflow artifact bundle upload、attestation execution、release notes/rollback execution、publish eligibility execution、runner/toolchain/target、archive staging、checksum manifest、publish/upload boundary、signing/attestation policy binding、release notes/rollback policy binding 和 publish eligibility aggregate。

### Windows 发布路径

- **Windows CLI artifact**（历史）：`v0.1.1-alpha.1` 发布 source/release contract，`v0.1.1-alpha.2` 激活 Windows CLI package/publish path，`package-windows` 生成 `networkcore-windows` manual-extract zip 四件套。仅保留为审计记录，合同见 [windows-cli-artifact-source-release-contract.md](architecture/windows-cli-artifact-source-release-contract.md)。
- **Windows managed client MSI**（`v0.2.0-alpha.1` 至 `v0.2.0` 由本仓库发布，客户端拆分后由 [AnixOps/anixops-net](https://github.com/AnixOps/anixops-net) 打包发布，其中的 `networkcore-windows` CLI 由固定的内核 commit 构建）：安装器注册 automatic SCM service，完整卸载前运行 service `purge`；GUI/service/platform 激活 signed INF driver package、WinINet/WinHTTP system proxy、LocalMachine ROOT CA 和 managed lifecycle 的 apply/rollback。Windows Managed Client Source Release Contract 已随客户端迁到 AnixOps/anixops-net。

| 版本 | 新增（同一 MSI/portable/attestation/publish path） |
|---|---|
| `v0.2.0-alpha.2` | operator-staged sing-box managed process、official ZIP extraction、PID/exit 诊断 |
| `v0.2.0-alpha.3` | install-time service start 异步化；每个 tag 增加 portable ZIP 四件套与 MSI smoke |
| `v0.2.0-alpha.4` | GUI 显式官方 sing-box core install 与本地 profile import |
| `v0.2.0-alpha.5` | service-owned CA lifecycle 与受控 HTTP/1.1 HTTPS MITM |
| `v0.2.0-alpha.6` | 原生 sing-box JSON 直通导入、`sing-box.log` 诊断入口 |
| `v0.2.0-alpha.7` | 原生 JSON `mixed-in` inbound 的 MITM snapshot/restore |
| `v0.2.0-alpha.8` | Hysteria2/TUIC 导入与 direct QUIC 渲染（不进入 MITM） |
| `v0.2.0-alpha.9` | V2Ray-family TLS/REALITY/uTLS/Vision/transport compatibility subset |
| `v0.2.0-alpha.10` | SCM handoff 先于 runtime 配置；坏配置不阻塞 Start，CI 用无效配置验证 |
| `v0.2.0-alpha.11` | GUI `check -c` 预检与本地 diagnostics report |
| `v0.2.0-alpha.12`–`alpha.14` | HTTP(S) 订阅手动导入、`Update URL`、`Load nodes` |
| `v0.2.0-alpha.15`–`alpha.17` | NodeCatalog selector、回环 Clash API `Switch active`、`Test delay`、`Check core` |
| `v0.2.0-alpha.18`–`alpha.19` | service 独占 proxy snapshot；监督 sing-box 子进程并在异常退出时回滚 |
| `v0.2.0-alpha.21` | GUI 重组为 Home/Nodes/Subscriptions/Settings/Diagnostics/Advanced；tray、登录启动、opt-in 自动连接与一次核心恢复（Windows GUI Daily Usability 现位于 AnixOps/anixops-net） |
| `v0.2.0-beta.5` | 应用当前用户代理前独立验证 SCM、`check -c`、PID、loopback listener、selector readback；opt-in 小时级单源订阅刷新；失败回滚 GUI-owned proxy。需真实 Windows 桌面验收 |

不启用：LAN controller、Web UI、`urltest`、自动延迟选择、订阅组、TUN/DNS 拦截、XHTTP/ECH/multiplex 推断、HTTP/2/HTTP/3/QUIC MITM、streaming 和 JavaScript dispatch。

## 产物矩阵

| 平台/产物 | 形态 | Runner | 状态 / 前置条件 |
| --- | --- | --- | --- |
| Rust crates | 暂不发布到 crates.io | `ubuntu-latest` | 公共 API 稳定、license 与 README 完整、crate publishing policy 单独评审 |
| Linux | `networkcore-linux` CLI tarball | `ubuntu-latest` | 已激活；需满足上方 Linux 打包合同和全部门禁 |
| Linux 图形客户端 | `anixops-net` tarball 与 `.deb` | — | `v0.2.0` 为本仓库最后一次发布；此后由 AnixOps/anixops-net 发布 |
| Windows | managed-client MSI 与 portable ZIP | — | `v0.2.0` 为本仓库最后一次发布；此后由 AnixOps/anixops-net 发布 |
| iOS/macOS App | TestFlight / App Store Connect | — | 由 AnixOps/anixops-net 负责；本仓库只保证 `engine-embedded`/`node-import` 静态库可为 `aarch64-apple-ios` 构建 |
| Source archive | GitHub release 自动源码包 | GitHub Release | tag、CHANGELOG 和 CI 通过 |

矩阵中的非源码包产物在对应平台设计完成前不得加入 release workflow。

## 版本节奏与候选版

内核在 0.x 阶段按“小版本交付功能，补丁版持续修复”的节奏发布。可承诺的接口与 0.x 期间仍会变化的部分见 [兼容性承诺清单](compatibility-surface.md)。

- **小版本**（`v0.3.0`、`v0.4.0`）：交付一轮功能，允许按兼容性承诺清单做不兼容改动，发布说明必须写明从上一个小版本升级的变化、迁移步骤与回退步骤。
- **补丁版**（`v0.3.1`、`v0.3.2`）：只收缺陷修复、功能回归修复与安全修复，不收新功能，不做兼容性承诺清单内的不兼容改动。新功能进入下一个小版本。
- **1.0**：在组网迁移完成、兼容性承诺清单中“0.x 期间仍可能变化”的条目都能转为承诺之后再评估，不在 0.x 小版本里提前使用 1.0 版本号。
- 内核小版本与客户端版本配套发布（例如内核 `v0.3.0` 与客户端 1.1），客户端在 AnixOps/anixops-net 中固定引用内核的发布提交。

### 发布前置条件（workflow 检查）

`release-policy` 的 “Release version preconditions” 步骤（`.github/scripts/release-version-check.sh`）对手动验证与标签发布都检查：

1. `Cargo.toml` 中 `[workspace.package] version` 等于去掉 `v` 的发布版本（`v0.3.0-rc.1` 对应 `0.3.0-rc.1`），使发布的 `networkcore-linux version`、`anixops-mesh version` 与资产名一致。
2. `CHANGELOG.md` 含 `## vX.Y.Z[-rc.N] - YYYY-MM-DD` 小节：发布前把 Unreleased 中属于本版本的条目移入该小节。

两项都在打标签之前通过普通 PR 合入发布所在的分支（`main` 或下方的维护分支）；该提交在这条分支上的 CI 成功后，再对同一提交打标签（门禁 1 读取同一提交在 `main` 或 `release/X.Y` 上成功的 CI）。改动 `Cargo.toml` 的提交在 CI 中总是运行完整矩阵。

### 维护分支

- 每个小版本冻结时，从 `main` 的冻结提交创建维护分支 `release/X.Y`（如 `release/0.3`）。该版本的 RC、正式版与补丁版都从这条分支打标签；`main` 继续合入下一个小版本的功能，不因发布而冻结。
- CI 对 `release/X.Y` 的 push 与 `main` 一样运行；`release-policy` 只接受从 `main` 或与版本号同一 `X.Y` 的 `release/X.Y` 发起的手动验证；`release-ci-gate` 只接受同一提交在 `main` 或 `release/X.Y` 上成功的 CI，其他分支（包括 `release/` 下版本号不符的分支）一律拒绝。
- 修复先以 PR 合入 `main`（`main` 已不含该问题时除外），再以单独 PR 挑选到 `release/X.Y`，PR 描述引用 `main` 上的原 PR；只存在于维护分支的问题直接对 `release/X.Y` 提 PR。维护分支不接受新功能。
- `release/*` 的分支保护（禁止强推与删除、合并前要求 CI 通过）需要仓库管理员在 GitHub 设置中开启，见 `docs/manual-intervention.md`。

### 候选版（RC）流程

1. **冻结范围**：发布负责人在 `main` 上选定冻结提交并创建 `release/X.Y`，列出本版本收录的需求、已合并 PR 与审计结论。未完成审计或仍有未修复高危、中危问题的功能不进入候选版：要么先修复并复审，要么在发布说明中明确标为未启用，且默认配置下不可达。
2. **准备 RC**：对 `release/X.Y` 提 PR，把 workspace 版本改为 `X.Y.Z-rc.N`、新增 CHANGELOG 小节（含“从上一个小版本升级”：配置、命令行、C ABI、管理接口的变化与示例），CI 全绿后合入。
3. **验证同一提交**：确认待打标签的提交就是 `release/X.Y` 上 CI 成功的提交；可先以 `workflow_dispatch`（从 `release/X.Y`、输入同一版本号）跑一次发布验证。
   从内核 0.4 起，同一提交的「Mesh end-to-end」工作流（[组网端到端实验床](mesh-e2e.md)）也必须为 `completed` 且 `success`；仍为「待启用」的场景，其功能须在发布说明中标为未启用。
4. **打 RC 标签**：经负责人同意后推送 `vX.Y.Z-rc.N`，发布工作流产出预发布版本。
5. **内核验收**：用脱敏的上一个小版本配置（`v0.3.0` 用 `v0.2.0` 配置）验证候选版能加载配置、启动并完成一次实际连接；对有变化的字段给出升级前后示例；用升级前备份验证回退到上一个小版本可用。
6. **客户端验收**：客户端测试构建固定到 RC 标签的提交 SHA，在受影响平台验证构建、启动、连接与断开；C ABI 有变化时必须包含实际使用该接口的 Apple 客户端；记录客户端提交与内核提交的对应关系。
7. **阻断问题**：发现阻断问题时，修复按维护分支规则合入 `main` 与 `release/X.Y`，递增 RC 号（`rc.N+1`）重复第 2–6 步；不覆盖已发布的 RC 标签。
8. **正式版**：最后一个 RC 验收通过且无阻断问题后，对 `release/X.Y` 提 PR 把版本改为 `X.Y.Z`、把 RC 小节合并为正式版小节，合入后经负责人同意对该提交打 `vX.Y.Z` 标签；随后把 CHANGELOG 的版本小节同步回 `main`。正式版与最后一个 RC 之间只允许版本号与发布说明的改动；有代码改动时必须再出一个 RC。

验收记录（各平台负责人、验证项结果、客户端与内核提交对应关系）写入发布说明或 `docs/manual-intervention.md`。

### 补丁维护

| 环节 | 普通缺陷 | 安全漏洞 |
| --- | --- | --- |
| 确认影响 | 记录受影响版本、平台与用户可见症状 | 私下确认影响范围，分别核对 Linux CLI、`anixops-mesh` 与各客户端内置的内核提交；修复合并前不公开细节 |
| 验证修复 | 在 CI 中验证修复，并加入此前会失败的回归测试 | 同左，并覆盖全部受影响平台；高风险修复通过后可单独发补丁版，不等其他修复 |
| 交付用户 | 发布补丁版，发布说明列出修复项、受影响版本与升级目标 | 发布内核补丁版；受影响客户端更新固定提交、完成验证并发布各平台版本 |
| 关闭记录 | 关联修复提交、CI 结果与发布标签 | 公告列出受影响版本、已修复的 CLI 与客户端版本，以及仍待发布的平台 |

- 补丁版发布前同样满足上方发布前置条件与全部门禁，不跳过 RC 以外的任何检查；改动面大的补丁先出 `vX.Y.Z-rc.1`。
- 补丁版从对应的 `release/X.Y` 发布，只包含挑选进维护分支的修复，不带入 `main` 上下一个小版本的功能。
- 同时维护的稳定线只保留最新小版本；上一个小版本在新小版本正式发布后只接受安全修复，期限在发布说明中写明。
- 发布说明要让用户直接作出升级决定：Linux CLI 与 `anixops-mesh` 用户需要知道可下载的修复版本；客户端用户需要知道自己平台的修复版本，某个平台仍在等待发布时标明进度。

## 版本与回滚

- 版本号采用 `vMAJOR.MINOR.PATCH` tag；alpha、beta、rc 预发布分别为 `-alpha.N`、`-beta.N`、`-rc.N`，N 为无前导零的正整数，为让同版本号的 AnixOps/anixops-net Windows Installer 版本排序保持有效，分别限定 `1-499`、`1-399`、`1-98`。release policy gate 按此检查手动输入与 tag 名。
- 任何 release 修复都通过新 tag 发布，不覆盖已发布 tag。
- 发布前失败：删除 draft 或 failed run artifact；asset 已公开：发布撤回说明并以新版本替换。
- iOS 和商店渠道回滚依赖 App Store Connect 或对应商店能力，须在发布说明中记录。
- macOS/Windows 签名凭据泄漏时必须撤销证书、轮换 Secrets，并记录人工处理项。

## 人工介入边界

以下外部事项不能由仓库自动完成，完成后把下一步自动化动作写入 `docs/manual-intervention.md`：

- 新增 Linux artifact、文件集合变化或 license/NOTICE 来源变化时的文本确认（当前 `networkcore-linux` 范围已 confirmed）。
- Apple Developer、App Store Connect、Network Extension entitlement、证书、Provisioning Profile、Privacy Manifest/Required Reason API review、App Privacy、隐私政策、App Review Notes、demo account、TestFlight group、export compliance、beta app review、protected environment、manual approval、App Review submission 和 VPN compliance。
- Windows 代码签名证书、时间戳服务和商店账号。
- GitHub Environments、branch protection、release approval policy 和 protected tags。
- 第三方发布渠道账号、API token、税务或合规材料。

## 参考

- GitHub Docs: [Managing releases in a repository](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
- GitHub Docs: [Storing workflow data as artifacts](https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts)
- GitHub Docs: [Using artifact attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
- Apple: [Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution)
- Apple: [Provisioning with capabilities](https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities/)
