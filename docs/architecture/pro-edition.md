# Pro 版开关（`engine-embedded::pro`）

AnixOps Net 的调试功能分免费与 Pro 两档。免费部分（抓包、HTTPS 解密、导出、单条重放与编辑、现有 Loon/Surge 插件与脚本）全部在公开仓库，许可证 Apache-2.0 不变。Pro 部分（断点、对比、弱网模拟、批量重放、新的调试脚本 API）的实现**不在**公开仓库，公开内核只保留本文描述的开关。

## 构建

- **社区构建**：从公开源码编出的任何构建。没有 Pro 模块，`pro_status` 答 `build: community`，所有 Pro 功能 `enabled` 为空。免费功能完整可用。
- **官方构建**：官方发布流程在公开客户端之上叠加一个闭源 provider crate（与 ANX 客户端构建同样的叠加方式：不改公开仓库的 Cargo.toml，CI 工作区里加依赖并在入口调用注册函数）。该 crate 调用 `pro::register_pro_provider`，自带 Pro 模块、离线许可证校验和签名公钥。

公开仓库的 Cargo.toml 不出现指向闭源仓库的可选依赖：Cargo 会解析所有可选依赖，那样会让公开构建拉不到源码而失败。

## 接口

| 调用 | 说明 |
| --- | --- |
| `pro::register_pro_provider(Arc<dyn ProProvider>)` | 官方构建在加载时调用一次；后注册的替换先注册的 |
| `pro::status() -> ProStatus` | 当前状态；没有 provider 时是 `ProStatus::community()` |
| `pro::set_license(Option<&str>) -> ProStatus` | 客户端把自己保存的许可证文本交给 provider；`None` 移除 |
| `pro::enabled(ProFeature) -> bool` | Pro 代码在入口处判断；社区构建恒为 `false` |
| 控制命令 `pro_status` | 答 `ProStatus` |
| 控制命令 `set_pro_license`，字段 `license`（字符串或 `null`） | 答 `ProStatus` |

`ProStatus` 字段：`build`（`community` / `official`）、`license`（`none` / `valid` / `invalid` / `updates_expired` / `revoked`）、`licensed_to`（`license_id`、`licensee`、`updates_until`）、`available`（本构建编入的 Pro 功能）、`enabled`（现在可用的 Pro 功能）。

功能名是稳定的：`breakpoints`、`diff`、`network_conditions`、`batch_replay`、`debug_scripts`。

## 许可证

许可证是离线签名的文本，校验完全在官方构建的闭源部分完成，不联网，与服务商面板的 ANX 设备授权无关。买断模式下许可证不会“过期”：它带一个更新截止日，截止日之前发布的构建永久可用，之后发布的构建答 `updates_expired`。

许可证文本是凭据：不进错误信息、状态和日志。`ProStatus` 只带许可证编号、持有人标识和更新截止日。

## 客户端

- 客户端负责保存许可证文本（Apple 平台 Keychain，桌面与 Android 应用数据目录），引擎启动后用 `set_pro_license` 交给内核。
- 界面按 `available` / `enabled` 决定 Pro 入口：社区构建显示“官方构建提供”，官方构建未授权显示导入许可证入口。
- Pro 功能的界面代码可以开源；没有闭源模块时它们没有可调用的后端。
