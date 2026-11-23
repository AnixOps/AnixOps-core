# Windows Platform Integration

`platform-windows` 是 Windows 客户端（AnixOps Net 的 Tauri 应用，以管理员身份运行）和 Windows 服务共用的平台层。本文记录它对本机状态的写入规则；客户端在 [AnixOps/anixops-net](https://github.com/AnixOps/anixops-net)。

## 托管文件（`managed_files`）

`%ProgramData%` 允许任何用户新建子目录和文件，新建者拥有它们；以固定名称写临时文件再改名，或在产品目录还不存在时抢先建好目录，都能让标准用户拥有提升权限进程随后信任的文件（引擎配置、节点、插件脚本、登录任务定义）。因此：

- `%ProgramData%\AnixOps` 及其下每一级目录都以显式、受保护（不继承）的访问表创建，属主为 Administrators：SYSTEM、Administrators 完全控制，Users 只读。已有目录若是重解析点（junction、符号链接）直接拒绝；属主不是 SYSTEM/Administrators 或访问表仍继承自 `%ProgramData%`（旧版本留下的）时，接管属主（`SeTakeOwnershipPrivilege`）并重设访问表，其下的子目录一并重设，其中的链接被删除（只删链接本身）。
- 写文件（`write_managed_file_atomic`，`write_managed_config`、`write_managed_state`、`write_managed_text_atomic` 都经由它）：在受保护目录里以随机文件名、`CREATE_NEW` 和同样的访问表新建临时文件，写入、刷盘后 `MoveFileExW` 覆盖目标。已存在的文件或链接永远不会被打开。
- 读文件（`read_managed_file`，`read_managed_config`、`read_managed_state` 经由它）：托管根目录下的文件必须不是重解析点，属主必须是 SYSTEM、Administrators 或当前进程的账户；检查与读取使用同一个句柄。
- 托管配置从托管目录读写时，`embedded.envelope_path` 与启用的 HTTPS 解密根证书、私钥路径必须在托管根目录内（`validate_managed_file_references`）。
- 托管根目录以外的路径（测试、其他平台）只使用随机名独占临时文件，不处理访问表。
- 需要普通用户写入的目录（例如以后给非提升进程看的日志）必须单独授权；当前托管目录只有提升权限的进程会写。

测试：`managed_files` 的跨平台用例（不复用旧的固定临时名、随机独占临时文件、根目录包含判定）与 Windows CI 用例（新建目录/文件的属主与受保护访问表、继承访问表的目录被修复、junction 被拒绝），`managed_integration_contracts.rs` 的路径引用用例。

## 登录启动任务

登录任务以最高可用权限运行客户端，定义 XML 不再写到用户的 `%TEMP%`（同一用户的任何中等完整性进程都能改）：写在 `%ProgramData%\AnixOps\NetworkCore\tmp`（受保护目录）里随机名、独占创建的文件中，`schtasks /Create /XML` 读取期间以不共享写入的方式保持打开，用完删除。注册后用 `schtasks /Query /XML` 读回，命令、参数、运行级别、登录类型必须与定义一致且主体不是 SYSTEM/服务账户/组，否则删除任务并报错（`startup_task_matches`）。

## 系统代理（`system_integration`）

客户端连接时设置当前用户的系统代理，断开、退出或卸载时恢复。规则：

- **不改 WinHTTP。** 机器级 WinHTTP 代理供系统服务使用（Windows Update、Defender、证书吊销检查），在“设置”里看不到；客户端崩溃留下的值会在客户端卸载后继续把这些服务指向不存在的本机端口。`WindowsSystemIntegration::apply_system_proxy` 只读取 WinHTTP 记入快照（`winhttp_untouched: true`），从不写入。`apply_winhttp_proxy` 仍保留给管理员显式调用，连接流程不得使用。
- **按连接保存与恢复 WinINet。** 应用时对 LAN 和每个拨号 / PPPoE / 内置 VPN（RAS）条目分别读取 `INTERNET_PER_CONN_FLAGS_UI`（取不到时用 `FLAGS`）、代理服务器、例外列表和自动配置脚本 URL，记入快照的 `connections`，然后把每个连接设为代理（或在设置停用时设为直连），并关闭自动检测（WPAD）与自动配置脚本（PAC）——两者都优先于手动代理，不关闭时浏览器流量不会经过本地代理。快照的 `applied` 记录写入的值。
- **只恢复仍是我们写入的值。** 恢复时逐个连接读回当前值，只有标志、服务器、例外列表与写入值一致且没有自动配置脚本时才写回快照里的原值；用户之后改过（重新打开 PAC、自动检测或换了代理）的连接保持不动。单步失败不中断其余步骤，最后总会发出 `INTERNET_OPTION_SETTINGS_CHANGED` / `REFRESH` 通知，失败一并报告。
- **1.0 之前的快照。** 旧快照没有 `winhttp_untouched`、`applied`、`connections`（反序列化为 `false`、`None`、空），恢复时照旧写回 LAN 的三个平铺值；当时的应用也写了 WinHTTP，因此只在 WinHTTP 仍等于写入值时才恢复（`restore_winhttp_proxy_if_unchanged` 同理，供客户端清理旧版本残留）；若快照里的“原值”本身就是写入值（上一次会话崩溃的残留），WinHTTP 改为“无代理”而不是写回残留。
- **生效检查。** `read_current_user_effective_proxy` 返回浏览器实际使用的配置（`WinHttpGetIEProxyConfigForCurrentUser`）以及组策略是否按机器统一代理（`ProxySettingsPerUser` = 0）；`WindowsEffectiveProxy::routes_through` 为假时客户端应提示用户自动配置或策略使流量绕过本地代理，并建议改用 TUN 模式。
- `apply_current_user_system_proxy` / `restore_current_user_system_proxy` 只读写 LAN 的三个平铺值，不处理 PAC、自动检测和拨号 / VPN 条目，保留给旧调用方。

测试：`proxy_ownership_tests`（WinHTTP 只在仍是写入值时恢复、残留清为无代理；用户改过的连接不被覆盖；生效代理被 PAC / 自动检测 / 其他代理覆盖时判为不经过；旧快照 JSON 可读）；Windows CI 用例在真实用户设置上先写入 PAC，再应用、检查 PAC 关闭且 WinHTTP 不变、恢复后 PAC 回来、应用后用户改过的连接不被恢复覆盖（测试结束由守卫写回原值）；`managed_integration_contracts.rs` 的新快照字段往返。
