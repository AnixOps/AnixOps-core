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
