# 公开版不带预设规则和插件

2026-11-15 起，所有公开发布的构建（含 `networkcore-linux` 命令行、各平台客户端和 anx 私有构建）不携带任何预设脚本、预设分流规则、广告拦截规则或站点插件。用户自己导入的配置、订阅、规则和插件不受影响。客户端仓库的同名说明见 AnixOps/anixops-net 的 `docs/no-presets.md`。

## 内核里去掉的

- `engine-embedded::profile`：`RoutingMode` 只剩 `rule` 和 `direct`，去掉“绕过大陆”“GFW 列表”“回国”三种模式和 `RuleList`（Loyalsoldier / gaoyifan 列表地址）。`envelope_for_mode(profile, mode)` 不再接收列表。
- `mitm-policy`：去掉内置的 `networkcore.adblock` 和 Bilibili 网页去广告插件。用户插件用 `user_plugin_package(text)` 加载，id 为 `user`。
- `platform-windows`：去掉 `WindowsManagedNativeMitmConfig.bilibili_web_ad_block_enabled`。带这个字段的旧配置仍能读取。
- `networkcore-linux`：
  - `start` 和 `mitm http-rewrite preview` 用 `--mitm-plugin <path>` 加载用户自己的插件。
  - 不带插件时，`start` 没有 HTTP MITM 钩子；`--enable-https-mitm` 和 `--enable-script-runtime` 需要插件，否则返回 `cli.linux.start.mitm_plugin_required`。
  - `mitm status` 等命令报告 `plugin_loaded=false`。

## 保留的

- 局域网与私有地址直连开关（客户端，默认开）。
- GEOSITE/GEOIP 到公开列表的对应关系：只在用户自己的规则引用这些分类时才使用。
- 测试里的插件文本：测试代替用户提供插件，不进入发布产物。

## 防回归

`.github/scripts/verify-repository-policy.sh`（“Repository policy (fast)” job）在非测试、非文档的源码里查找预设列表地址、预设模式名和内置插件名，发现即失败。
