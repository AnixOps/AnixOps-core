//! Takeover profiles: everything this program knows about an existing mesh
//! program comes from one of these data files.
//!
//! Requirement R12 keeps the identifiers of other programs (executable,
//! service and package names, configuration keys, command-line flags and
//! environment variables) out of the kernel and the interface: they are
//! deployment data, maintained next to the deployment scripts and handed to
//! this program with `--profile`. The code here only knows the shape of a
//! profile and our own configuration model.
//!
//! See `docs/deploy/mesh-node.md` for the format with an example.

use std::collections::{BTreeMap, HashSet};

use serde::Deserialize;

/// The only `profile_version` this build reads.
pub const PROFILE_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub profile_version: u32,
    /// Neutral name shown in reports, for example "现有组网程序".
    pub label: String,
    /// Version of the program the mapping was written for; informational.
    #[serde(default)]
    pub source_version: Option<String>,
    pub detect: Detect,
    #[serde(default)]
    pub config: ConfigSources,
    pub fields: BTreeMap<Field, Source>,
    /// Shorthand listener values such as a bare port.
    #[serde(default)]
    pub listener_shorthand: Option<ListenerShorthand>,
    /// Listeners in effect when neither the file nor the command line names
    /// any and no "no listener" switch is set.
    #[serde(default)]
    pub default_listeners: Vec<String>,
    /// Port of a peer address that names none, per transport.
    #[serde(default)]
    pub default_peer_ports: BTreeMap<String, u16>,
    /// Settings that are recognised but not imported.
    #[serde(default)]
    pub drop: Vec<DropRule>,
}

/// How to find installations.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detect {
    /// Executable file names (no directory).
    pub executables: Vec<String>,
    /// Service names: systemd unit stems (`name` for `name.service` and the
    /// template `name@.service`), init script names, launchd labels.
    #[serde(default)]
    pub services: Vec<String>,
    /// Package names, for the package-manager check.
    #[serde(default)]
    pub packages: Vec<String>,
    /// Substrings of container image names.
    #[serde(default)]
    pub images: Vec<String>,
}

/// Where configuration files are named on the command line.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSources {
    /// Flags naming one configuration file each (may repeat).
    #[serde(default)]
    pub file_flags: Vec<String>,
    #[serde(default)]
    pub file_env: Option<String>,
    /// Flags naming a directory; each file in it is one instance.
    #[serde(default)]
    pub dir_flags: Vec<String>,
    #[serde(default)]
    pub dir_env: Option<String>,
    /// The file name meaning "read the file from standard input".
    #[serde(default)]
    pub stdin_name: Option<String>,
    /// Environment variables starting with this are reported when no rule
    /// covers them.
    #[serde(default)]
    pub env_prefix: Option<String>,
    /// File keys that only identify the instance locally and need no report.
    #[serde(default)]
    pub ignore_file_keys: Vec<String>,
}

/// Settings we can import, named in our own terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    NetworkName,
    NetworkSecret,
    SecureMode,
    SecurePrivateKey,
    /// `true` when traffic is encrypted.
    Encryption,
    Cipher,
    Ipv4,
    Ipv6,
    /// `true` when the address is assigned automatically.
    AutoAddress,
    Listeners,
    Peers,
    Subnets,
    LatencyFirst,
    /// `true` when the node does not relay for others.
    RelayDisabled,
    /// When set, only these networks go into the system route table.
    SystemRoutes,
    Mtu,
    EnableIpv6,
    Hostname,
    InstanceName,
}

/// Value type of a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    Bool,
    Integer,
    List,
}

impl Field {
    pub fn kind(self) -> Kind {
        match self {
            Field::NetworkName
            | Field::NetworkSecret
            | Field::SecurePrivateKey
            | Field::Cipher
            | Field::Ipv4
            | Field::Ipv6
            | Field::Hostname
            | Field::InstanceName => Kind::Text,
            Field::SecureMode
            | Field::Encryption
            | Field::AutoAddress
            | Field::LatencyFirst
            | Field::RelayDisabled
            | Field::EnableIpv6 => Kind::Bool,
            Field::Mtu => Kind::Integer,
            Field::Listeners | Field::Peers | Field::Subnets | Field::SystemRoutes => Kind::List,
        }
    }

    /// Values that must never be printed.
    pub fn is_secret(self) -> bool {
        matches!(self, Field::NetworkSecret | Field::SecurePrivateKey)
    }

    /// Stable name used in reports.
    pub fn name(self) -> &'static str {
        match self {
            Field::NetworkName => "network.name",
            Field::NetworkSecret => "network.secret",
            Field::SecureMode => "network.secure_mode",
            Field::SecurePrivateKey => "network.secure_private_key",
            Field::Encryption => "network.encryption",
            Field::Cipher => "network.cipher",
            Field::Ipv4 => "node.address",
            Field::Ipv6 => "node.address_v6",
            Field::AutoAddress => "node.auto_address",
            Field::Listeners => "node.listen",
            Field::Peers => "peers",
            Field::Subnets => "subnets.advertise",
            Field::LatencyFirst => "routing.policy",
            Field::RelayDisabled => "node.relay",
            Field::SystemRoutes => "routing.system_routes",
            Field::Mtu => "node.mtu",
            Field::EnableIpv6 => "node.ipv6",
            Field::Hostname => "node.hostname",
            Field::InstanceName => "instance_name",
        }
    }
}

/// Where one field comes from.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Dotted key path in the configuration file.
    #[serde(default)]
    pub file: Option<String>,
    /// For an array of tables in the file: the key holding the value.
    #[serde(default)]
    pub file_item: Option<String>,
    /// For an array of tables: the key holding a mapped network, whose
    /// presence makes the instance unmigratable (requirement R15).
    #[serde(default)]
    pub file_item_mapped: Option<String>,
    /// For an array of tables: further keys that need confirmation when set.
    #[serde(default)]
    pub file_item_confirm: Vec<String>,
    /// Command-line flags carrying the value, long or short.
    #[serde(default)]
    pub flags: Vec<String>,
    /// Environment variable carrying the value.
    #[serde(default)]
    pub env: Option<String>,
    /// Delimiter of list values given on the command line or in the
    /// environment.
    #[serde(default)]
    pub split: Option<String>,
    /// A list flag takes every following value up to the next flag.
    #[serde(default)]
    pub greedy: bool,
    /// Separator of "network->mapped network" in command-line values.
    #[serde(default)]
    pub mapped_separator: Option<String>,
    /// `append`: command-line or environment values are added after the
    /// file's; `replace` (the default): they replace them.
    #[serde(default)]
    pub merge: Merge,
    /// Switches that set a fixed value when present.
    #[serde(default)]
    pub set: Vec<SetSwitch>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Merge {
    #[default]
    Replace,
    Append,
}

/// A switch such as "disable encryption" that sets a field to a constant.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetSwitch {
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub env: Option<String>,
    /// The value set: a boolean, or an empty list.
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerShorthand {
    /// Port used when a shorthand names none.
    pub default_port: u16,
    /// Transports a shorthand expands to, with their port offsets.
    pub transports: Vec<TransportOffset>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportOffset {
    pub name: String,
    #[serde(default)]
    pub offset: u16,
}

/// Settings recognised and deliberately not imported.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DropRule {
    /// Dotted file keys; a key also covers everything below it.
    #[serde(default)]
    pub file: Vec<String>,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    /// Whether the flags take a value.
    #[serde(default)]
    pub takes_value: bool,
    pub reason: DropReason,
}

/// Why a setting is not imported. The severity follows from the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DropReason {
    /// Using a node as the way out to other networks: intranet only (R5).
    ExitNode,
    /// Local port forwarding.
    PortForward,
    /// A local proxy listener.
    LocalProxy,
    /// A gateway for standard VPN clients.
    VpnPortal,
    /// The local management interface (R11).
    ManagementPort,
    /// Managed by a remote configuration server (R15): unmigratable.
    RemoteConfig,
    /// Credential-based joining: unmigratable in the first version.
    CredentialMode,
    /// Stream proxies over other transports.
    TransportProxy,
    /// Payload compression.
    Compression,
    /// Built-in name resolution (replaced by ours, R28).
    NameResolution,
    /// Access rules and port allowlists: kept for manual review.
    AccessRules,
    /// Settings for shared public relays.
    SharedRelay,
    /// NAT traversal switches; recorded until hole punching ships.
    NatTraversal,
    /// Rate limits.
    RateLimit,
    /// Local implementation details with no counterpart.
    LocalDetail,
    /// Keys the program no longer reads.
    Obsolete,
    /// Logging.
    Logging,
    /// Addresses published for other nodes behind NAT.
    MappedListeners,
}

/// What a dropped setting means for the instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Listed in the report; nothing to do.
    Note,
    /// Listed; somebody must look at it before the import is accepted.
    Confirm,
    /// The instance cannot be migrated automatically.
    Block,
}

impl DropReason {
    pub fn severity(self) -> Severity {
        match self {
            DropReason::RemoteConfig | DropReason::CredentialMode => Severity::Block,
            DropReason::ExitNode
            | DropReason::PortForward
            | DropReason::LocalProxy
            | DropReason::VpnPortal
            | DropReason::AccessRules => Severity::Confirm,
            DropReason::ManagementPort
            | DropReason::TransportProxy
            | DropReason::Compression
            | DropReason::NameResolution
            | DropReason::SharedRelay
            | DropReason::NatTraversal
            | DropReason::RateLimit
            | DropReason::LocalDetail
            | DropReason::Obsolete
            | DropReason::Logging
            | DropReason::MappedListeners => Severity::Note,
        }
    }

    /// Report text.
    pub fn message(self) -> &'static str {
        match self {
            DropReason::ExitNode => "出口功能不迁移：组网只用于内网之间通讯。",
            DropReason::PortForward => "端口转发不迁移，请确认是否仍需要。",
            DropReason::LocalProxy => "本机代理监听不迁移，请确认是否仍需要。",
            DropReason::VpnPortal => "标准 VPN 客户端接入网关不迁移，请确认是否仍需要。",
            DropReason::ManagementPort => "本机管理接口不迁移，由 Agent 或本地配置管理。",
            DropReason::RemoteConfig => {
                "该节点由远程配置服务器管理，本机没有完整配置，无法自动迁移；接管后远程管理失效。"
            }
            DropReason::CredentialMode => "凭据入网模式第一版不支持，无法自动迁移。",
            DropReason::TransportProxy => "其他传输上的流代理不支持，不迁移。",
            DropReason::Compression => "数据压缩不迁移。",
            DropReason::NameResolution => "原有内网域名功能不迁移，改用本程序的内网域名解析。",
            DropReason::AccessRules => "访问规则与端口白名单暂不导入，原样保留供人工处理。",
            DropReason::SharedRelay => "共享中转设置不迁移。",
            DropReason::NatTraversal => "打洞相关设置已记录，打洞功能上线后再导入。",
            DropReason::RateLimit => "限速设置已记录，暂不导入。",
            DropReason::LocalDetail => "本机实现细节，无对应项，不导入。",
            DropReason::Obsolete => "该项已不再生效，忽略。",
            DropReason::Logging => "日志设置不导入。",
            DropReason::MappedListeners => "对外映射地址已记录，暂不导入。",
        }
    }
}

/// What a command-line flag means, after looking it up in the profile.
#[derive(Debug, Clone)]
pub enum FlagAction {
    Field(Field),
    Set(Field, serde_json::Value),
    ConfigFile,
    ConfigDir,
    Drop { rule: usize, takes_value: bool },
}

impl FlagAction {
    pub fn takes_value(&self) -> bool {
        match self {
            FlagAction::Field(field) => field.kind() != Kind::Bool,
            FlagAction::Set(..) => false,
            FlagAction::ConfigFile | FlagAction::ConfigDir => true,
            FlagAction::Drop { takes_value, .. } => *takes_value,
        }
    }
}

#[derive(Debug)]
pub enum ProfileError {
    Parse(String),
    Version(u32),
    Invalid(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::Parse(error) => write!(f, "profile is not valid JSON: {error}"),
            ProfileError::Version(version) => {
                write!(
                    f,
                    "profile_version {version} is not supported by this build"
                )
            }
            ProfileError::Invalid(why) => write!(f, "profile is invalid: {why}"),
        }
    }
}

impl std::error::Error for ProfileError {}

impl Profile {
    pub fn from_json(text: &str) -> Result<Self, ProfileError> {
        let profile: Profile =
            serde_json::from_str(text).map_err(|error| ProfileError::Parse(error.to_string()))?;
        if profile.profile_version != PROFILE_VERSION {
            return Err(ProfileError::Version(profile.profile_version));
        }
        profile.check()?;
        Ok(profile)
    }

    fn check(&self) -> Result<(), ProfileError> {
        let invalid = |why: String| Err(ProfileError::Invalid(why));
        if self.label.trim().is_empty() {
            return invalid("label is empty".into());
        }
        if self.detect.executables.is_empty() {
            return invalid("detect.executables is empty".into());
        }
        for name in self.detect.executables.iter().chain(&self.detect.services) {
            if name.is_empty() || name.contains('/') || name.contains('\\') {
                return invalid(format!("detect name {name:?} must be a plain file name"));
            }
        }
        for field in [Field::NetworkName, Field::NetworkSecret, Field::Ipv4] {
            if !self.fields.contains_key(&field) {
                return invalid(format!("fields.{} is required", field.name()));
            }
        }
        for (field, source) in &self.fields {
            for switch in &source.set {
                let fits = match field.kind() {
                    Kind::Bool => switch.value.is_boolean(),
                    Kind::List => switch
                        .value
                        .as_array()
                        .is_some_and(|items| items.is_empty()),
                    Kind::Text | Kind::Integer => false,
                };
                if !fits {
                    return invalid(format!(
                        "fields.{}: a switch may only set a boolean or an empty list",
                        field.name()
                    ));
                }
            }
        }
        // Every flag must mean exactly one thing.
        let mut seen: HashSet<&str> = HashSet::new();
        for flag in self.all_flags() {
            if !(flag.starts_with('-') && flag.len() >= 2) || flag.contains('=') {
                return invalid(format!("flag {flag:?} must start with '-' and hold no '='"));
            }
            if !flag.starts_with("--") && flag.len() != 2 {
                return invalid(format!("short flag {flag:?} must be one letter"));
            }
            if !seen.insert(flag) {
                return invalid(format!("flag {flag:?} is listed twice"));
            }
        }
        if let Some(shorthand) = &self.listener_shorthand {
            if shorthand.transports.is_empty() {
                return invalid("listener_shorthand.transports is empty".into());
            }
        }
        Ok(())
    }

    fn all_flags(&self) -> Vec<&str> {
        let mut flags: Vec<&str> = Vec::new();
        flags.extend(self.config.file_flags.iter().map(String::as_str));
        flags.extend(self.config.dir_flags.iter().map(String::as_str));
        for source in self.fields.values() {
            flags.extend(source.flags.iter().map(String::as_str));
            for switch in &source.set {
                flags.extend(switch.flags.iter().map(String::as_str));
            }
        }
        for rule in &self.drop {
            flags.extend(rule.flags.iter().map(String::as_str));
        }
        flags
    }

    /// Looks a flag up; `None` when the profile does not know it.
    pub fn flag_action(&self, flag: &str) -> Option<FlagAction> {
        if self.config.file_flags.iter().any(|known| known == flag) {
            return Some(FlagAction::ConfigFile);
        }
        if self.config.dir_flags.iter().any(|known| known == flag) {
            return Some(FlagAction::ConfigDir);
        }
        for (field, source) in &self.fields {
            if source.flags.iter().any(|known| known == flag) {
                return Some(FlagAction::Field(*field));
            }
            for switch in &source.set {
                if switch.flags.iter().any(|known| known == flag) {
                    return Some(FlagAction::Set(*field, switch.value.clone()));
                }
            }
        }
        for (index, rule) in self.drop.iter().enumerate() {
            if rule.flags.iter().any(|known| known == flag) {
                return Some(FlagAction::Drop {
                    rule: index,
                    takes_value: rule.takes_value,
                });
            }
        }
        None
    }

    /// Environment variable names any rule reads.
    pub fn known_env(&self) -> Vec<&str> {
        let mut names: Vec<&str> = Vec::new();
        names.extend(self.config.file_env.as_deref());
        names.extend(self.config.dir_env.as_deref());
        for source in self.fields.values() {
            names.extend(source.env.as_deref());
            for switch in &source.set {
                names.extend(switch.env.as_deref());
            }
        }
        for rule in &self.drop {
            names.extend(rule.env.iter().map(String::as_str));
        }
        names
    }

    /// Whether an environment variable is relevant to this profile.
    pub fn wants_env(&self, name: &str) -> bool {
        self.known_env().contains(&name)
            || self
                .config
                .env_prefix
                .as_deref()
                .is_some_and(|prefix| !prefix.is_empty() && name.starts_with(prefix))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fictional program, "demo-meshd", used by every test in this crate.
    pub(crate) const DEMO_PROFILE: &str = include_str!("../testdata/demo-profile.json");

    pub(crate) fn demo() -> Profile {
        Profile::from_json(DEMO_PROFILE).expect("demo profile is valid")
    }

    #[test]
    fn demo_profile_loads() {
        let profile = demo();
        assert_eq!(profile.detect.executables, vec!["demo-meshd".to_string()]);
        assert!(matches!(
            profile.flag_action("--net-name"),
            Some(FlagAction::Field(Field::NetworkName))
        ));
        assert!(matches!(
            profile.flag_action("-c"),
            Some(FlagAction::ConfigFile)
        ));
        assert!(matches!(
            profile.flag_action("--no-crypto"),
            Some(FlagAction::Set(
                Field::Encryption,
                serde_json::Value::Bool(false)
            ))
        ));
        assert!(profile.flag_action("--unknown").is_none());
        assert!(profile.wants_env("DEMO_NET_NAME"));
        assert!(profile.wants_env("DEMO_ANYTHING"));
        assert!(!profile.wants_env("PATH"));
    }

    #[test]
    fn rejects_duplicate_flags_and_bad_switches() {
        let mut value: serde_json::Value = serde_json::from_str(DEMO_PROFILE).unwrap();
        value["fields"]["hostname"]["flags"] = serde_json::json!(["--net-name"]);
        let error = Profile::from_json(&value.to_string()).unwrap_err();
        assert!(error.to_string().contains("listed twice"), "{error}");

        let mut value: serde_json::Value = serde_json::from_str(DEMO_PROFILE).unwrap();
        value["fields"]["mtu"]["set"] = serde_json::json!([{ "flags": ["--x"], "value": 5 }]);
        assert!(Profile::from_json(&value.to_string()).is_err());

        let mut value: serde_json::Value = serde_json::from_str(DEMO_PROFILE).unwrap();
        value["profile_version"] = serde_json::json!(2);
        assert!(matches!(
            Profile::from_json(&value.to_string()),
            Err(ProfileError::Version(2))
        ));

        let mut value: serde_json::Value = serde_json::from_str(DEMO_PROFILE).unwrap();
        value["detect"]["executables"] = serde_json::json!(["/usr/bin/x"]);
        assert!(Profile::from_json(&value.to_string()).is_err());
    }

    #[test]
    fn unknown_profile_keys_fail() {
        let mut value: serde_json::Value = serde_json::from_str(DEMO_PROFILE).unwrap();
        value["fields"]["network_name"]["typo"] = serde_json::json!(1);
        assert!(Profile::from_json(&value.to_string()).is_err());
        let mut value: serde_json::Value = serde_json::from_str(DEMO_PROFILE).unwrap();
        value["fields"]["not_a_field"] = serde_json::json!({});
        assert!(Profile::from_json(&value.to_string()).is_err());
    }
}
