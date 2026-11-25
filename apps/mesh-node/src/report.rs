//! The import and takeover reports: what was converted, what was left out
//! and why, and what somebody must confirm (requirement R13).
//!
//! Reports never hold a secret. They are printed for the operator and read
//! by the Agent and the installers, so field names and status codes are
//! stable; messages are for people only.

use serde::Serialize;

pub const REPORT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    /// Converted into our configuration.
    Imported,
    /// Recognised and deliberately left out; nothing to do.
    Dropped,
    /// Left out or changed; somebody must confirm before the import counts.
    NeedsConfirmation,
    /// Prevents the automatic migration of this instance.
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Item {
    /// Our field name, or the source key for settings we have no field for.
    pub field: String,
    pub status: ItemStatus,
    /// Stable reason code.
    pub code: String,
    /// For people.
    pub message: String,
    /// Where the setting came from; never a value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The imported or offending value, when it is not secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceStatus {
    /// The configuration can be used as it is.
    Ready,
    /// A configuration was written, but some items need confirmation.
    NeedsConfirmation,
    /// No configuration; manual migration (requirement R15).
    Blocked,
}

/// Values every node of one network must agree on; the Agent compares them
/// across the nodes it imports (a mismatch stops the import).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkSummary {
    pub name: String,
    pub secure_mode: bool,
    pub encrypted: bool,
    pub cipher: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstanceReport {
    pub id: String,
    pub status: InstanceStatus,
    /// How the program was found: service, init script, autostart line,
    /// process, or given by hand.
    pub origin: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_file: Option<String>,
    /// Where our configuration was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkSummary>,
    /// Another instance of this report describing the same network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duplicate_of: Option<String>,
    pub items: Vec<Item>,
}

impl InstanceReport {
    pub fn worst(&self) -> ItemStatus {
        self.items
            .iter()
            .map(|item| item.status)
            .max()
            .unwrap_or(ItemStatus::Imported)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    pub report_version: u32,
    pub tool_version: &'static str,
    pub profile_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_version: Option<String>,
    pub instances: Vec<InstanceReport>,
    /// Notes that concern the machine rather than one instance.
    pub notes: Vec<Item>,
}

impl ImportReport {
    /// 0 when every instance is ready, 3 when nothing was found, 5 when
    /// something needs confirmation, 6 when an instance is blocked.
    pub fn exit_code(&self) -> i32 {
        if self.instances.is_empty() {
            3
        } else if self
            .instances
            .iter()
            .any(|instance| instance.status == InstanceStatus::Blocked)
        {
            6
        } else if self
            .instances
            .iter()
            .any(|instance| instance.status == InstanceStatus::NeedsConfirmation)
        {
            5
        } else {
            0
        }
    }
}

pub fn item(field: &str, status: ItemStatus, code: &str, message: &str) -> Item {
    Item {
        field: field.to_string(),
        status,
        code: code.to_string(),
        message: message.to_string(),
        source: None,
        value: None,
    }
}

impl Item {
    pub fn at(mut self, source: Option<&str>) -> Self {
        self.source = source.map(str::to_string);
        self
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }
}
