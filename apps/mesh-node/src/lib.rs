//! `anixops-mesh`: the standalone intranet mesh node.
//!
//! This crate holds the deployment side shared by the Agent and the
//! installers (requirements R12, R13, R15, R31): finding an existing mesh
//! program on the machine, importing its configuration into ours with a
//! report, and taking it over with a recorded, reversible procedure. The
//! node itself (`run`) is added by the mesh module.
//!
//! Nothing here names another program. What identifies one, and how its
//! configuration is written, comes from a profile file maintained in the
//! deployment layer (see [`profile`] and `docs/deploy/mesh-node.md`).

pub mod cmdline;
pub mod convert;
pub mod detect;
pub mod host;
pub mod import;
pub mod launchd;
pub mod net;
pub mod profile;
pub mod report;
pub mod source;
pub mod takeover;
pub mod winsvc;

/// Version of this program.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Subcommands this build has. Installers read them with
/// `anixops-mesh capabilities` and only take a machine over when `run` is
/// among them, so an existing network is never stopped without a node to
/// replace it.
pub const COMMANDS: &[&str] = &[
    "capabilities",
    "detect",
    "import",
    "rollback",
    "takeover",
    "version",
];
