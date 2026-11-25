//! `anixops-mesh`: the standalone intranet mesh node.
//!
//! This crate holds the deployment side shared by the Agent and the
//! installers (requirements R12, R13, R15, R31): finding an existing mesh
//! program on the machine, importing its configuration into ours with a
//! report, and taking it over with a recorded, reversible procedure. The
//! node itself (`run`, Linux, macOS and Windows) drives the mesh module's socket driver
//! over a TUN interface ([`serve`], [`tun`]). The kernel's management API
//! runs the networks a node agent sends through [`managed`] the same way,
//! one interface each.
//!
//! Nothing here names another program. What identifies one, and how its
//! configuration is written, comes from a profile file maintained in the
//! deployment layer (see [`profile`] and `docs/deploy/mesh-node.md`).

pub mod cmdline;
pub mod convert;
pub mod detect;
#[cfg(target_os = "macos")]
pub mod forward_macos;
pub mod host;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub mod host_routes;
pub mod import;
pub mod launchd;
#[cfg(target_os = "linux")]
pub mod managed;
pub mod net;
pub mod profile;
pub mod report;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub mod serve;
#[cfg(windows)]
pub mod service_windows;
pub mod source;
pub mod takeover;
#[cfg(target_os = "linux")]
pub mod tun;
#[cfg(target_os = "macos")]
#[path = "tun_macos.rs"]
pub mod tun;
#[cfg(windows)]
#[path = "tun_windows.rs"]
pub mod tun;
pub mod winsvc;

/// Version of this program.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Subcommands this build has. Installers read them with
/// `anixops-mesh capabilities` and only take a machine over when `run` is
/// among them, so an existing network is never stopped without a node to
/// replace it. `run` exists on Linux but is not listed until the
/// interoperability tests against third-party nodes pass in CI, so that no
/// installer replaces a working network with an incomplete node.
pub const COMMANDS: &[&str] = &[
    "capabilities",
    "detect",
    "import",
    "rollback",
    "takeover",
    "version",
];
