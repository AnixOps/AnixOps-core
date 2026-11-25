//! SOCKS5 server inbound for internal networks (`"type": "socks"`).
//!
//! Meant for an exit node that other devices of the same private network
//! (a mesh's virtual addresses, a LAN) reach to send traffic out through it,
//! for a limited time. It is not a public proxy, so it is strict:
//!
//! - Every client must authenticate with a username and password
//!   (RFC 1929); a client that offers no password method gets "no
//!   acceptable methods". Passwords are at least [`MIN_PASSWORD_BYTES`]
//!   long, and an inbound needs at least one user.
//! - Only clients from internal addresses ([`is_internal`]) are answered;
//!   others are closed unread. The node runtime also refuses to listen on
//!   anything but an internal address and requires an expiry time for
//!   this type.
//! - Only `CONNECT` is served. `BIND` and `UDP ASSOCIATE` are answered
//!   with "command not supported".
//!
//! A user's login is `username`, or `name` when absent. The reply to a
//! failed connect names the failure (refused, unreachable, not allowed),
//! and the relayed bytes are charged to the user like any inbound's.
//! Errors and logs never contain credentials or request contents.

mod factory;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use engine_inbound::addr::{read_addr_port, SOCKS};
use engine_inbound::server::ConnectionContext;
use engine_inbound::users::{UserIndex, Validator};
use engine_inbound::{Accepted, Rejected, StreamInbound, User, UserEntry, UserStore};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use factory::{SocksInboundFactory, TYPE_NAME};

pub const PROTOCOL: &str = "socks";

/// Shortest password a user may have.
pub const MIN_PASSWORD_BYTES: usize = 16;
/// Longest login and password RFC 1929 can carry.
const MAX_CREDENTIAL_BYTES: usize = 255;

const VERSION: u8 = 0x05;
const AUTH_VERSION: u8 = 0x01;
const AUTH_SUCCEEDED: u8 = 0x00;
const AUTH_FAILED: u8 = 0x01;
const METHOD_PASSWORD: u8 = 0x02;
const METHOD_UNACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;

const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

/// Whether `ip` is an internal address: loopback, private (RFC 1918),
/// shared (RFC 6598, `100.64.0.0/10`, which mesh networks use), link-local
/// or IPv6 unique local. IPv4-mapped IPv6 addresses count as their IPv4
/// address. The unspecified address is not internal.
pub fn is_internal(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => is_internal_v4(ip),
        IpAddr::V6(ip) => is_internal_v6(ip),
    }
}

fn is_internal_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (a == 100 && (64..128).contains(&b))
}

fn is_internal_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_loopback()
        // fc00::/7 unique local, fe80::/10 link-local.
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
}

pub struct SocksInbound {
    users: Arc<UserStore>,
    /// Users by login and password.
    index: UserIndex<(String, String)>,
}

impl Default for SocksInbound {
    fn default() -> Self {
        Self::new()
    }
}

impl SocksInbound {
    pub fn new() -> Self {
        let validator: Validator = Box::new(|user: &User| {
            let login = login(user);
            if login.is_empty() || login.len() > MAX_CREDENTIAL_BYTES {
                return Err("socks user login must be 1-255 bytes");
            }
            match user.password.as_deref() {
                Some(password)
                    if (MIN_PASSWORD_BYTES..=MAX_CREDENTIAL_BYTES).contains(&password.len()) =>
                {
                    Ok(())
                }
                _ => Err("socks user password must be 16-255 bytes"),
            }
        });
        let users = Arc::new(UserStore::new(Some(validator)));
        Self {
            index: UserIndex::new(users.clone(), credentials),
            users,
        }
    }

    async fn serve(&self, mut stream: BoxStream, context: ConnectionContext<'_>) {
        if !is_internal(context.peer.ip()) {
            context.handshake_failed();
            return;
        }
        let handshake = tokio::time::timeout(
            context.settings.handshake_timeout,
            self.handshake(&mut stream),
        )
        .await;
        let (user, target) = match handshake {
            Ok(Ok(accepted)) => accepted,
            Ok(Err(_)) | Err(_) => {
                context.handshake_failed();
                return;
            }
        };
        if user.is_revoked() {
            context.revoked();
            let _ = stream.write_all(&reply(REP_NOT_ALLOWED)).await;
            return;
        }
        let Some(_online) = user.try_connect(context.peer.ip()) else {
            context.stats.device_limited.fetch_add(1, Ordering::Relaxed);
            let _ = stream.write_all(&reply(REP_NOT_ALLOWED)).await;
            return;
        };
        let mut remote = match context.connect(&target).await {
            Ok(remote) => remote,
            Err(error) => {
                let _ = stream.write_all(&reply(failure_code(&error))).await;
                let _ = stream.shutdown().await;
                return;
            }
        };
        if stream.write_all(&reply(REP_SUCCEEDED)).await.is_err() {
            return;
        }
        let _ = context
            .relay_to(Some(&user), Some(&target), &mut stream, &mut remote)
            .await;
    }

    /// Method selection, RFC 1929 authentication and the request. Answers
    /// the client itself where SOCKS has an answer for the failure.
    async fn handshake(
        &self,
        stream: &mut BoxStream,
    ) -> Result<(Arc<UserEntry>, TargetAddr), Failed> {
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await?;
        if head[0] != VERSION {
            return Err(Failed);
        }
        let mut methods = vec![0u8; usize::from(head[1])];
        stream.read_exact(&mut methods).await?;
        if !methods.contains(&METHOD_PASSWORD) {
            stream.write_all(&[VERSION, METHOD_UNACCEPTABLE]).await?;
            return Err(Failed);
        }
        stream.write_all(&[VERSION, METHOD_PASSWORD]).await?;

        let mut auth = [0u8; 2];
        stream.read_exact(&mut auth).await?;
        if auth[0] != AUTH_VERSION {
            stream.write_all(&[AUTH_VERSION, AUTH_FAILED]).await?;
            return Err(Failed);
        }
        let mut login = vec![0u8; usize::from(auth[1])];
        stream.read_exact(&mut login).await?;
        let mut password = vec![0u8; usize::from(stream.read_u8().await?)];
        stream.read_exact(&mut password).await?;
        let Some(user) = self.user(login, password) else {
            stream.write_all(&[AUTH_VERSION, AUTH_FAILED]).await?;
            return Err(Failed);
        };
        stream.write_all(&[AUTH_VERSION, AUTH_SUCCEEDED]).await?;

        let mut request = [0u8; 3];
        stream.read_exact(&mut request).await?;
        if request[0] != VERSION {
            return Err(Failed);
        }
        if request[1] != CMD_CONNECT {
            stream.write_all(&reply(REP_COMMAND_NOT_SUPPORTED)).await?;
            return Err(Failed);
        }
        let target = match read_addr_port(stream, SOCKS).await {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                stream.write_all(&reply(REP_ADDRESS_NOT_SUPPORTED)).await?;
                return Err(Failed);
            }
            Err(error) => return Err(error.into()),
        };
        Ok((user, target))
    }

    fn user(&self, login: Vec<u8>, password: Vec<u8>) -> Option<Arc<UserEntry>> {
        let login = String::from_utf8(login).ok()?;
        let password = String::from_utf8(password).ok()?;
        if login.is_empty() || password.is_empty() {
            return None;
        }
        self.index.get(&(login, password))
    }
}

impl StreamInbound for SocksInbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn users(&self) -> &Arc<UserStore> {
        &self.users
    }

    fn accept<'a>(
        &'a self,
        _stream: BoxStream,
        _peer: std::net::SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(async { Err(Rejected::close("socks serves whole connections")) })
    }

    fn serves_connections(&self) -> bool {
        true
    }

    fn serve_connection<'a>(
        &'a self,
        stream: BoxStream,
        context: ConnectionContext<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.serve(stream, context))
    }
}

/// A handshake that ended without a request to serve.
struct Failed;

impl From<io::Error> for Failed {
    fn from(_: io::Error) -> Self {
        Failed
    }
}

fn login(user: &User) -> &str {
    user.username.as_deref().unwrap_or(&user.name)
}

fn credentials(user: &User) -> Option<(String, String)> {
    let password = user.password.clone()?;
    Some((login(user).to_owned(), password))
}

/// A reply with an all-zero IPv4 bound address; clients of `CONNECT` do
/// not use it.
fn reply(code: u8) -> [u8; 10] {
    [VERSION, code, 0, 0x01, 0, 0, 0, 0, 0, 0]
}

fn failure_code(error: &io::Error) -> u8 {
    match error.kind() {
        io::ErrorKind::PermissionDenied => REP_NOT_ALLOWED,
        io::ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
        io::ErrorKind::NetworkUnreachable => REP_NETWORK_UNREACHABLE,
        io::ErrorKind::HostUnreachable | io::ErrorKind::TimedOut => REP_HOST_UNREACHABLE,
        _ => REP_GENERAL_FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_addresses() {
        for internal in [
            "127.0.0.1",
            "10.126.126.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_internal(internal.parse().unwrap()), "{internal}");
        }
        for external in [
            "0.0.0.0",
            "::",
            "1.1.1.1",
            "100.128.0.1",
            "172.32.0.1",
            "2001:db8::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_internal(external.parse().unwrap()), "{external}");
        }
    }

    #[test]
    fn users_need_a_login_and_a_long_password() {
        let inbound = SocksInbound::new();
        let short = User::with_password("a", "short");
        assert!(inbound.users().add(short).is_err());
        let mut long_login = User::with_password("a", "p".repeat(MIN_PASSWORD_BYTES));
        long_login.username = Some("x".repeat(256));
        assert!(inbound.users().add(long_login).is_err());
        let mut empty_login = User::with_password("a", "p".repeat(MIN_PASSWORD_BYTES));
        empty_login.username = Some(String::new());
        assert!(inbound.users().add(empty_login).is_err());
        let ok = User::with_password("a", "p".repeat(MIN_PASSWORD_BYTES));
        assert!(inbound.users().add(ok).is_ok());
    }

    #[test]
    fn users_log_in_with_their_username_or_name() {
        let inbound = SocksInbound::new();
        let password = "p".repeat(MIN_PASSWORD_BYTES);
        let mut alice = User::with_password("1", password.clone());
        alice.username = Some("alice".into());
        inbound.users().add(alice).unwrap();
        inbound
            .users()
            .add(User::with_password("bob", password.clone()))
            .unwrap();
        let user = |login: &str, password: &str| {
            inbound
                .user(login.as_bytes().to_vec(), password.as_bytes().to_vec())
                .map(|user| user.name().to_owned())
        };
        assert_eq!(user("alice", &password).as_deref(), Some("1"));
        assert_eq!(user("1", &password), None);
        assert_eq!(user("bob", &password).as_deref(), Some("bob"));
        assert_eq!(user("bob", "wrong-password-xxxx"), None);
        assert_eq!(user("", ""), None);
    }

    #[test]
    fn connect_failures_get_their_reply() {
        let code = |kind| failure_code(&io::Error::from(kind));
        assert_eq!(code(io::ErrorKind::PermissionDenied), REP_NOT_ALLOWED);
        assert_eq!(
            code(io::ErrorKind::ConnectionRefused),
            REP_CONNECTION_REFUSED
        );
        assert_eq!(code(io::ErrorKind::TimedOut), REP_HOST_UNREACHABLE);
        assert_eq!(code(io::ErrorKind::Other), REP_GENERAL_FAILURE);
    }
}
