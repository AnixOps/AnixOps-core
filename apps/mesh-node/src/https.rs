//! The HTTPS client a device without the Agent talks to Control with
//! (`docs/deploy/mesh-device.md`, "传输"): HTTP/1.1 over TLS, one request
//! per connection, no redirects, verified against the built-in public
//! roots or, when the operator gives one, only the certificates of a CA
//! file. Connecting (TCP and TLS) may take 10 seconds, the whole request
//! 30. Answers are read up to [`crate::device::MAX_ANSWER`] bytes of body.
//!
//! The token goes in the `Authorization` header only; neither it nor a
//! body is ever part of an error message.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::device::MAX_ANSWER;

/// Connecting: TCP and the TLS handshake.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The whole request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Room for the status line and headers on top of the body.
const MAX_HEAD: usize = 64 * 1024;

/// An answer: the status, `Retry-After` when given, and the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub retry_after: Option<String>,
    pub body: Vec<u8>,
}

/// A client for one Control address (`https://host[:port]`, checked by
/// [`crate::device::control_url`]).
#[derive(Clone)]
pub struct Client {
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    connector: TlsConnector,
}

impl Client {
    /// `ca_file`: trust only the certificates in this PEM file instead of
    /// the built-in public roots.
    pub fn new(control: &str, ca_file: Option<&Path>) -> io::Result<Self> {
        let (host, port) = split_control(control)?;
        let server_name = ServerName::try_from(host.clone())
            .map_err(|_| invalid("control host is not a valid server name"))?;
        let roots = match ca_file {
            Some(path) => {
                let pem = std::fs::read(path)?;
                ca_roots(&pem)?
            }
            None => RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            },
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| invalid("tls protocol versions are unavailable"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            host,
            port,
            server_name,
            connector: TlsConnector::from(Arc::new(config)),
        })
    }

    /// Sends one request: `path` with its query, the device token when
    /// given, and a JSON body when given.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
    ) -> io::Result<Response> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.exchange(method, path, token, body))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timed out"))?
    }

    async fn exchange(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
    ) -> io::Result<Response> {
        let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, async {
            let tcp = TcpStream::connect((self.host.as_str(), self.port)).await?;
            tcp.set_nodelay(true)?;
            self.connector.connect(self.server_name.clone(), tcp).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
        let head = request_head(
            method,
            &self.authority(),
            path,
            token,
            body.map(<[u8]>::len),
        );
        stream.write_all(head.as_bytes()).await?;
        if let Some(body) = body {
            stream.write_all(body).await?;
        }
        stream.flush().await?;
        let limit = (MAX_ANSWER + MAX_HEAD) as u64;
        let mut answer = Vec::new();
        // A peer that closes without close_notify still gave a complete
        // answer when its length checks out, which parse_response decides.
        match (&mut stream).take(limit + 1).read_to_end(&mut answer).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(error) => return Err(error),
        }
        if answer.len() as u64 > limit {
            return Err(invalid("answer is larger than 1 MiB"));
        }
        parse_response(&answer).map_err(invalid)
    }

    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

/// Host (IPv6 without brackets) and port of `https://host[:port]`.
pub fn split_control(control: &str) -> io::Result<(String, u16)> {
    let rest = control
        .strip_prefix("https://")
        .ok_or_else(|| invalid("control must start with https://"))?;
    if let Some(inner) = rest.strip_prefix('[') {
        let (host, after) = inner
            .split_once(']')
            .ok_or_else(|| invalid("control IPv6 address is not closed"))?;
        let port = match after {
            "" => 443,
            _ => port_of(
                after
                    .strip_prefix(':')
                    .ok_or_else(|| invalid("control has text after the address"))?,
            )?,
        };
        return Ok((host.to_owned(), port));
    }
    match rest.rsplit_once(':') {
        Some((host, port)) => Ok((host.to_owned(), port_of(port)?)),
        None => Ok((rest.to_owned(), 443)),
    }
}

fn port_of(text: &str) -> io::Result<u16> {
    match text.parse::<u16>() {
        Ok(port) if port > 0 => Ok(port),
        _ => Err(invalid("control port must be 1-65535")),
    }
}

/// The roots of a PEM CA file: at least one certificate, all valid.
pub fn ca_roots(pem: &[u8]) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(pem) {
        let certificate = certificate.map_err(|_| invalid("ca file is not PEM"))?;
        roots
            .add(certificate)
            .map_err(|_| invalid("ca file holds a certificate that cannot be used"))?;
    }
    if roots.is_empty() {
        return Err(invalid("ca file holds no certificate"));
    }
    Ok(roots)
}

/// The request line and headers.
pub fn request_head(
    method: &str,
    authority: &str,
    path: &str,
    token: Option<&str>,
    length: Option<usize>,
) -> String {
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: anixops-mesh/{}\r\nAccept: application/json\r\nConnection: close\r\n",
        crate::VERSION
    );
    if let Some(token) = token {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    match length {
        Some(length) => head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {length}\r\n"
        )),
        None if method != "GET" => head.push_str("Content-Length: 0\r\n"),
        None => {}
    }
    head.push_str("\r\n");
    head
}

/// Parses a whole HTTP/1.1 answer: the status, `Retry-After`, and the
/// body by `Content-Length`, chunked transfer coding, or up to the end.
pub fn parse_response(answer: &[u8]) -> Result<Response, &'static str> {
    let end = find(answer, b"\r\n\r\n").ok_or("answer has no complete head")?;
    if end > MAX_HEAD {
        return Err("answer head is too large");
    }
    let head = std::str::from_utf8(&answer[..end]).map_err(|_| "answer head is not text")?;
    let rest = &answer[end + 4..];
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or("answer has no status line")?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err("answer is not HTTP/1.x");
    }
    let status: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .filter(|code| (100..=599).contains(code))
        .ok_or("answer status is invalid")?;
    let mut length = None;
    let mut chunked = false;
    let mut retry_after = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err("answer header is malformed");
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            let parsed: usize = value.parse().map_err(|_| "answer length is invalid")?;
            if length.is_some_and(|known| known != parsed) {
                return Err("answer length is given twice");
            }
            length = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .rsplit(',')
                .next()
                .is_some_and(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
            if !chunked {
                return Err("answer transfer coding is not supported");
            }
        } else if name.eq_ignore_ascii_case("retry-after") {
            retry_after = Some(value.to_owned());
        }
    }
    let body = if chunked {
        dechunk(rest)?
    } else if let Some(length) = length {
        if length > MAX_ANSWER {
            return Err("answer is larger than 1 MiB");
        }
        rest.get(..length)
            .ok_or("answer is shorter than its length")?
            .to_vec()
    } else {
        rest.to_vec()
    };
    if body.len() > MAX_ANSWER {
        return Err("answer is larger than 1 MiB");
    }
    Ok(Response {
        status,
        retry_after,
        body,
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut body = Vec::new();
    loop {
        let line_end = find(rest, b"\r\n").ok_or("answer chunk is cut off")?;
        let line =
            std::str::from_utf8(&rest[..line_end]).map_err(|_| "answer chunk is malformed")?;
        let size = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| "answer chunk size is invalid")?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(body);
        }
        if body.len().saturating_add(size) > MAX_ANSWER {
            return Err("answer is larger than 1 MiB");
        }
        let chunk = rest.get(..size).ok_or("answer chunk is cut off")?;
        body.extend_from_slice(chunk);
        rest = rest.get(size..).ok_or("answer chunk is cut off")?;
        rest = rest
            .strip_prefix(b"\r\n")
            .ok_or("answer chunk is malformed")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_addresses_split_into_host_and_port() {
        assert_eq!(
            split_control("https://panel.example.com").unwrap(),
            ("panel.example.com".to_owned(), 443)
        );
        assert_eq!(
            split_control("https://panel.example.com:8443").unwrap(),
            ("panel.example.com".to_owned(), 8443)
        );
        assert_eq!(
            split_control("https://[2001:db8::1]:8443").unwrap(),
            ("2001:db8::1".to_owned(), 8443)
        );
        assert_eq!(
            split_control("https://[2001:db8::1]").unwrap(),
            ("2001:db8::1".to_owned(), 443)
        );
        assert!(split_control("http://panel.example.com").is_err());
        assert!(split_control("https://panel.example.com:0").is_err());
        assert!(split_control("https://[2001:db8::1]x").is_err());
    }

    #[test]
    fn the_request_carries_the_token_and_length_only_in_headers() {
        let head = request_head(
            "POST",
            "panel.example.com",
            "/api/v5/mesh/device/report",
            Some("msd_abc"),
            Some(12),
        );
        assert!(head.starts_with(
            "POST /api/v5/mesh/device/report HTTP/1.1\r\nHost: panel.example.com\r\n"
        ));
        assert!(head.contains("\r\nAuthorization: Bearer msd_abc\r\n"));
        assert!(head.contains("\r\nContent-Length: 12\r\n"));
        assert!(head.contains("\r\nConnection: close\r\n"));
        assert!(head.contains(&format!("User-Agent: anixops-mesh/{}", crate::VERSION)));
        assert!(head.ends_with("\r\n\r\n"));
        let get = request_head("GET", "panel.example.com:8443", "/x?y=1", None, None);
        assert!(!get.contains("Authorization"));
        assert!(!get.contains("Content-Length"));
    }

    #[test]
    fn answers_are_read_by_length_chunks_or_to_the_end() {
        let plain = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}extra").unwrap();
        assert_eq!((plain.status, plain.body.as_slice()), (200, &b"{}"[..]));
        let chunked = parse_response(
            b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"a\r\n4;x=y\r\n\":1}\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(chunked.body, b"{\"a\":1}");
        let open = parse_response(b"HTTP/1.0 204 No Content\r\n\r\n").unwrap();
        assert_eq!((open.status, open.body.len()), (204, 0));
        let limited = parse_response(
            b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(limited.retry_after.as_deref(), Some("120"));
    }

    #[test]
    fn broken_or_oversized_answers_are_refused() {
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2").is_err());
        assert!(parse_response(b"SSH-2.0 x\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 2000 OK\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n").is_err());
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").is_err()
        );
        assert!(parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n{}"
        )
        .is_err());
        let huge = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_ANSWER + 1
        );
        assert!(parse_response(huge.as_bytes()).is_err());
        let mut chunks = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        chunks.extend_from_slice(format!("{:x}\r\n", MAX_ANSWER + 1).as_bytes());
        assert!(parse_response(&chunks).is_err());
    }

    #[test]
    fn a_ca_file_needs_a_certificate() {
        assert!(ca_roots(b"").is_err());
        assert!(
            ca_roots(b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")
                .is_err()
        );
    }
}
