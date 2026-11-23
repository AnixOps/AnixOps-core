//! `$httpClient` for MITM scripts. Each request opens one connection through
//! the tunnel's dispatcher, so it is routed like any other connection of the
//! device, and sends one HTTP/1.1 request with `Connection: close`. Answers
//! are read up to [`MAX_BODY_BYTES`]. Redirects are followed, as Surge and
//! Quantumult X do, up to [`SCRIPT_HTTP_CLIENT_MAX_REDIRECTS`] hops within
//! the request's one timeout, unless the script turned them off; a redirect
//! that cannot be followed is handed to the script as it is. Answers are
//! UTF-8 text, or bytes in `binary-mode`. Errors are fixed strings without
//! URLs or payloads.
//!
//! Scripts run on the blocking pool; a request is spawned on the tunnel's
//! runtime and the script thread waits for it, so the runtime thread keeps
//! serving the tunnel meanwhile.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use engine_native::{ScriptHttpClient, ScriptHttpClientRequest, ScriptResponse};
use engine_outbound::{TargetAddr, TcpOutbound};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use script_runtime::{binary_body_string, SCRIPT_HTTP_CLIENT_MAX_REDIRECTS};
use tokio::io::{AsyncRead, AsyncWrite};

use super::http1::{Body, Conn, Framing, Head};
use super::{remove, response_status, MAX_BODY_BYTES};

const UNAVAILABLE: &str = "networkcore: $httpClient is not available yet";
const INVALID_URL: &str = "networkcore: $httpClient needs an http or https URL";
const CONNECT_FAILED: &str = "networkcore: $httpClient could not connect";
const TIMED_OUT: &str = "networkcore: $httpClient request timed out";
const BAD_RESPONSE: &str = "networkcore: $httpClient got an invalid response";
const TOO_LARGE: &str = "networkcore: $httpClient response is too large";
/// Used when the script left the timeout to the dispatch budget and the
/// runtime passed none.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct TunnelScriptHttpClient {
    outbound: Arc<OnceLock<Arc<dyn TcpOutbound>>>,
    tls: Arc<ClientConfig>,
}

impl TunnelScriptHttpClient {
    pub(super) fn new(
        outbound: Arc<OnceLock<Arc<dyn TcpOutbound>>>,
        tls: Arc<ClientConfig>,
    ) -> Self {
        Self { outbound, tls }
    }
}

impl ScriptHttpClient for TunnelScriptHttpClient {
    fn execute(&self, request: &ScriptHttpClientRequest) -> Result<ScriptResponse, String> {
        let outbound = self.outbound.get().cloned().ok_or(UNAVAILABLE)?;
        let handle = tokio::runtime::Handle::try_current().map_err(|_| UNAVAILABLE)?;
        let url = RequestUrl::parse(&request.url).ok_or(INVALID_URL)?;
        let timeout = if request.timeout.is_zero() {
            DEFAULT_TIMEOUT
        } else {
            request.timeout
        };
        let tls = self.tls.clone();
        let request = request.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        handle.spawn(async move {
            // Every hop of a redirect chain shares the one timeout.
            let result = tokio::time::timeout(timeout, fetch(&*outbound, &tls, url, request))
                .await
                .unwrap_or(Err(TIMED_OUT));
            let _ = sender.send(result);
        });
        receiver
            .recv_timeout(timeout + Duration::from_secs(1))
            .unwrap_or(Err(TIMED_OUT))
            .map_err(str::to_string)
    }
}

/// An answer as read: its body is bytes until it is handed to the script.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Runs `request`, following redirects unless the script turned them off.
async fn fetch(
    outbound: &dyn TcpOutbound,
    tls: &Arc<ClientConfig>,
    mut url: RequestUrl,
    mut request: ScriptHttpClientRequest,
) -> Result<ScriptResponse, &'static str> {
    let mut hops = 0;
    let answer = loop {
        let answer = exchange(outbound, tls, &url, &request).await?;
        if !request.follow_redirects || hops >= SCRIPT_HTTP_CLIENT_MAX_REDIRECTS {
            break answer;
        }
        let Some(next) = redirect_target(&url, &answer) else {
            break answer;
        };
        hops += 1;
        follow_redirect(&mut request, answer.status, &url, &next);
        url = next;
    };
    let body = if request.binary_response {
        binary_body_string(&answer.body)
    } else {
        String::from_utf8_lossy(&answer.body).into_owned()
    };
    Ok(ScriptResponse {
        status: answer.status,
        headers: answer.headers,
        body: Some(body),
    })
}

/// Where a redirect answer points, when it is one this client follows: a
/// 301, 302, 303, 307 or 308 with a `Location` that resolves to an http or
/// https URL.
fn redirect_target(url: &RequestUrl, answer: &Answer) -> Option<RequestUrl> {
    if !matches!(answer.status, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    let location = answer
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("Location"))
        .map(|(_, value)| value.as_str())?;
    url.resolve(location)
}

/// Turns `request` into the request for the next hop, as browsers do
/// (RFC 9110 section 15.4): a 303, and a 301 or 302 answering a POST, become
/// a GET without a body; 307 and 308 keep the method and body. Credentials
/// and a `Host` the script set go only to the same origin.
fn follow_redirect(
    request: &mut ScriptHttpClientRequest,
    status: u16,
    from: &RequestUrl,
    to: &RequestUrl,
) {
    let method = request.method.to_ascii_uppercase();
    let to_get =
        (status == 303 && method != "HEAD") || (matches!(status, 301 | 302) && method == "POST");
    if to_get {
        request.method = "GET".to_string();
        request.body = None;
        request.body_binary = false;
        for name in ["Content-Type", "Content-Length", "Content-Encoding"] {
            remove(&mut request.headers, name);
        }
    }
    if !from.same_origin(to) {
        for name in ["Host", "Authorization", "Proxy-Authorization", "Cookie"] {
            remove(&mut request.headers, name);
        }
    }
    request.url = to.to_url();
}

async fn exchange(
    outbound: &dyn TcpOutbound,
    tls: &Arc<ClientConfig>,
    url: &RequestUrl,
    request: &ScriptHttpClientRequest,
) -> Result<Answer, &'static str> {
    let stream = outbound
        .connect(&url.target())
        .await
        .map_err(|_| CONNECT_FAILED)?;
    if url.tls {
        let server_name = ServerName::try_from(url.host.clone()).map_err(|_| INVALID_URL)?;
        let stream = tokio_rustls::TlsConnector::from(tls.clone())
            .connect(server_name, stream)
            .await
            .map_err(|_| CONNECT_FAILED)?;
        send(Conn::new(stream, Vec::new()), url, request).await
    } else {
        send(Conn::new(stream, Vec::new()), url, request).await
    }
}

async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    mut conn: Conn<S>,
    url: &RequestUrl,
    request: &ScriptHttpClientRequest,
) -> Result<Answer, &'static str> {
    // A byte-string body goes out as its bytes, not as UTF-8 of its chars.
    let body = request.body_bytes();
    let head = request_head(url, request, body.len());
    let io = |_: io::Error| BAD_RESPONSE;
    conn.write_all(&head.encode()).await.map_err(io)?;
    if !body.is_empty() {
        conn.write_all(&body).await.map_err(io)?;
    }

    let response = loop {
        let head = conn.read_head().await.map_err(io)?.ok_or(BAD_RESPONSE)?;
        let status = response_status(&head.start_line).map_err(io)?;
        if (100..200).contains(&status) {
            continue;
        }
        break head;
    };
    let status = response_status(&response.start_line).map_err(io)?;
    let no_body = request.method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304;
    let framing = if no_body {
        Framing::Length(0)
    } else if response.header("Transfer-Encoding").is_none()
        && response.header("Content-Length").is_none()
    {
        Framing::UntilClose
    } else {
        response.framing().map_err(io)?
    };
    let body = match conn.read_body(framing, MAX_BODY_BYTES).await.map_err(io)? {
        Body::Complete(body) => body,
        Body::TooLarge { .. } => return Err(TOO_LARGE),
    };
    Ok(Answer {
        status,
        headers: response.headers,
        body,
    })
}

/// The request head: the script's headers, minus the framing and connection
/// headers this client owns.
fn request_head(url: &RequestUrl, request: &ScriptHttpClientRequest, body_len: usize) -> Head {
    let mut headers = request.headers.clone();
    for name in [
        "Connection",
        "Content-Length",
        "Transfer-Encoding",
        "Accept-Encoding",
        "Proxy-Connection",
        "Keep-Alive",
        "TE",
        "Upgrade",
    ] {
        remove(&mut headers, name);
    }
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("Host"))
    {
        headers.insert(0, ("Host".to_string(), url.host_header()));
    }
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("User-Agent"))
    {
        headers.push(("User-Agent".to_string(), "NetworkCore".to_string()));
    }
    headers.push(("Accept-Encoding".to_string(), "identity".to_string()));
    headers.push(("Connection".to_string(), "close".to_string()));
    let method = request.method.to_ascii_uppercase();
    if body_len > 0 || matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
        headers.push(("Content-Length".to_string(), body_len.to_string()));
    }
    Head {
        start_line: format!("{method} {} HTTP/1.1", url.path),
        headers,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestUrl {
    tls: bool,
    host: String,
    port: u16,
    /// Path and query, starting with `/`.
    path: String,
}

impl RequestUrl {
    fn parse(url: &str) -> Option<Self> {
        let url = url.trim();
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else {
            (false, url.strip_prefix("http://")?)
        };
        let rest = rest.split('#').next().unwrap_or_default();
        let (authority, path) = match rest.find(['/', '?']) {
            Some(index) => rest.split_at(index),
            None => (rest, ""),
        };
        if authority.contains('@') || path.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
            return None;
        }
        let default_port = if tls { 443 } else { 80 };
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, after) = bracketed.split_once(']')?;
            host.parse::<std::net::Ipv6Addr>().ok()?;
            let port = match after.strip_prefix(':') {
                Some(port) => port.parse().ok()?,
                None if after.is_empty() => default_port,
                None => return None,
            };
            (host.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host.to_string(), port.parse().ok()?),
                None => (authority.to_string(), default_port),
            }
        };
        if host.is_empty()
            || port == 0
            || !host
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':'))
        {
            return None;
        }
        let path = if path.starts_with('?') {
            format!("/{path}")
        } else if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };
        Some(Self {
            tls,
            host: host.to_ascii_lowercase(),
            port,
            path,
        })
    }

    /// `location` from a redirect answered for this URL, resolved against
    /// it (RFC 3986 section 5.2): absolute, scheme-relative (`//host/path`),
    /// absolute-path, query-only or relative. `None` for another scheme or a
    /// URL this client cannot request.
    fn resolve(&self, location: &str) -> Option<Self> {
        let location = location.trim();
        let location = location.split('#').next().unwrap_or_default();
        let scheme = if self.tls { "https" } else { "http" };
        let lower = location.to_ascii_lowercase();
        if lower.starts_with("https://") || lower.starts_with("http://") {
            let (prefix, rest) = location.split_at(location.find("://")? + 3);
            return Self::parse(&format!("{}{rest}", prefix.to_ascii_lowercase()));
        }
        if let Some(rest) = location.strip_prefix("//") {
            return Self::parse(&format!("{scheme}://{rest}"));
        }
        // Any other `scheme:` before the first `/`, `?` or `#` is refused.
        let head = location.split(['/', '?']).next().unwrap_or_default();
        if head.contains(':') {
            return None;
        }
        let origin = format!("{scheme}://{}", self.host_header());
        let current_path = self.path.split('?').next().unwrap_or("/");
        let target = if location.is_empty() {
            self.path.clone()
        } else if location.starts_with('/') {
            location.to_string()
        } else if location.starts_with('?') {
            format!("{current_path}{location}")
        } else {
            let directory = &current_path[..current_path.rfind('/').map_or(0, |index| index + 1)];
            format!("{directory}{location}")
        };
        let (path, query) = match target.split_once('?') {
            Some((path, query)) => (path.to_string(), Some(query)),
            None => (target.clone(), None),
        };
        let mut resolved = format!("{origin}{}", remove_dot_segments(&path));
        if let Some(query) = query {
            resolved.push('?');
            resolved.push_str(query);
        }
        Self::parse(&resolved)
    }

    /// Same scheme, host and port.
    fn same_origin(&self, other: &Self) -> bool {
        self.tls == other.tls && self.host == other.host && self.port == other.port
    }

    fn to_url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{}{}", self.host_header(), self.path)
    }

    fn target(&self) -> TargetAddr {
        match self.host.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, self.port)),
            Err(_) => TargetAddr::Domain(self.host.clone(), self.port),
        }
    }

    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default_port = if self.tls { 443 } else { 80 };
        if self.port == default_port {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// RFC 3986 section 5.2.4 for an absolute path.
fn remove_dot_segments(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    let parts = path.split('/').skip(1).collect::<Vec<_>>();
    for (index, segment) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        match *segment {
            "." => {
                if last {
                    segments.push("");
                }
            }
            ".." => {
                segments.pop();
                if last {
                    segments.push("");
                }
            }
            segment => segments.push(segment),
        }
    }
    format!("/{}", segments.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_outbound::{BoxFuture, BoxStream};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Every connection the canned outbound saw: target and request bytes.
    type Seen = Arc<Mutex<Vec<(TargetAddr, Vec<u8>)>>>;

    #[test]
    fn parses_urls_and_refuses_others() {
        let url = RequestUrl::parse("https://API.example.test/v1?x=1#frag").unwrap();
        assert_eq!(
            url,
            RequestUrl {
                tls: true,
                host: "api.example.test".to_string(),
                port: 443,
                path: "/v1?x=1".to_string(),
            }
        );
        assert_eq!(url.host_header(), "api.example.test");
        let url = RequestUrl::parse("http://[::1]:8080").unwrap();
        assert_eq!(url.path, "/");
        assert_eq!(url.host_header(), "[::1]:8080");
        assert!(matches!(url.target(), TargetAddr::Ip(addr) if addr.port() == 8080));
        for bad in [
            "ftp://example.test/",
            "https://user@example.test/",
            "https://example.test/a b",
            "https://:443/",
            "https://example.test:0/",
        ] {
            assert_eq!(RequestUrl::parse(bad), None, "{bad}");
        }
    }

    /// Answers the n-th connection with the n-th canned response (the last
    /// one for any after it) and records the request bytes it received,
    /// body included.
    struct Canned {
        responses: Vec<&'static [u8]>,
        seen: Seen,
        /// Holds every answer back this long.
        delay: Duration,
    }

    impl TcpOutbound for Canned {
        fn protocol(&self) -> &'static str {
            "canned"
        }

        fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async move {
                let (client, mut server) = tokio::io::duplex(64 * 1024);
                let seen = self.seen.clone();
                let index = seen.lock().unwrap().len();
                let response = self.responses[index.min(self.responses.len() - 1)];
                let delay = self.delay;
                let target = target.clone();
                // Reserve the slot now, so the next connection gets the next answer.
                seen.lock().unwrap().push((target.clone(), Vec::new()));
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        if let Some(end) =
                            request.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            let head =
                                String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                            let length = head
                                .lines()
                                .find_map(|line| line.strip_prefix("content-length:"))
                                .and_then(|value| value.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if request.len() >= end + 4 + length {
                                break;
                            }
                        }
                        let read = server.read(&mut buf).await.unwrap_or(0);
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buf[..read]);
                    }
                    seen.lock().unwrap()[index] = (target, request);
                    tokio::time::sleep(delay).await;
                    let _ = server.write_all(response).await;
                    let _ = server.shutdown().await;
                });
                Ok(Box::new(client) as BoxStream)
            })
        }
    }

    fn client(response: &'static [u8]) -> (TunnelScriptHttpClient, Seen) {
        client_answering(vec![response], Duration::ZERO)
    }

    fn client_answering(
        responses: Vec<&'static [u8]>,
        delay: Duration,
    ) -> (TunnelScriptHttpClient, Seen) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let outbound = Arc::new(OnceLock::new());
        let _ = outbound.set(Arc::new(Canned {
            responses,
            seen: seen.clone(),
            delay,
        }) as Arc<dyn TcpOutbound>);
        (TunnelScriptHttpClient::new(outbound, client_tls()), seen)
    }

    fn request(method: &str, url: &str, body: Option<&str>) -> ScriptHttpClientRequest {
        ScriptHttpClientRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers: vec![
                ("X-Script".to_string(), "1".to_string()),
                ("Connection".to_string(), "keep-alive".to_string()),
            ],
            body: body.map(str::to_string),
            body_binary: false,
            binary_response: false,
            follow_redirects: true,
            timeout: Duration::from_secs(2),
        }
    }

    fn run(
        client: TunnelScriptHttpClient,
        request: ScriptHttpClientRequest,
    ) -> Result<ScriptResponse, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(async { tokio::task::spawn_blocking(move || client.execute(&request)).await })
            .unwrap()
    }

    fn seen_text(seen: &Seen, index: usize) -> (TargetAddr, String) {
        let seen = seen.lock().unwrap();
        let (target, bytes) = &seen[index];
        (target.clone(), String::from_utf8_lossy(bytes).into_owned())
    }

    #[test]
    fn resolves_redirect_locations_against_the_request_url() {
        let base = RequestUrl::parse("https://a.example.test/dir/page?x=1").unwrap();
        let resolved = |location: &str| base.resolve(location).map(|url| url.to_url());
        assert_eq!(
            resolved("HTTPS://b.example.test/next").as_deref(),
            Some("https://b.example.test/next")
        );
        assert_eq!(
            resolved("//c.example.test:8443/x").as_deref(),
            Some("https://c.example.test:8443/x")
        );
        assert_eq!(
            resolved("/root?y=2#frag").as_deref(),
            Some("https://a.example.test/root?y=2")
        );
        assert_eq!(
            resolved("other").as_deref(),
            Some("https://a.example.test/dir/other")
        );
        assert_eq!(
            resolved("../up/./there").as_deref(),
            Some("https://a.example.test/up/there")
        );
        assert_eq!(
            resolved("?z=3").as_deref(),
            Some("https://a.example.test/dir/page?z=3")
        );
        assert_eq!(resolved("ftp://a.example.test/"), None);
        assert_eq!(resolved("javascript:alert(1)"), None);
        assert!(base.same_origin(&base.resolve("/x").unwrap()));
        assert!(!base.same_origin(&base.resolve("http://a.example.test/x").unwrap()));
    }

    #[test]
    fn follows_redirects_and_turns_post_into_get_on_302() {
        let (client, seen) = client_answering(
            vec![
                b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone",
            ],
            Duration::ZERO,
        );
        let mut post = request("POST", "http://api.example.test/start", Some("x=1"));
        post.headers
            .push(("Content-Type".to_string(), "text/plain".to_string()));
        post.headers
            .push(("Authorization".to_string(), "Bearer t".to_string()));
        let response = run(client, post).expect("redirect is followed");
        assert_eq!(response.status, 200);
        assert_eq!(response.body.as_deref(), Some("done"));
        let (_, second) = seen_text(&seen, 1);
        assert!(second.starts_with("GET /next HTTP/1.1\r\n"), "{second}");
        assert!(!second.contains("Content-Type"), "{second}");
        assert!(!second.contains("x=1"), "{second}");
        // Same origin: the credentials stay.
        assert!(second.contains("Authorization: Bearer t\r\n"), "{second}");
    }

    #[test]
    fn cross_host_redirects_send_the_body_on_307_and_drop_credentials() {
        let (client, seen) = client_answering(
            vec![
                b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://b.example.test:8080/up\r\nContent-Length: 0\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            ],
            Duration::ZERO,
        );
        let mut post = request("POST", "http://a.example.test/start", Some("x=1"));
        post.headers
            .push(("Host".to_string(), "a.example.test".to_string()));
        post.headers.push(("Cookie".to_string(), "s=1".to_string()));
        post.headers
            .push(("Authorization".to_string(), "Bearer t".to_string()));
        let response = run(client, post).expect("redirect is followed");
        assert_eq!(response.body.as_deref(), Some("ok"));
        let (target, second) = seen_text(&seen, 1);
        assert_eq!(
            target,
            TargetAddr::Domain("b.example.test".to_string(), 8080)
        );
        assert!(
            second.starts_with("POST /up HTTP/1.1\r\nHost: b.example.test:8080\r\n"),
            "{second}"
        );
        assert!(second.ends_with("\r\n\r\nx=1"), "{second}");
        assert!(!second.contains("Bearer"), "{second}");
        assert!(!second.contains("s=1"), "{second}");
    }

    #[test]
    fn redirects_stop_when_turned_off_or_past_the_hop_limit() {
        let redirect: &'static [u8] =
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n";
        let (client, seen) = client_answering(vec![redirect], Duration::ZERO);
        let mut get = request("GET", "http://api.example.test/", None);
        get.follow_redirects = false;
        let response = run(client, get).expect("the redirect is the answer");
        assert_eq!(response.status, 301);
        assert_eq!(seen.lock().unwrap().len(), 1);

        let (client, seen) = client_answering(vec![redirect], Duration::ZERO);
        let response = run(client, request("GET", "http://api.example.test/", None))
            .expect("the last redirect is the answer");
        assert_eq!(response.status, 301);
        assert_eq!(
            seen.lock().unwrap().len(),
            SCRIPT_HTTP_CLIENT_MAX_REDIRECTS + 1
        );
    }

    #[test]
    fn all_hops_share_one_timeout() {
        let redirect: &'static [u8] =
            b"HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n";
        let (client, _) = client_answering(vec![redirect], Duration::from_millis(400));
        let mut get = request("GET", "http://api.example.test/", None);
        get.timeout = Duration::from_millis(1000);
        let started = std::time::Instant::now();
        let result = run(client, get);
        assert_eq!(result.unwrap_err(), TIMED_OUT);
        assert!(started.elapsed() < Duration::from_millis(1900));
    }

    #[test]
    fn binary_mode_keeps_every_byte_both_ways() {
        let (client, seen) = client_answering(
            vec![b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\x00\x80\xfe\xff"],
            Duration::ZERO,
        );
        let mut post = request(
            "POST",
            "http://api.example.test/upload",
            Some(&binary_body_string(&[0x00, 0x7f, 0x80, 0xff])),
        );
        post.body_binary = true;
        post.binary_response = true;
        let response = run(client, post).expect("request should succeed");
        assert_eq!(
            script_runtime::binary_body_bytes(response.body.as_deref().unwrap()),
            Some(vec![0x00, 0x80, 0xfe, 0xff])
        );
        let seen = seen.lock().unwrap();
        let bytes = &seen[0].1;
        assert!(bytes.ends_with(&[0x00, 0x7f, 0x80, 0xff]), "{bytes:?}");
        let text = String::from_utf8_lossy(bytes);
        assert!(text.contains("Content-Length: 4\r\n"), "{text}");
    }

    #[test]
    fn sends_one_request_through_the_outbound_and_reads_the_answer() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (client, seen) = client(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"a\":1}\r\n0\r\n\r\n",
        );
        let response = runtime
            .block_on(async {
                tokio::task::spawn_blocking(move || {
                    client.execute(&request(
                        "post",
                        "http://api.example.test:8080/v1",
                        Some("x=1"),
                    ))
                })
                .await
            })
            .unwrap()
            .expect("request should succeed");
        assert_eq!(response.status, 200);
        assert_eq!(response.body.as_deref(), Some("{\"a\":1}"));
        assert!(response
            .headers
            .iter()
            .any(|(name, value)| name == "Content-Type" && value == "application/json"));

        let seen = seen.lock().unwrap();
        let (target, bytes) = &seen[0];
        assert_eq!(
            *target,
            TargetAddr::Domain("api.example.test".to_string(), 8080)
        );
        let text = String::from_utf8_lossy(bytes);
        assert!(
            text.starts_with("POST /v1 HTTP/1.1\r\nHost: api.example.test:8080\r\n"),
            "{text}"
        );
        assert!(text.contains("X-Script: 1\r\n"), "{text}");
        assert!(text.contains("Connection: close\r\n"), "{text}");
        assert!(!text.contains("keep-alive"), "{text}");
        assert!(text.contains("Content-Length: 3\r\n"), "{text}");
    }

    #[test]
    fn oversized_answers_and_missing_outbounds_are_errors() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (client, _) = client(b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n");
        let result = runtime
            .block_on(async {
                tokio::task::spawn_blocking(move || {
                    client.execute(&request("GET", "http://big.example.test/", None))
                })
                .await
            })
            .unwrap();
        assert_eq!(result.unwrap_err(), TOO_LARGE);

        let unset = TunnelScriptHttpClient::new(Arc::new(OnceLock::new()), client_tls());
        let result = runtime
            .block_on(async {
                tokio::task::spawn_blocking(move || {
                    unset.execute(&request("GET", "http://api.example.test/", None))
                })
                .await
            })
            .unwrap();
        assert_eq!(result.unwrap_err(), UNAVAILABLE);
    }

    fn client_tls() -> Arc<ClientConfig> {
        Arc::new(
            transport_tls::client_config(&transport_tls::TlsSettings {
                server_name: String::new(),
                alpn: vec!["http/1.1".to_string()],
                insecure: false,
                ..transport_tls::TlsSettings::default()
            })
            .unwrap(),
        )
    }
}
