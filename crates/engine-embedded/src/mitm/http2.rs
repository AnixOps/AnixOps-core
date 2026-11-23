//! HTTP/2 for decrypted HTTPS flows.
//!
//! When the app's ClientHello offers `h2`, the origin is asked for `h2` and
//! `http/1.1` first and the app gets whatever the origin chose, so a
//! request is never translated between versions. With `h2` both sides run
//! the `h2` crate (framing, HPACK, flow control) and every stream goes
//! through the same rewrite hook and capture as an HTTP/1.1 message:
//!
//! - A body no rule reads is relayed frame by frame as flow control
//!   allows, trailers included (gRPC), and only its head is planned; a
//!   body a rule reads is held whole up to [`MAX_BODY_BYTES`], and a
//!   larger one is relayed without rewriting (`too_large`). All streams of
//!   one connection hold at most [`MAX_HELD_BODY_BYTES`] of such bodies at
//!   once, and all connections of the engine (HTTP/1.1 ones included) at
//!   most [`super::MAX_ENGINE_HELD_BODY_BYTES`]; a body that finds no room
//!   is relayed without rewriting too (`busy`), never waited for, since a
//!   stream that waits holds flow control window the others need.
//! - `text/event-stream` responses are relayed as they arrive
//!   (`streaming`).
//! - A request for another authority than the intercepted host gets
//!   `421 Misdirected Request`, so the app opens a connection of its own
//!   for it; `CONNECT` gets `405`.
//!
//! When the origin sends GOAWAY or closes, the app's connection is shut
//! down gracefully too: the app gets a GOAWAY, the streams in flight finish
//! (for at most `idle_timeout`), and a stream the origin never took is
//! reset with `REFUSED_STREAM`, which tells the app it may send it again on
//! a new connection. A stream the origin reset gets the origin's reason.
//!
//! All streams of one connection run in the flow's own task, without
//! spawning. Memory stays bounded for the Network Extension: at most
//! [`MAX_CONCURRENT_STREAMS`] streams, [`STREAM_WINDOW`] of receive window
//! per stream, [`SEND_BUFFER`] of queued data per stream on each side and
//! [`MAX_HELD_BODY_BYTES`] of bodies held for rules.

use std::io;
use std::pin::{pin, Pin};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use control_domain::{HttpMitmPhase, MetadataEntry};
use engine_native::NativePlainHttpMessage;
use futures::stream::{FuturesUnordered, StreamExt};
use h2::client::SendRequest;
use h2::server::SendResponse;
use h2::{Reason, RecvStream, SendStream};
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::request_route::{request_head, Decision, MAX_EXTRA_ORIGINS};
use super::{from_metadata, to_metadata, MitmEngine, Recording, Reroute, MAX_BODY_BYTES};
use crate::capture::h2frames::{FrameScanner, Link};
use crate::capture::{CaptureStore, CapturedBody, Direction, HTTP_2, MAX_HTTP_BODY_BYTES};

/// The ALPN id of HTTP/2.
pub const ALPN_H2: &[u8] = b"h2";
/// Streams one decrypted connection carries at once.
pub const MAX_CONCURRENT_STREAMS: u32 = 16;
/// Receive window of one stream.
pub const STREAM_WINDOW: u32 = 128 * 1024;
/// Receive window of a whole connection.
pub const CONNECTION_WINDOW: u32 = 1024 * 1024;
/// Data queued for sending on one stream before the sender waits.
pub const SEND_BUFFER: usize = 128 * 1024;
/// Largest header list accepted.
const MAX_HEADER_LIST: u32 = 64 * 1024;
/// Grace for in-flight streams after an idle connection sent GOAWAY.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
/// Body bytes the streams of one connection hold at once for rules to
/// read (each held body is copied about twice more while it is planned).
pub const MAX_HELD_BODY_BYTES: usize = 2 * MAX_BODY_BYTES;

/// Headers that do not exist in HTTP/2 or that the relay sets itself.
const CONNECTION_HEADERS: [&str; 6] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "host",
];

fn h2_error(error: h2::Error) -> io::Error {
    if error.is_io() {
        return error
            .into_io()
            .unwrap_or_else(|| io::Error::other("http/2 failed"));
    }
    io::Error::other(error)
}

/// A request that never reached the origin: its connection was going away
/// or gone before the stream opened there, so the app may send it again.
#[derive(Debug)]
struct NotSent(h2::Error);

impl std::fmt::Display for NotSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request not sent to the origin: {}", self.0)
    }
}

impl std::error::Error for NotSent {}

fn not_sent(error: h2::Error) -> io::Error {
    io::Error::other(NotSent(error))
}

/// How the app's stream is reset after `error`, and whether the origin's
/// connection is going away (so the app's connection should too).
fn reset_reason(error: &io::Error) -> (Reason, bool) {
    let inner = error.get_ref();
    if inner.is_some_and(|inner| inner.is::<NotSent>()) {
        return (Reason::REFUSED_STREAM, true);
    }
    match inner.and_then(|inner| inner.downcast_ref::<h2::Error>()) {
        // The origin's GOAWAY reset only streams it never processed (those
        // past its last stream id, RFC 9113 section 6.8).
        Some(h2) if h2.is_go_away() && h2.is_remote() => (Reason::REFUSED_STREAM, true),
        Some(h2) if h2.is_reset() && h2.is_remote() => {
            (h2.reason().unwrap_or(Reason::INTERNAL_ERROR), false)
        }
        _ => (Reason::INTERNAL_ERROR, false),
    }
}

/// Body bytes that may still be held for rules: those of the streams of
/// one connection (see [`MAX_HELD_BODY_BYTES`]), or, as the parent of every
/// connection's budget and of HTTP/1.1 exchanges, those of the whole engine
/// (see [`super::MAX_ENGINE_HELD_BODY_BYTES`]).
pub(super) struct BodyBudget {
    left: AtomicUsize,
    /// A budget every byte is also taken from.
    parent: Option<Arc<BodyBudget>>,
}

impl BodyBudget {
    pub(super) fn new(bytes: usize) -> Self {
        Self {
            left: AtomicUsize::new(bytes),
            parent: None,
        }
    }

    /// A budget of `bytes` whose bytes are also taken from `parent`.
    pub(super) fn within(bytes: usize, parent: Arc<BodyBudget>) -> Self {
        Self {
            left: AtomicUsize::new(bytes),
            parent: Some(parent),
        }
    }

    /// Takes `bytes` from this budget alone; `false`, taking nothing, when
    /// they do not fit.
    fn take(&self, bytes: usize) -> bool {
        let mut current = self.left.load(Ordering::Acquire);
        loop {
            let Some(rest) = current.checked_sub(bytes) else {
                return false;
            };
            match self.left.compare_exchange_weak(
                current,
                rest,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn give(&self, bytes: usize) {
        self.left.fetch_add(bytes, Ordering::AcqRel);
    }

    #[cfg(test)]
    pub(super) fn left(&self) -> usize {
        self.left.load(Ordering::Acquire)
    }
}

/// What one stream or exchange holds of a [`BodyBudget`] (and its
/// parent), given back when dropped, whichever way it ends.
pub(super) struct Held<'a> {
    budget: &'a BodyBudget,
    bytes: usize,
}

impl<'a> Held<'a> {
    pub(super) fn new(budget: &'a BodyBudget) -> Self {
        Self { budget, bytes: 0 }
    }

    /// Takes `bytes` more from the budget and its parent; `false`, taking
    /// nothing, when they do not fit in either.
    pub(super) fn grow(&mut self, bytes: usize) -> bool {
        if !self.budget.take(bytes) {
            return false;
        }
        if let Some(parent) = &self.budget.parent {
            if !parent.take(bytes) {
                self.budget.give(bytes);
                return false;
            }
        }
        self.bytes += bytes;
        true
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.budget.give(self.bytes);
        if let Some(parent) = &self.budget.parent {
            parent.give(self.bytes);
        }
    }
}

impl MitmEngine {
    /// Relays one decrypted HTTP/2 connection until the app closes it, the
    /// origin does, or it stays idle for `idle_timeout`.
    pub(super) async fn relay_h2<C, O>(
        &self,
        client: C,
        origin: O,
        host: &str,
        authority: &str,
        idle_timeout: Duration,
        reroute: Reroute<'_>,
    ) -> io::Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send,
        O: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let capture = crate::capture::current_flow();

        // With capture on, every frame header on both links is kept.
        let origin = FrameTap::new(origin, Link::Origin, capture.as_ref());
        let client = FrameTap::new(client, Link::App, capture.as_ref());
        let (send_request, upstream) = tokio::time::timeout(
            idle_timeout,
            h2::client::Builder::new()
                .enable_push(false)
                .initial_window_size(STREAM_WINDOW)
                .initial_connection_window_size(CONNECTION_WINDOW)
                .max_send_buffer_size(SEND_BUFFER)
                .max_header_list_size(MAX_HEADER_LIST)
                .handshake::<_, Bytes>(origin),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(h2_error)?;
        let mut server = tokio::time::timeout(
            idle_timeout,
            h2::server::Builder::new()
                .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
                .initial_window_size(STREAM_WINDOW)
                .initial_connection_window_size(CONNECTION_WINDOW)
                .max_send_buffer_size(SEND_BUFFER)
                .max_header_list_size(MAX_HEADER_LIST)
                .handshake::<_, Bytes>(client),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(h2_error)?;

        // Origin connections through other outbounds, for streams whose
        // request routes elsewhere; driven in this task like the rest.
        let (driver_tx, mut driver_rx) = tokio::sync::mpsc::unbounded_channel();
        let origins = Origins {
            primary: send_request,
            reroute: &reroute,
            extra: tokio::sync::Mutex::new(Vec::new()),
            drivers: driver_tx,
            going_away: AtomicBool::new(false),
        };
        // Bounded per connection and, with every other connection, by the
        // engine's budget.
        let budget = BodyBudget::within(MAX_HELD_BODY_BYTES, self.held_bodies.clone());
        let mut drivers = FuturesUnordered::new();
        let mut upstream = pin!(upstream);
        let mut upstream_done = false;
        let mut streams = FuturesUnordered::new();
        let idle = tokio::time::sleep(idle_timeout);
        let mut idle = pin!(idle);
        // Once the origin's connection is gone: how long the streams in
        // flight may still take.
        let drain = tokio::time::sleep(idle_timeout);
        let mut drain = pin!(drain);
        let mut closing = false;
        loop {
            tokio::select! {
                accepted = server.accept() => match accepted {
                    Some(Ok((request, respond))) => {
                        streams.push(self.h2_stream(
                            request,
                            respond,
                            &origins,
                            &budget,
                            host,
                            authority,
                            capture.as_ref(),
                        ));
                    }
                    Some(Err(error)) if error.is_go_away() || error.is_io() => break,
                    Some(Err(error)) => return Err(h2_error(error)),
                    None => break,
                },
                Some(()) = streams.next(), if !streams.is_empty() => {
                    idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                    if upstream_done && streams.is_empty() {
                        // The GOAWAY the app got is flushed as the
                        // connection is polled for the grace below.
                        idle.as_mut().reset(tokio::time::Instant::now() + SHUTDOWN_GRACE);
                    }
                }
                Some(driver) = driver_rx.recv() => drivers.push(driver),
                Some(()) = drivers.next(), if !drivers.is_empty() => {}
                // The origin's connection ended (GOAWAY, or closed). A
                // finished h2 connection is ready again at once when
                // polled, so this branch runs once.
                _ = &mut upstream, if !upstream_done => {
                    upstream_done = true;
                    origins.going_away.store(true, Ordering::Release);
                    drain.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                    if streams.is_empty() {
                        idle.as_mut().reset(tokio::time::Instant::now() + SHUTDOWN_GRACE);
                    }
                }
                _ = &mut drain, if upstream_done => break,
                _ = &mut idle, if streams.is_empty() => {
                    if closing {
                        break;
                    }
                    closing = true;
                    server.graceful_shutdown();
                    idle.as_mut().reset(tokio::time::Instant::now() + SHUTDOWN_GRACE);
                }
            }
            // The origin is going away: the app gets a GOAWAY, so it sends
            // new requests on a new connection while these streams finish.
            if !closing && origins.going_away.load(Ordering::Acquire) {
                closing = true;
                server.graceful_shutdown();
            }
        }
        Ok(())
    }

    /// One stream; failures reset it and leave the connection up (see
    /// [`reset_reason`] for the reason the app gets).
    #[allow(clippy::too_many_arguments)]
    async fn h2_stream(
        &self,
        request: Request<RecvStream>,
        mut respond: SendResponse<Bytes>,
        origins: &Origins<'_>,
        budget: &BodyBudget,
        host: &str,
        authority: &str,
        capture: Option<&(std::sync::Arc<crate::capture::CaptureStore>, u64)>,
    ) {
        let relayed = self
            .relay_h2_stream(
                request,
                &mut respond,
                origins,
                budget,
                host,
                authority,
                capture,
            )
            .await;
        if let Err(error) = relayed {
            let (reason, going_away) = reset_reason(&error);
            if going_away {
                origins.going_away.store(true, Ordering::Release);
            }
            respond.send_reset(reason);
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn relay_h2_stream(
        &self,
        request: Request<RecvStream>,
        respond: &mut SendResponse<Bytes>,
        origins: &Origins<'_>,
        budget: &BodyBudget,
        host: &str,
        authority: &str,
        capture: Option<&(std::sync::Arc<crate::capture::CaptureStore>, u64)>,
    ) -> io::Result<()> {
        let (parts, mut request_body) = request.into_parts();
        if parts.method == Method::CONNECT {
            return answer(
                respond,
                StatusCode::METHOD_NOT_ALLOWED,
                HeaderMap::new(),
                Bytes::new(),
                false,
            );
        }
        if !same_host(&parts.uri, &parts.headers, host) {
            return answer(
                respond,
                StatusCode::MISDIRECTED_REQUEST,
                HeaderMap::new(),
                Bytes::new(),
                false,
            );
        }
        let method = parts.method.as_str().to_string();
        let path = parts
            .uri
            .path_and_query()
            .map(|path| path.as_str())
            .filter(|path| path.starts_with('/'))
            .unwrap_or("/")
            .to_string();
        let url = format!("https://{authority}{path}");
        let is_head = parts.method == Method::HEAD;
        // Rules and scripts see one `cookie` field, as in HTTP/1.1; the
        // capture keeps the fields as they came.
        let mut request_headers = vec![("host".to_string(), authority.to_string())];
        request_headers.extend(plan_header_list(&parts.headers));
        let mut recording = capture.map(|capture| {
            let mut recording =
                Recording::new(capture, &method, &url, &header_list(&parts.headers));
            recording.exchange.http_version = HTTP_2;
            recording.publish();
            recording
        });
        let refused = match origins.pick(self, &url, &parts.headers).await {
            Pick::Send(upstream) => Ok(upstream),
            Pick::Reject => Err((StatusCode::FORBIDDEN, "rejected")),
            Pick::Failed => Err((StatusCode::BAD_GATEWAY, "connect_failed")),
        };
        let upstream = match refused {
            Ok(upstream) => upstream,
            Err((status, note)) => {
                if let Some(recording) = &mut recording {
                    recording.exchange.status = Some(status.as_u16());
                    recording.exchange.note = Some(note);
                }
                return answer(respond, status, HeaderMap::new(), Bytes::new(), is_head);
            }
        };
        let stream_request = !self.needs_body(&url, HttpMitmPhase::Request);
        let stream_response = !self.needs_body(&url, HttpMitmPhase::Response);
        let request_ends = request_body.is_end_stream();

        // The request body, when a rule reads it; what it holds of the
        // connection's budget goes back when this stream ends.
        let mut held = Held::new(budget);
        let mut held_request = None;
        if !stream_request && !request_ends {
            match collect(&mut request_body, MAX_BODY_BYTES, &mut held).await? {
                Collected::Complete(body, trailers) => held_request = Some((body, trailers)),
                Collected::Partial(prefix, note) => {
                    // Relayed as it is, without rewriting.
                    if let Some(recording) = &mut recording {
                        recording.exchange.request_body = CapturedBody {
                            data: prefix[..prefix.len().min(MAX_HTTP_BODY_BYTES)].to_vec(),
                            size: prefix.len() as u64,
                        };
                        recording.exchange.note = Some(note);
                        recording.exchange.rules_skipped = true;
                    }
                    let headers = upstream_headers(&parts.headers);
                    let upstream_request = build_request(&parts.method, authority, &path, headers)?;
                    let mut upstream = upstream.ready().await.map_err(not_sent)?;
                    let (response, mut send) = upstream
                        .send_request(upstream_request, false)
                        .map_err(not_sent)?;
                    send_bytes(&mut send, Bytes::from(prefix)).await?;
                    pump(&mut request_body, &mut send, None).await?;
                    let response = response.await.map_err(h2_error)?;
                    return self
                        .forward_response(respond, response, None, recording.as_mut())
                        .await;
                }
            }
        }
        let holds_request = held_request.is_some();
        let (body_for_plan, request_trailers) = held_request.unwrap_or_default();
        if let (Some(recording), true) = (&mut recording, holds_request) {
            recording.exchange.request_body = CapturedBody::of(&body_for_plan);
        }
        let request_id = self.next_request_id();
        let report = self
            .plan(NativePlainHttpMessage {
                request_id: request_id.clone(),
                url: url.clone(),
                method: Some(method.clone()),
                phase: HttpMitmPhase::Request,
                status_code: None,
                headers: to_metadata(&request_headers),
                body: body_for_plan,
                request_headers: Vec::new(),
                request_body: None,
            })
            .await?;

        if report.terminal_action.is_some() {
            let status = status(report.final_status_code, StatusCode::OK);
            let mut headers = header_map(&from_metadata(&report.headers));
            if let Some(location) = report
                .redirect_location
                .as_deref()
                .and_then(|location| HeaderValue::from_str(location).ok())
            {
                headers.insert(http::header::LOCATION, location);
            }
            if let Some(recording) = &mut recording {
                recording.exchange.status = Some(status.as_u16());
                recording.exchange.response_headers = header_list(&headers);
                recording.exchange.response_body = CapturedBody::of(&report.body);
                recording.exchange.note = Some("answered_locally");
            }
            return answer(respond, status, headers, Bytes::from(report.body), is_head);
        }

        // A rewrite may change the path; the authority stays the host.
        let path = report
            .url
            .strip_prefix(&format!("https://{authority}"))
            .filter(|rest| rest.starts_with('/'))
            .unwrap_or(path.as_str())
            .to_string();
        let mut headers = header_map(&from_metadata(&report.headers));
        strip_connection_headers(&mut headers);
        split_cookie_fields(&mut headers);
        if holds_request || !report.body.is_empty() && !stream_request {
            headers.remove(http::header::CONTENT_LENGTH);
            headers.insert(
                http::header::CONTENT_LENGTH,
                HeaderValue::from(report.body.len()),
            );
        }
        if stream_request {
            keep_streamed_body_headers(&mut headers, &parts.headers);
        }
        if !stream_response {
            // Rules read the response body as sent, so ask for it
            // uncompressed.
            headers.insert(
                http::header::ACCEPT_ENCODING,
                HeaderValue::from_static("identity"),
            );
        }
        let upstream_request = build_request(&parts.method, authority, &path, headers)?;
        let mut upstream = upstream.ready().await.map_err(not_sent)?;
        if !stream_request {
            let trailers = request_trailers;
            let sent_body = Bytes::from(report.body);
            let end = sent_body.is_empty() && trailers.is_none();
            let (response, mut send) = upstream
                .send_request(upstream_request, end)
                .map_err(not_sent)?;
            if !end {
                send_bytes(&mut send, sent_body.clone()).await?;
                finish(&mut send, trailers)?;
            }
            let response = response.await.map_err(h2_error)?;
            let sent = SentRequest {
                headers: report.headers,
                body: Some(sent_body.to_vec()),
            };
            return self
                .respond_planned(
                    respond,
                    response,
                    request_id,
                    url,
                    method,
                    sent,
                    stream_response,
                    recording.as_mut(),
                    is_head,
                    budget,
                )
                .await;
        }
        let sent = SentRequest {
            headers: report.headers,
            body: None,
        };
        // The request body streams while the response is handled, so a
        // bidirectional stream (gRPC) keeps going both ways.
        let (response, mut send) = upstream
            .send_request(upstream_request, request_ends)
            .map_err(not_sent)?;
        let mut tap = Tap::new(recording.is_some());
        let request = async {
            if !request_ends {
                pump(&mut request_body, &mut send, Some(&mut tap)).await?;
            }
            Ok::<_, io::Error>(())
        };
        let responding = async {
            let response = response.await.map_err(h2_error)?;
            self.respond_planned(
                respond,
                response,
                request_id,
                url,
                method,
                sent,
                stream_response,
                recording.as_mut(),
                is_head,
                budget,
            )
            .await
        };
        let joined = tokio::try_join!(request, responding);
        if let (Some(recording), Some(body)) = (&mut recording, tap.into_body()) {
            recording.exchange.request_body = body;
        }
        joined.map(|_| ())
    }

    /// Plans the origin's response (head only when no rule reads its body)
    /// and relays it.
    #[allow(clippy::too_many_arguments)]
    async fn respond_planned(
        &self,
        respond: &mut SendResponse<Bytes>,
        response: Response<RecvStream>,
        request_id: String,
        url: String,
        method: String,
        sent: SentRequest,
        stream_response: bool,
        mut recording: Option<&mut Recording<'_>>,
        is_head: bool,
        budget: &BodyBudget,
    ) -> io::Result<()> {
        let (parts, mut body) = response.into_parts();
        let event_stream = parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().starts_with("text/event-stream"));
        if event_stream {
            if let Some(recording) = recording.as_deref_mut() {
                recording.stream(!stream_response);
            }
            let response = Response::from_parts(parts, body);
            return self
                .forward_response(respond, response, None, recording)
                .await;
        }
        let no_body = is_head
            || parts.status == StatusCode::NO_CONTENT
            || parts.status == StatusCode::NOT_MODIFIED
            || body.is_end_stream();
        let mut response_headers = header_list(&parts.headers);
        if stream_response || no_body {
            let report = self
                .plan(NativePlainHttpMessage {
                    request_id,
                    url,
                    method: Some(method),
                    phase: HttpMitmPhase::Response,
                    status_code: Some(parts.status.as_u16()),
                    headers: to_metadata(&response_headers),
                    body: Vec::new(),
                    request_headers: sent.headers,
                    request_body: sent.body,
                })
                .await?;
            if report.terminal_action.is_some() {
                let status = status(report.final_status_code, parts.status);
                let headers = header_map(&from_metadata(&report.headers));
                if let Some(recording) = recording.as_deref_mut() {
                    recording.exchange.status = Some(status.as_u16());
                    recording.exchange.response_headers = header_list(&headers);
                    recording.exchange.response_body = CapturedBody::of(&report.body);
                    recording.exchange.note = Some("answered_locally");
                }
                return answer(respond, status, headers, Bytes::from(report.body), is_head);
            }
            let mut head = Response::new(());
            *head.status_mut() = status(report.final_status_code, parts.status);
            *head.headers_mut() = header_map(&from_metadata(&report.headers));
            strip_connection_headers(head.headers_mut());
            keep_streamed_body_headers(head.headers_mut(), &parts.headers);
            if let Some(recording) = recording.as_deref_mut() {
                recording.exchange.status = Some(head.status().as_u16());
                recording.exchange.response_headers = header_list(head.headers());
            }
            let end = body.is_end_stream();
            let mut send = respond.send_response(head, end).map_err(h2_error)?;
            if !end {
                let mut tap = Tap::new(recording.is_some());
                pump(&mut body, &mut send, Some(&mut tap)).await?;
                if let (Some(recording), Some(body)) = (recording, tap.into_body()) {
                    recording.exchange.response_body = body;
                }
            }
            return Ok(());
        }

        // A rule reads the body: hold it whole, or relay it unchanged when
        // it is too large or the connection's budget has no room for it.
        let mut held = Held::new(budget);
        let (data, trailers) = match collect(&mut body, MAX_BODY_BYTES, &mut held).await? {
            Collected::Complete(data, trailers) => (
                super::decoded_for_rules(&mut response_headers, data),
                trailers,
            ),
            Collected::Partial(prefix, note) => {
                if let Some(recording) = recording.as_deref_mut() {
                    recording.exchange.note = Some(note);
                    recording.exchange.rules_skipped = true;
                }
                let response = Response::from_parts(parts, body);
                return self
                    .forward_response(respond, response, Some(prefix), recording)
                    .await;
            }
        };
        let report = self
            .plan(NativePlainHttpMessage {
                request_id,
                url,
                method: Some(method),
                phase: HttpMitmPhase::Response,
                status_code: Some(parts.status.as_u16()),
                headers: to_metadata(&response_headers),
                body: data,
                request_headers: sent.headers,
                request_body: sent.body,
            })
            .await?;
        let status = status(report.final_status_code, parts.status);
        let mut headers = header_map(&from_metadata(&report.headers));
        strip_connection_headers(&mut headers);
        if let Some(location) = report
            .redirect_location
            .as_deref()
            .and_then(|location| HeaderValue::from_str(location).ok())
        {
            headers.insert(http::header::LOCATION, location);
        }
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from(report.body.len()),
        );
        if let Some(recording) = recording {
            recording.exchange.status = Some(status.as_u16());
            recording.exchange.response_headers = header_list(&headers);
            recording.exchange.response_body = CapturedBody::of(&report.body);
            if report.terminal_action.is_some() {
                recording.exchange.note = Some("answered_locally");
            }
        }
        let mut head = Response::new(());
        *head.status_mut() = status;
        *head.headers_mut() = headers;
        let end = report.body.is_empty() && trailers.is_none();
        let mut send = respond.send_response(head, end).map_err(h2_error)?;
        if !end {
            send_bytes(&mut send, Bytes::from(report.body)).await?;
            finish(&mut send, trailers)?;
        }
        Ok(())
    }

    /// Relays an origin response unchanged: `prefix` (body bytes already
    /// read) and then the rest of `response`'s body and trailers.
    async fn forward_response(
        &self,
        respond: &mut SendResponse<Bytes>,
        response: Response<RecvStream>,
        prefix: Option<Vec<u8>>,
        recording: Option<&mut Recording<'_>>,
    ) -> io::Result<()> {
        let (parts, mut body) = response.into_parts();
        let mut head = Response::new(());
        *head.status_mut() = parts.status;
        *head.headers_mut() = parts.headers;
        strip_connection_headers(head.headers_mut());
        let streaming = recording
            .as_ref()
            .is_some_and(|recording| recording.exchange.note == Some("streaming"));
        let mut tap = Tap::new(recording.is_some() && !streaming);
        let end = body.is_end_stream() && prefix.as_ref().is_none_or(Vec::is_empty);
        let status = head.status().as_u16();
        let headers = header_list(head.headers());
        let mut send = respond.send_response(head, end).map_err(h2_error)?;
        if let Some(recording) = recording {
            recording.exchange.status = Some(status);
            recording.exchange.response_headers = headers;
            if streaming {
                recording.start_events();
            }
            if !end {
                if let Some(prefix) = prefix {
                    tap.add(&prefix);
                    send_bytes(&mut send, Bytes::from(prefix)).await?;
                }
                if streaming {
                    pump_events(&mut body, &mut send, recording).await?;
                } else {
                    pump(&mut body, &mut send, Some(&mut tap)).await?;
                }
            }
            if let Some(body) = tap.into_body() {
                recording.exchange.response_body = body;
            }
            return Ok(());
        }
        if !end {
            if let Some(prefix) = prefix {
                send_bytes(&mut send, Bytes::from(prefix)).await?;
            }
            pump(&mut body, &mut send, None).await?;
        }
        Ok(())
    }
}

/// The first bytes of a relayed body, for capture.
/// Keeps a body for capture as the pieces it arrived in, joined once when
/// the exchange is filed, so a growing body is never copied on reallocation
/// (the iOS extension's peak memory).
struct Tap {
    pieces: Option<Vec<Vec<u8>>>,
    kept: usize,
    size: u64,
}

impl Tap {
    fn new(on: bool) -> Self {
        Self {
            pieces: on.then(Vec::new),
            kept: 0,
            size: 0,
        }
    }

    fn add(&mut self, chunk: &[u8]) {
        if let Some(pieces) = &mut self.pieces {
            self.size += chunk.len() as u64;
            let room = MAX_HTTP_BODY_BYTES.saturating_sub(self.kept);
            let take = chunk.len().min(room);
            if take > 0 {
                pieces.push(chunk[..take].to_vec());
                self.kept += take;
            }
        }
    }

    fn into_body(self) -> Option<CapturedBody> {
        let kept = self.kept;
        self.pieces.map(|pieces| {
            let mut data = Vec::with_capacity(kept);
            for piece in pieces {
                data.extend_from_slice(&piece);
            }
            CapturedBody {
                data,
                size: self.size,
            }
        })
    }
}

enum Collected {
    Complete(Vec<u8>, Option<HeaderMap>),
    /// Not held whole: what was read so far, and why (`too_large` past the
    /// limit, `busy` when the connection's or the engine's [`BodyBudget`]
    /// had no room).
    Partial(Vec<u8>, &'static str),
}

/// Reads a body whole, up to `limit` bytes, each piece taken from `held`
/// first.
async fn collect(
    body: &mut RecvStream,
    limit: usize,
    held: &mut Held<'_>,
) -> io::Result<Collected> {
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(h2_error)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        let fits = held.grow(chunk.len());
        data.extend_from_slice(&chunk);
        if !fits {
            return Ok(Collected::Partial(data, "busy"));
        }
        if data.len() > limit {
            return Ok(Collected::Partial(data, "too_large"));
        }
    }
    let trailers = body.trailers().await.map_err(h2_error)?;
    Ok(Collected::Complete(data, trailers))
}

/// Relays `body` (data, then trailers or the end of the stream) to `send`
/// as flow control allows on both sides.
async fn pump(
    body: &mut RecvStream,
    send: &mut SendStream<Bytes>,
    mut tap: Option<&mut Tap>,
) -> io::Result<()> {
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(h2_error)?;
        let len = chunk.len();
        if let Some(tap) = tap.as_deref_mut() {
            tap.add(&chunk);
        }
        send_bytes(send, chunk).await?;
        // Released only once the other side took it: backpressure.
        let _ = body.flow_control().release_capacity(len);
    }
    let trailers = body.trailers().await.map_err(h2_error)?;
    finish(send, trailers)
}

/// [`pump`] for an event stream: each piece goes to `recording` once sent,
/// which keeps its events.
async fn pump_events(
    body: &mut RecvStream,
    send: &mut SendStream<Bytes>,
    recording: &mut Recording<'_>,
) -> io::Result<()> {
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(h2_error)?;
        let len = chunk.len();
        send_bytes(send, chunk.clone()).await?;
        recording.response_bytes(&chunk);
        let _ = body.flow_control().release_capacity(len);
    }
    let trailers = body.trailers().await.map_err(h2_error)?;
    finish(send, trailers)
}

/// Sends `data` without ending the stream, waiting for send capacity.
async fn send_bytes(send: &mut SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?
            .map_err(h2_error)?;
        if capacity == 0 {
            continue;
        }
        let chunk = data.split_to(capacity.min(data.len()));
        send.send_data(chunk, false).map_err(h2_error)?;
    }
    Ok(())
}

/// Ends the stream, with trailers when there are any.
fn finish(send: &mut SendStream<Bytes>, trailers: Option<HeaderMap>) -> io::Result<()> {
    match trailers {
        Some(trailers) => send.send_trailers(trailers),
        None => send.send_data(Bytes::new(), true),
    }
    .map_err(h2_error)
}

/// Where a stream's request goes when requests are routed one by one (see
/// [`super::request_route`]).
enum Pick {
    Send(SendRequest<Bytes>),
    Reject,
    Failed,
}

/// The origin connections of one HTTP/2 app connection through outbounds
/// other than its own, opened as streams route to them, at most
/// [`MAX_EXTRA_ORIGINS`].
struct Origins<'r> {
    /// The app connection's own origin.
    primary: SendRequest<Bytes>,
    reroute: &'r Reroute<'r>,
    extra: tokio::sync::Mutex<Vec<(String, SendRequest<Bytes>)>>,
    /// Hands each new connection's driver to the relay loop.
    drivers: tokio::sync::mpsc::UnboundedSender<engine_outbound::BoxFuture<'static, ()>>,
    /// The origin's connection sent GOAWAY or closed: the relay loop shuts
    /// the app's connection down gracefully.
    going_away: AtomicBool,
}

impl Origins<'_> {
    /// Routes the request for `url` and returns where to send it: the
    /// connection's own origin when it routes there or
    /// requests are not routed, else an origin connection through the
    /// outbound it routes to, opened now if there is none that still works.
    async fn pick(&self, engine: &MitmEngine, url: &str, headers: &HeaderMap) -> Pick {
        let Some(routes) = &self.reroute.routes else {
            return Pick::Send(self.primary.clone());
        };
        let user_agent = headers
            .get(http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok());
        let head = request_head(url, user_agent);
        let name = match routes.decide(&routes.connection, &head).await {
            Decision::Keep => return Pick::Send(self.primary.clone()),
            Decision::Reject => return Pick::Reject,
            Decision::Switch(name) => name,
        };
        let mut extra = self.extra.lock().await;
        if let Some(index) = extra.iter().position(|(open, _)| *open == name) {
            // A connection the origin closed fails `ready`; open another.
            match extra[index].1.clone().ready().await {
                Ok(send) => return Pick::Send(send),
                Err(_) => {
                    extra.remove(index);
                }
            }
        }
        if extra.len() >= MAX_EXTRA_ORIGINS {
            return Pick::Failed;
        }
        let Ok(stream) = engine
            .connect_routed(self.reroute, routes, &head, true)
            .await
        else {
            return Pick::Failed;
        };
        let handshake = h2::client::Builder::new()
            .enable_push(false)
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .max_send_buffer_size(SEND_BUFFER)
            .max_header_list_size(MAX_HEADER_LIST)
            .handshake::<_, Bytes>(stream);
        let Ok(Ok((send, connection))) =
            tokio::time::timeout(self.reroute.connect_timeout, handshake).await
        else {
            return Pick::Failed;
        };
        if self
            .drivers
            .send(Box::pin(async move {
                let _ = connection.await;
            }))
            .is_err()
        {
            return Pick::Failed;
        }
        extra.push((name, send.clone()));
        Pick::Send(send)
    }
}

/// A complete response the relay makes itself.
fn answer(
    respond: &mut SendResponse<Bytes>,
    status: StatusCode,
    mut headers: HeaderMap,
    body: Bytes,
    is_head: bool,
) -> io::Result<()> {
    strip_connection_headers(&mut headers);
    headers.remove(http::header::CONTENT_LENGTH);
    if status != StatusCode::NO_CONTENT && status != StatusCode::NOT_MODIFIED {
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    }
    let mut head = Response::new(());
    *head.status_mut() = status;
    *head.headers_mut() = headers;
    let end = body.is_empty() || is_head;
    let mut send = respond.send_response(head, end).map_err(h2_error)?;
    if !end {
        // A local answer is small: queue it whole.
        send.send_data(body, true).map_err(h2_error)?;
    }
    Ok(())
}

fn status(code: Option<u16>, fallback: StatusCode) -> StatusCode {
    code.and_then(|code| StatusCode::from_u16(code).ok())
        .unwrap_or(fallback)
}

/// Whether the request's authority names the intercepted host.
fn same_host(uri: &Uri, headers: &HeaderMap, host: &str) -> bool {
    let authority = uri
        .authority()
        .map(|authority| authority.host().to_string())
        .or_else(|| {
            headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(|value| {
                    value
                        .rsplit_once(':')
                        .map_or(value, |(host, _)| host)
                        .to_string()
                })
        });
    authority.is_none_or(|authority| authority.eq_ignore_ascii_case(host))
}

fn build_request(
    method: &Method,
    authority: &str,
    path: &str,
    headers: HeaderMap,
) -> io::Result<Request<()>> {
    let uri = Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path)
        .build()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid request target"))?;
    let mut request = Request::new(());
    *request.method_mut() = method.clone();
    *request.uri_mut() = uri;
    *request.version_mut() = http::Version::HTTP_2;
    *request.headers_mut() = headers;
    Ok(request)
}

fn upstream_headers(headers: &HeaderMap) -> HeaderMap {
    let mut headers = headers.clone();
    strip_connection_headers(&mut headers);
    headers
}

/// A body relayed frame by frame goes on exactly as `original` sized and
/// encoded it, so those headers stay the original's whatever a rule or a
/// script without `requires-body` did to the head.
fn keep_streamed_body_headers(headers: &mut HeaderMap, original: &HeaderMap) {
    for name in [http::header::CONTENT_LENGTH, http::header::CONTENT_ENCODING] {
        headers.remove(&name);
        for value in original.get_all(&name) {
            headers.append(name.clone(), value.clone());
        }
    }
}

fn strip_connection_headers(headers: &mut HeaderMap) {
    for name in CONNECTION_HEADERS {
        headers.remove(name);
    }
    // `TE` may only say `trailers` in HTTP/2.
    if headers
        .get(http::header::TE)
        .is_some_and(|value| value.as_bytes() != b"trailers")
    {
        headers.remove(http::header::TE);
    }
}

/// Header pairs for the rewrite hook and capture; values that are not
/// UTF-8 are shown lossily.
fn header_list(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// The request a response answers, as the rules and request scripts left
/// it, for the `$request` of response scripts.
struct SentRequest {
    headers: Vec<MetadataEntry>,
    /// Only when the request body was held whole for a rule.
    body: Option<Vec<u8>>,
}

/// Header pairs of a request for the rewrite hook: the `cookie` fields an
/// HTTP/2 client splits (RFC 9113 section 8.2.3) are joined with "; " into
/// one field where the first one was, so rules and scripts read and write
/// one valid cookie list.
fn plan_header_list(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut list: Vec<(String, String)> = Vec::with_capacity(headers.len());
    let mut cookie_at: Option<usize> = None;
    for (name, value) in header_list(headers) {
        if name != http::header::COOKIE.as_str() {
            list.push((name, value));
            continue;
        }
        match cookie_at {
            Some(index) => {
                let joined = &mut list[index].1;
                joined.push_str("; ");
                joined.push_str(&value);
            }
            None => {
                cookie_at = Some(list.len());
                list.push((name, value));
            }
        }
    }
    list
}

/// Splits each `cookie` field back into one field per cookie pair, as an
/// HTTP/2 client sends them (RFC 9113 section 8.2.3), so header compression
/// keeps working for the pairs that do not change.
fn split_cookie_fields(headers: &mut HeaderMap) {
    let values = headers
        .get_all(http::header::COOKIE)
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    if values.is_empty() {
        return;
    }
    headers.remove(http::header::COOKIE);
    for value in values {
        let pairs = value
            .to_str()
            .ok()
            .map(|text| {
                text.split(';')
                    .map(str::trim)
                    .filter(|pair| !pair.is_empty())
                    .filter_map(|pair| HeaderValue::from_str(pair).ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if pairs.is_empty() {
            headers.append(http::header::COOKIE, value);
            continue;
        }
        for pair in pairs {
            headers.append(http::header::COOKIE, pair);
        }
    }
}

/// A header map from the hook's pairs; names HTTP/2 cannot carry
/// (upper case is lowered, invalid ones are dropped).
fn header_map(headers: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()),
            HeaderValue::from_str(value),
        ) else {
            continue;
        };
        map.append(name, value);
    }
    map
}

/// Whether `alpn` (the protocols a ClientHello offers) includes `h2`.
pub fn offers_h2(alpn: &[Vec<u8>]) -> bool {
    alpn.iter().any(|protocol| protocol == ALPN_H2)
}

/// One TLS link of a decrypted HTTP/2 connection, passing its bytes through
/// unchanged and, with capture on, keeping the header of every frame that
/// goes either way (see [`crate::capture::h2frames`]).
struct FrameTap<S> {
    inner: S,
    taps: Option<Taps>,
}

struct Taps {
    store: Arc<CaptureStore>,
    id: u64,
    read: FrameScanner,
    write: FrameScanner,
}

impl<S> FrameTap<S> {
    fn new(inner: S, link: Link, capture: Option<&(Arc<CaptureStore>, u64)>) -> Self {
        // The relay is the server on the app's link and the client on the
        // origin's: what it reads from the app and writes to the origin goes
        // up.
        let (read, write) = match link {
            Link::App => (Direction::Up, Direction::Down),
            Link::Origin => (Direction::Down, Direction::Up),
        };
        Self {
            inner,
            taps: capture.map(|(store, id)| Taps {
                store: store.clone(),
                id: *id,
                read: FrameScanner::new(link, read),
                write: FrameScanner::new(link, write),
            }),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FrameTap<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let (Poll::Ready(Ok(())), Some(taps)) = (&polled, &mut this.taps) {
            let frames = taps
                .read
                .feed(&buf.filled()[before..], crate::capture::unix_millis());
            taps.store.push_h2_frames(taps.id, frames);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FrameTap<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let (Poll::Ready(Ok(written)), Some(taps)) = (&polled, &mut this.taps) {
            let frames = taps
                .write
                .feed(&buf[..*written], crate::capture::unix_millis());
            taps.store.push_h2_frames(taps.id, frames);
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_maps_drop_connection_headers_and_lower_names() {
        let mut map = header_map(&[
            ("Host".to_string(), "a.test".to_string()),
            ("Connection".to_string(), "keep-alive".to_string()),
            ("X-Test".to_string(), "1".to_string()),
            ("TE".to_string(), "gzip".to_string()),
            ("bad name".to_string(), "x".to_string()),
        ]);
        strip_connection_headers(&mut map);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("x-test").unwrap(), "1");
    }

    #[test]
    fn split_cookie_fields_are_joined_for_rules_and_split_on_the_way_out() {
        let mut map = HeaderMap::new();
        map.append(http::header::COOKIE, HeaderValue::from_static("a=1"));
        map.append(http::header::ACCEPT, HeaderValue::from_static("x"));
        map.append(http::header::COOKIE, HeaderValue::from_static("b=2"));
        let list = plan_header_list(&map);
        assert_eq!(
            list,
            vec![
                ("cookie".to_string(), "a=1; b=2".to_string()),
                ("accept".to_string(), "x".to_string()),
            ]
        );
        // The capture still sees the fields as sent.
        assert_eq!(header_list(&map).len(), 3);

        // What a script hands back is one cookie list; it goes out split.
        let mut out = header_map(&[
            ("Cookie".to_string(), "a=1; b=3;  ;c=4".to_string()),
            ("accept".to_string(), "x".to_string()),
        ]);
        split_cookie_fields(&mut out);
        let cookies = out
            .get_all(http::header::COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(cookies, ["a=1", "b=3", "c=4"]);
        assert_eq!(out.get(http::header::ACCEPT).unwrap(), "x");
    }

    #[test]
    fn same_host_reads_authority_or_host() {
        let uri: Uri = "https://a.test/x".parse().unwrap();
        assert!(same_host(&uri, &HeaderMap::new(), "A.test"));
        assert!(!same_host(&uri, &HeaderMap::new(), "b.test"));
        let path: Uri = "/x".parse().unwrap();
        assert!(same_host(&path, &HeaderMap::new(), "a.test"));
    }

    #[tokio::test]
    async fn taps_keep_the_first_bytes() {
        let mut tap = Tap::new(true);
        tap.add(&vec![1; MAX_HTTP_BODY_BYTES]);
        tap.add(&[2; 10]);
        let body = tap.into_body().unwrap();
        assert_eq!(body.data.len(), MAX_HTTP_BODY_BYTES);
        assert_eq!(body.size, MAX_HTTP_BODY_BYTES as u64 + 10);
        assert!(Tap::new(false).into_body().is_none());
    }

    #[test]
    fn held_bodies_share_the_connections_budget_and_give_it_back() {
        let budget = BodyBudget::new(100);
        let left = || budget.left.load(Ordering::Acquire);
        let mut first = Held::new(&budget);
        assert!(first.grow(60));
        {
            let mut second = Held::new(&budget);
            assert!(second.grow(30));
            // A piece that does not fit takes nothing.
            assert!(!second.grow(11));
            assert_eq!(left(), 10);
            assert!(second.grow(10));
            assert!(!first.grow(1));
            assert_eq!((first.bytes, second.bytes, left()), (60, 40, 0));
        }
        // The second stream ended: exactly what it held is back.
        assert_eq!(left(), 40);
        assert!(!first.grow(41));
        assert!(first.grow(40));
        assert_eq!(left(), 0);
        drop(first);
        assert_eq!(left(), 100);
    }

    #[test]
    fn connections_share_the_engines_budget_and_give_it_back() {
        let engine = Arc::new(BodyBudget::new(100));
        let first = BodyBudget::within(80, engine.clone());
        let second = BodyBudget::within(80, engine.clone());
        let mut a = Held::new(&first);
        assert!(a.grow(70));
        let mut b = Held::new(&second);
        // The second connection has room of its own, the engine does not:
        // nothing is taken from either.
        assert!(!b.grow(40));
        assert_eq!((second.left(), engine.left()), (80, 30));
        assert!(b.grow(30));
        assert_eq!((first.left(), second.left(), engine.left()), (10, 50, 0));
        // A connection's own limit still holds while the engine has room.
        drop(b);
        assert!(!a.grow(11));
        assert_eq!((first.left(), engine.left()), (10, 30));
        drop(a);
        assert_eq!((first.left(), second.left(), engine.left()), (80, 80, 100));
    }

    #[test]
    fn streams_the_relay_fails_are_reset_as_internal_errors_unless_never_sent() {
        let never_sent = not_sent(h2::Error::from(Reason::REFUSED_STREAM));
        assert_eq!(reset_reason(&never_sent), (Reason::REFUSED_STREAM, true));
        // Made here, not by the origin: neither a remote reset nor GOAWAY.
        let local = io::Error::other(h2::Error::from(Reason::CANCEL));
        assert_eq!(reset_reason(&local), (Reason::INTERNAL_ERROR, false));
        let broken = io::Error::from(io::ErrorKind::BrokenPipe);
        assert_eq!(reset_reason(&broken), (Reason::INTERNAL_ERROR, false));
    }
}
