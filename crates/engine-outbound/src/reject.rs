//! How an inbound answers a connection a routing rule rejected.
//!
//! Routing (in `engine-embedded`) fails a rejected connect with an
//! [`io::Error`] made by [`rejected`]; an inbound reads the answer it owes
//! the client back with [`rejection`]:
//!
//! - [`RejectAction::Close`] (`REJECT`, `REJECT-NO-DROP`): close at once, or
//!   answer a proxy request with an error.
//! - [`RejectAction::Drop`] (`REJECT-DROP`, and a `REJECT` storm): answer
//!   nothing and keep the connection open with [`hold`], so the client waits
//!   for its own timeout instead of retrying at once.
//! - [`RejectAction::TinyGif`] (`REJECT-TINYGIF`): answer a plain HTTP request
//!   with [`tiny_gif_response`]; any other flow closes as with `Close`.

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// What the client of a rejected connection gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectAction {
    Close,
    Drop,
    TinyGif,
}

/// The message every rejection carries; no rule text or host goes in it.
pub const REJECTED_MESSAGE: &str = "connection rejected by routing rule";

/// How long [`hold`] keeps a dropped connection open at most. Apps time a
/// silent connect or request out well before this; one that does not gets
/// its retries spaced this far apart.
pub const DROP_HOLD: Duration = Duration::from_secs(60);

/// Dropped connections held open at once, process-wide. Past this a
/// dropped connection closes at once instead, so a storm cannot pile up
/// sockets and tasks.
pub const MAX_HELD: usize = 256;

static HELD: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
struct Rejected(RejectAction);

impl fmt::Display for Rejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REJECTED_MESSAGE)
    }
}

impl std::error::Error for Rejected {}

/// The error of a connect a routing rule rejected:
/// [`io::ErrorKind::PermissionDenied`] with [`REJECTED_MESSAGE`], carrying
/// `action` for [`rejection`].
pub fn rejected(action: RejectAction) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, Rejected(action))
}

/// The answer `error` asks for, when it is a rejection made by [`rejected`].
pub fn rejection(error: &io::Error) -> Option<RejectAction> {
    error
        .get_ref()?
        .downcast_ref::<Rejected>()
        .map(|rejected| rejected.0)
}

/// A transparent 1x1 GIF, 43 bytes.
pub const TINY_GIF: [u8; 43] = [
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

/// An HTTP/1.1 `200 OK` carrying [`TINY_GIF`] that closes the connection.
pub fn tiny_gif_response() -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: image/gif\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        TINY_GIF.len()
    )
    .into_bytes();
    response.extend_from_slice(&TINY_GIF);
    response
}

/// Keeps a dropped connection open without answering: what the client
/// sends is read and discarded until it closes, reading fails, or `hold`
/// passes. Returns `false` at once, holding nothing, when [`MAX_HELD`]
/// connections are already held; the caller then just closes.
pub async fn hold<S: AsyncRead + Unpin>(stream: &mut S, hold: Duration) -> bool {
    struct Slot;
    impl Drop for Slot {
        fn drop(&mut self) {
            HELD.fetch_sub(1, Ordering::AcqRel);
        }
    }

    if HELD.fetch_add(1, Ordering::AcqRel) >= MAX_HELD {
        HELD.fetch_sub(1, Ordering::AcqRel);
        return false;
    }
    let _slot = Slot;
    let deadline = tokio::time::Instant::now() + hold;
    let mut sink = [0u8; 2048];
    while let Ok(Ok(read)) = tokio::time::timeout_at(deadline, stream.read(&mut sink)).await {
        if read == 0 {
            break;
        }
    }
    true
}

/// Connections [`hold`] keeps open right now.
pub fn held() -> usize {
    HELD.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn a_rejection_carries_its_action_and_a_fixed_message() {
        for action in [
            RejectAction::Close,
            RejectAction::Drop,
            RejectAction::TinyGif,
        ] {
            let error = rejected(action);
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(error.to_string(), REJECTED_MESSAGE);
            assert_eq!(rejection(&error), Some(action));
        }
        let other = io::Error::new(io::ErrorKind::PermissionDenied, REJECTED_MESSAGE);
        assert_eq!(rejection(&other), None);
        assert_eq!(rejection(&io::Error::from(io::ErrorKind::TimedOut)), None);
    }

    #[test]
    fn the_tiny_gif_response_is_a_complete_http_message() {
        let response = tiny_gif_response();
        let split = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("head ends")
            + 4;
        let head = std::str::from_utf8(&response[..split]).unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.contains("Content-Type: image/gif\r\n"));
        assert!(head.contains("Content-Length: 43\r\n"));
        assert!(head.contains("Connection: close\r\n"));
        assert_eq!(&response[split..], &TINY_GIF[..]);
        assert!(TINY_GIF.starts_with(b"GIF89a"));
        assert_eq!(TINY_GIF.last(), Some(&0x3b));
    }

    #[tokio::test(start_paused = true)]
    async fn hold_reads_until_the_client_closes() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let held = tokio::spawn(async move { hold(&mut server, DROP_HOLD).await });
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        tokio::task::yield_now().await;
        assert!(!held.is_finished());
        drop(client);
        assert!(held.await.unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn hold_gives_up_after_its_time() {
        let (_client, mut server) = tokio::io::duplex(64);
        let started = tokio::time::Instant::now();
        assert!(hold(&mut server, Duration::from_secs(5)).await);
        let waited = started.elapsed();
        assert!(waited >= Duration::from_secs(5), "{waited:?}");
        assert!(waited < Duration::from_secs(6), "{waited:?}");
    }
}
