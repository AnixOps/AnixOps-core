use super::*;
use std::io::Cursor;

fn read(bytes: &[u8], method: &str) -> (Option<NativePlainHttpProxyResponse>, Vec<u8>, u64) {
    let mut cursor = Cursor::new(bytes.to_vec());
    let (report, interim) = read_plain_http_proxy_response_with_interim(&mut cursor, method);
    (report.response, interim, cursor.position())
}

#[test]
fn a_response_without_length_runs_to_the_close() {
    let (response, _, _) = read(
        b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nhello from an old server",
        "GET",
    );
    assert_eq!(response.unwrap().body, b"hello from an old server");

    // Past the body limit it fails instead of being cut short.
    let mut long = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
    long.extend(vec![b'x'; HTTP_PROXY_MAX_BODY_BYTES + 1]);
    assert!(read(&long, "GET").0.is_none());

    // A read that times out is no end of the body.
    struct TimesOut(Cursor<Vec<u8>>);
    impl Read for TimesOut {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            match self.0.read(buffer)? {
                0 => Err(std::io::Error::from(ErrorKind::TimedOut)),
                read => Ok(read),
            }
        }
    }
    let mut reader = TimesOut(Cursor::new(b"HTTP/1.1 200 OK\r\n\r\npartial".to_vec()));
    assert!(
        read_plain_http_proxy_response_for_request(&mut reader, "GET")
            .response
            .is_none()
    );
}

#[test]
fn head_204_and_304_answers_have_no_body() {
    let next = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    for (head, method) in [
        (
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"[..],
            "HEAD",
        ),
        (
            &b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1000\r\n\r\n"[..],
            "GET",
        ),
        (&b"HTTP/1.1 204 No Content\r\n\r\n"[..], "GET"),
    ] {
        let mut bytes = head.to_vec();
        bytes.extend_from_slice(next);
        let (response, _, position) = read(&bytes, method);
        assert!(response.unwrap().body.is_empty());
        // Nothing past the head was read: the next message is intact.
        assert_eq!(position, head.len() as u64);
    }
}

#[test]
fn interim_answers_are_kept_for_the_client_and_the_final_one_is_returned() {
    let (response, interim, _) = read(
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\ndone",
        "POST",
    );
    let response = response.unwrap();
    assert_eq!(response.status_code, 201);
    assert_eq!(response.body, b"done");
    assert_eq!(
        interim,
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n"
    );
    // A protocol switch cannot be relayed.
    assert!(read(b"HTTP/1.1 101 Switching Protocols\r\n\r\n", "GET")
        .0
        .is_none());
}

fn report_for(status: u16, headers: &[(&str, &str)], body: &[u8]) -> NativePlainHttpRewriteReport {
    passthrough_plain_http_rewrite_report(&NativePlainHttpMessage {
        request_id: "framing".to_string(),
        url: "http://example.test/".to_string(),
        method: Some("GET".to_string()),
        phase: HttpMitmPhase::Response,
        status_code: Some(status),
        headers: headers
            .iter()
            .map(|(key, value)| MetadataEntry {
                key: key.to_string(),
                value: value.to_string(),
            })
            .collect(),
        body: body.to_vec(),
        request_headers: Vec::new(),
        request_body: None,
    })
}

#[test]
fn bodiless_answers_keep_their_announced_length_and_send_no_body() {
    let head = |status, headers: &[(&str, &str)], method| {
        String::from_utf8(serialize_plain_http_proxy_response_with_connection(
            "HTTP/1.1",
            &report_for(status, headers, b""),
            false,
            method,
        ))
        .unwrap()
    };
    let text = head(200, &[("Content-Length", "1000")], "HEAD");
    assert!(text.contains("Content-Length: 1000\r\n"), "{text}");
    assert!(text.ends_with("\r\n\r\n"), "{text}");
    let text = head(304, &[("Content-Length", "1000")], "GET");
    assert!(text.contains("Content-Length: 1000\r\n"), "{text}");
    let text = head(204, &[("Content-Length", "0")], "GET");
    assert!(!text.contains("Content-Length"), "{text}");
    // A body for a HEAD request is never written.
    let text = String::from_utf8(serialize_plain_http_proxy_response_with_connection(
        "HTTP/1.1",
        &report_for(200, &[("Content-Length", "4")], b"body"),
        false,
        "HEAD",
    ))
    .unwrap();
    assert!(text.ends_with("Content-Length: 4\r\n\r\n"), "{text}");
}

/// Reads from `input` and keeps what is written.
struct Pipe {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Pipe {
    fn new(input: &[u8]) -> Self {
        Self {
            input: Cursor::new(input.to_vec()),
            output: Vec::new(),
        }
    }
}

impl Read for Pipe {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buffer)
    }
}

impl Write for Pipe {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn connect_request() -> NativeExplicitHttpProxyRequest {
    read_explicit_http_proxy_request(&mut Cursor::new(
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec(),
    ))
    .request
    .expect("test CONNECT request should parse")
}

#[test]
fn a_head_exchange_keeps_the_next_exchange_on_the_same_connection_in_step() {
    let mut downstream = Pipe::new(
        b"HEAD /a HTTP/1.1\r\nHost: example.com\r\n\r\nGET /b HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    );
    let mut upstream = Pipe::new(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    );
    let mut diagnostics = Vec::new();
    let written = run_controlled_tls_http1_exchanges(
        &mut downstream,
        &mut upstream,
        &connect_request(),
        None,
        Duration::from_secs(1),
        &mut diagnostics,
    )
    .expect("both exchanges complete");
    assert!(written);
    let client = String::from_utf8(downstream.output).unwrap();
    let responses = client
        .split("HTTP/1.1 200 OK\r\n")
        .skip(1)
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 2, "{client}");
    assert!(responses[0].contains("Content-Length: 5\r\n"), "{client}");
    assert!(responses[0].ends_with("\r\n\r\n"), "{client}");
    assert!(responses[1].ends_with("\r\n\r\nok"), "{client}");
    let origin = String::from_utf8(upstream.output).unwrap();
    assert!(origin.starts_with("HEAD /a HTTP/1.1\r\n"), "{origin}");
    assert!(origin.contains("GET /b HTTP/1.1\r\n"), "{origin}");
}

#[test]
fn a_close_delimited_answer_ends_the_session() {
    let mut downstream = Pipe::new(
        b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\nGET /b HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    let mut upstream = Pipe::new(b"HTTP/1.1 200 OK\r\n\r\nall of it");
    let mut diagnostics = Vec::new();
    run_controlled_tls_http1_exchanges(
        &mut downstream,
        &mut upstream,
        &connect_request(),
        None,
        Duration::from_secs(1),
        &mut diagnostics,
    )
    .expect("the first exchange completes");
    let client = String::from_utf8(downstream.output).unwrap();
    assert!(client.contains("Connection: close\r\n"), "{client}");
    assert!(client.contains("Content-Length: 9\r\n"), "{client}");
    assert!(client.ends_with("\r\n\r\nall of it"), "{client}");
    let origin = String::from_utf8(upstream.output).unwrap();
    assert!(!origin.contains("GET /b"), "{origin}");
}

#[test]
fn expect_is_not_sent_upstream() {
    let request = read_explicit_http_proxy_request(&mut Cursor::new(
        b"POST http://example.com/up HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nhi"
            .to_vec(),
    ))
    .request
    .expect("test request should parse");
    let message = explicit_http_proxy_request_to_plain_http_message(&request);
    let bytes = serialize_explicit_http_proxy_request_for_upstream(
        &request,
        &passthrough_plain_http_rewrite_report(&message),
    );
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.to_ascii_lowercase().contains("expect:"), "{text}");
    assert!(text.ends_with("\r\n\r\nhi"), "{text}");
}
