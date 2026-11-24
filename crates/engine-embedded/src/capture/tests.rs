use super::*;

fn store(budget: usize) -> CaptureStore {
    let store = CaptureStore::default();
    store.set(true, Some(budget));
    store
}

#[test]
fn off_by_default_and_keeps_nothing() {
    let store = CaptureStore::default();
    assert!(!store.begin(1, Network::Tcp, None, "192.0.2.1:80", 1));
    store.record(1, Direction::Up, b"GET /");
    assert_eq!(store.status().connections, 0);
    assert!(store.connection_json(1).is_none());
}

#[test]
fn keeps_the_first_bytes_of_each_direction_and_merges_tcp() {
    let store = store(MAX_TOTAL_BYTES_LIMIT);
    assert!(store.begin(7, Network::Tcp, Some("example.test"), "192.0.2.1:80", 1));
    store.record(7, Direction::Up, b"GET / HTTP/1.1\r\n");
    store.record(7, Direction::Up, b"\r\n");
    store.record(7, Direction::Down, &vec![b'x'; MAX_DIRECTION_BYTES + 10]);
    store.end(7, 2);
    let value = store.connection_json(7).unwrap();
    let chunks = value["chunks"].as_array().unwrap();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0]["dir"], "up");
    assert_eq!(
        chunks[0]["data_base64"],
        base64_encode(b"GET / HTTP/1.1\r\n\r\n")
    );
    assert_eq!(value["download"]["captured"], MAX_DIRECTION_BYTES);
    assert_eq!(value["download"]["truncated"], true);
    assert_eq!(value["upload"]["truncated"], false);
    assert_eq!(value["ended_at_ms"], 2);
}

#[test]
fn udp_datagrams_stay_apart() {
    let store = store(MAX_TOTAL_BYTES_LIMIT);
    store.begin(3, Network::Udp, None, "192.0.2.1:53", 1);
    store.record(3, Direction::Up, b"q1");
    store.record(3, Direction::Up, b"q2");
    let value = store.connection_json(3).unwrap();
    assert_eq!(value["chunks"].as_array().unwrap().len(), 2);
}

#[test]
fn the_budget_drops_the_oldest_connections() {
    let store = store(MIN_TOTAL_BYTES);
    for id in 1..=4 {
        store.begin(id, Network::Tcp, None, "192.0.2.1:80", 1);
        store.record(id, Direction::Down, &vec![0u8; 30 * 1024]);
    }
    let status = store.status();
    assert!(status.used_bytes <= MIN_TOTAL_BYTES, "{status:?}");
    assert!(store.connection_json(1).is_none());
    assert!(store.connection_json(4).is_some());
    store.clear();
    assert_eq!(store.status().used_bytes, 0);
}

#[test]
fn decrypted_connections_keep_http_only_and_export() {
    let store = Arc::new(store(MAX_TOTAL_BYTES_LIMIT));
    store.begin(
        9,
        Network::Tcp,
        Some("api.example.test"),
        "api.example.test:443",
        1_000,
    );
    store.record(9, Direction::Up, b"\x16\x03\x01tls");
    store.mark_decrypted(9);
    store.record(9, Direction::Up, b"\x17\x03\x03more");
    let mut exchange = HttpExchange::new(
        "GET",
        "https://api.example.test/a?x=1&y",
        &[("Host".to_string(), "api.example.test".to_string())],
    );
    exchange.status = Some(200);
    exchange.response_headers = vec![("Content-Type".to_string(), "text/plain".to_string())];
    exchange.response_body = CapturedBody::of(b"hello");
    store.add_exchange(9, exchange);

    let value = store.connection_json(9).unwrap();
    assert_eq!(value["decrypted"], true);
    assert!(value["chunks"].as_array().unwrap().is_empty());
    assert_eq!(value["http"][0]["status"], 200);
    assert_eq!(
        value["http"][0]["response"]["body"]["data_base64"],
        base64_encode(b"hello")
    );

    let har: Value = serde_json::from_slice(&store.export_har(None, true)).unwrap();
    let entry = &har["log"]["entries"][0];
    assert_eq!(har["log"]["version"], "1.2");
    assert_eq!(entry["request"]["method"], "GET");
    assert_eq!(entry["request"]["queryString"][0]["name"], "x");
    assert_eq!(entry["response"]["content"]["text"], "hello");

    let pcap = store.export_pcapng(Some(9), true);
    assert_eq!(&pcap[..4], &[0x0A, 0x0D, 0x0D, 0x0A]);
    assert!(pcap.windows(5).any(|window| window == b"hello"));
    assert!(pcap.windows(16).any(|window| window == b"api.example.test"));
    assert!(pcap.len().is_multiple_of(4));

    let answer: Value = serde_json::from_slice(&export_answer(&store, &{
        let mut request = ExportRequest::new(ExportFormat::Pcapng);
        request.selection.id = Some(9);
        request
    }))
    .unwrap();
    assert_eq!(answer["file_name"], "anixops-capture-9.pcapng");
    assert_eq!(answer["size"], pcap.len());
    let data = base64::engine::general_purpose::STANDARD
        .decode(answer["data_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(data.len(), pcap.len());
}

#[test]
fn har_carries_encoded_bodies_decoded() {
    use std::io::Write;

    let store = Arc::new(store(MAX_TOTAL_BYTES_LIMIT));
    store.begin(
        4,
        Network::Tcp,
        Some("cdn.example.test"),
        "192.0.2.4:443",
        1,
    );
    store.mark_decrypted(4);
    let text = "hello ".repeat(500);
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(text.as_bytes()).unwrap();
    let wire = gzip.finish().unwrap();
    let header = |name: &str, value: &str| (name.to_string(), value.to_string());
    let mut exchange = HttpExchange::new("GET", "https://cdn.example.test/a", &[]);
    exchange.status = Some(200);
    exchange.response_headers = vec![
        header("Content-Type", "text/plain"),
        header("Content-Encoding", "gzip"),
    ];
    exchange.response_body = CapturedBody::of(&wire);
    store.add_exchange(4, exchange.clone());
    // An encoding nobody decodes stays as captured, with a comment.
    exchange.response_headers[1].1 = "compress".to_string();
    exchange.response_body = CapturedBody::of(b"\x1f\x9d\x90");
    store.add_exchange(4, exchange);

    // Redacted, a body that cannot be decoded to be checked is left out.
    let redacted: Value = serde_json::from_slice(&store.export_har(Some(4), true)).unwrap();
    let omitted = &redacted["log"]["entries"][1]["response"];
    assert!(omitted["content"].get("text").is_none(), "{omitted}");
    assert_eq!(omitted["content"]["size"], 3);
    assert!(omitted["headers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|header| header["name"] == redact::REDACTED_BODY_HEADER));
    assert_eq!(
        redacted["log"]["entries"][0]["response"]["content"]["text"],
        text.as_str()
    );

    let har: Value = serde_json::from_slice(&store.export_har(Some(4), false)).unwrap();
    let decoded = &har["log"]["entries"][0]["response"];
    assert_eq!(decoded["content"]["text"], text.as_str());
    assert_eq!(decoded["content"]["size"], text.len());
    assert_eq!(decoded["content"]["compression"], text.len() - wire.len());
    assert_eq!(decoded["bodySize"], wire.len());
    // The headers stay as sent.
    assert_eq!(decoded["headers"][1]["value"], "gzip");

    let left = &har["log"]["entries"][1];
    assert_eq!(left["response"]["content"]["encoding"], "base64");
    assert!(left["comment"]
        .as_str()
        .unwrap()
        .contains("compress body left encoded"));
}

#[test]
fn exports_udp_over_ipv6() {
    let store = store(MAX_TOTAL_BYTES_LIMIT);
    store.begin(2, Network::Udp, None, "[2001:db8::1]:53", 1);
    store.record(2, Direction::Up, b"query");
    store.record(2, Direction::Down, b"answer");
    let pcap = store.export_pcapng(None, true);
    assert!(pcap.windows(6).any(|window| window == b"answer"));
    // The synthetic client fd00::1 talks to the real IPv6 server.
    let client = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert!(pcap.windows(16).any(|window| window == client));
}

#[test]
fn a_long_tcp_run_is_kept_in_pieces_and_shown_whole() {
    let store = store(MAX_TOTAL_BYTES_LIMIT);
    store.begin(3, Network::Tcp, None, "192.0.2.1:80", 1);
    let block = vec![7u8; 1460];
    for _ in 0..40 {
        store.record(3, Direction::Down, &block);
    }
    {
        let inner = lock(&store.inner);
        let captured = &inner.connections[&3];
        assert!(captured.chunks.len() > 1);
        assert!(captured
            .chunks
            .iter()
            .all(|chunk| chunk.data.capacity() <= CHUNK_PIECE_BYTES));
    }
    let value = store.connection_json(3).unwrap();
    let chunks = value["chunks"].as_array().unwrap();
    assert_eq!(chunks.len(), 1);
    let data = base64::engine::general_purpose::STANDARD
        .decode(chunks[0]["data_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(data.len(), 40 * 1460);
}

#[test]
fn kept_pieces_grow_no_further_than_their_limit() {
    let mut buf = Vec::new();
    for _ in 0..44 {
        reserve_capped(&mut buf, 1460, MAX_DIRECTION_BYTES);
        buf.extend_from_slice(&[0u8; 1460]);
    }
    assert_eq!(buf.len(), 44 * 1460);
    assert_eq!(buf.capacity(), MAX_DIRECTION_BYTES);
}

fn filed(store: &CaptureStore, id: u64, method: &str, url: &str, status: u16) {
    let mut exchange = HttpExchange::new(
        method,
        url,
        &[(
            "Authorization".to_string(),
            "Bearer secret-value".to_string(),
        )],
    );
    exchange.status = Some(status);
    store.add_exchange(id, exchange);
}

#[test]
fn requests_list_rows_in_order_and_filter() {
    let store = store(MAX_TOTAL_BYTES_LIMIT);
    store.begin(1, Network::Tcp, Some("a.test"), "a.test:443", 1);
    store.begin(2, Network::Tcp, Some("b.test"), "b.test:443", 2);
    store.mark_decrypted(1);
    store.mark_decrypted(2);
    filed(&store, 2, "GET", "https://b.test/one", 200);
    filed(&store, 1, "POST", "https://a.test/two", 500);
    filed(&store, 2, "GET", "https://b.test/three", 404);

    let all = store.requests_json(0, None, None, &Filter::default());
    let rows = all["requests"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["seq"], 1);
    assert_eq!(rows[0]["connection_id"], 2);
    assert_eq!(rows[0]["index"], 0);
    assert_eq!(rows[1]["connection_id"], 1);
    assert_eq!(rows[2]["index"], 1);
    assert_eq!(rows[2]["host"], "b.test");
    assert_eq!(rows[2]["http_version"], HTTP_1_1);
    assert_eq!(all["last_seq"], 3);
    assert_eq!(all["dropped_before_seq"], 0);

    let since = store.requests_json(1, None, Some(1), &Filter::default());
    assert_eq!(since["requests"].as_array().unwrap().len(), 1);
    assert_eq!(since["requests"][0]["seq"], 2);

    let errors = store.requests_json(
        0,
        None,
        None,
        &Filter::parse("status:>=400 -host:a.test").unwrap(),
    );
    assert_eq!(errors["requests"].as_array().unwrap().len(), 1);
    assert_eq!(errors["requests"][0]["url"], "https://b.test/three");

    store.clear();
    let cleared = store.requests_json(0, None, None, &Filter::default());
    assert!(cleared["requests"].as_array().unwrap().is_empty());
    assert_eq!(cleared["dropped_before_seq"], 3);
}

#[test]
fn exchanges_in_progress_are_listed_by_rev_and_keep_their_messages() {
    use stream::{MessageKind, StreamMessage};
    let store = store(MAX_TOTAL_BYTES_LIMIT);
    store.begin(7, Network::Tcp, Some("a.test"), "a.test:443", 1);
    store.mark_decrypted(7);
    let used = store.status().used_bytes;
    let mut exchange = HttpExchange::new("GET", "https://a.test/events", &[]);
    let index = store.open_exchange(7, exchange.clone()).unwrap();

    // Not finished: only `since_rev` lists it.
    let by_seq = store.requests_json(0, None, None, &Filter::default());
    assert!(by_seq["requests"].as_array().unwrap().is_empty());
    let by_rev = store.requests_json(0, Some(0), None, &Filter::default());
    assert_eq!(by_rev["requests"][0]["state"], "in_progress");
    assert_eq!(by_rev["requests"][0]["seq"], 0);
    let last_rev = by_rev["last_rev"].as_u64().unwrap();

    exchange.status = Some(200);
    exchange.note = Some("streaming");
    exchange.rules_skipped = true;
    store.update_exchange(7, index, &exchange);
    for i in 0..3u8 {
        store.push_message(
            7,
            index,
            StreamMessage {
                index: 0,
                at_ms: 5,
                direction: Direction::Down,
                kind: MessageKind::Sse,
                label: Some("tick".into()),
                id: None,
                code: None,
                data: vec![b'0' + i],
                size: 1,
            },
        );
    }
    let changed = store.requests_json(0, Some(last_rev), None, &Filter::default());
    let rows = changed["requests"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["status"], 200);
    assert_eq!(rows[0]["message_count"], 3);
    assert_eq!(rows[0]["rules_skipped"], true);
    let last_rev = changed["last_rev"].as_u64().unwrap();
    let unchanged = store.requests_json(0, Some(last_rev), None, &Filter::default());
    assert!(unchanged["requests"].as_array().unwrap().is_empty());

    let detail = store.exchange_json(7, index, 1);
    assert_eq!(detail["messages"]["seen"], 3);
    let kept = detail["messages"]["kept"].as_array().unwrap();
    assert_eq!(kept.len(), 2);
    assert_eq!(kept[0]["index"], 1);
    assert_eq!(kept[0]["label"], "tick");
    assert_eq!(kept[1]["text"], "2");

    // Finishing keeps the messages and files it by `seq`.
    store.finish_exchange(7, index, Some(exchange.clone()));
    let done = store.requests_json(0, None, None, &Filter::default());
    assert_eq!(done["requests"][0]["state"], "done");
    assert_eq!(done["requests"][0]["seq"], 1);
    assert_eq!(store.exchange_json(7, index, 0)["messages"]["seen"], 3);
    assert_eq!(store.exchange_json(7, 9, 0), Value::Null);

    // The memory the exchange holds is what the budget counts.
    let expected = {
        let inner = lock(&store.inner);
        inner.connections[&7].http[index].memory()
    };
    assert_eq!(store.status().used_bytes, used + expected);
    // One lock at a time: a second `lock` in the same statement would
    // wait for the first guard forever.
    let inner = lock(&store.inner);
    let captured = &inner.connections[&7];
    assert_eq!(captured.memory, captured.memory_estimate());
}

#[test]
fn a_stream_of_many_messages_stays_within_its_budget() {
    use stream::{MessageKind, StreamMessage, MAX_MESSAGES, MAX_MESSAGE_BYTES_TOTAL};
    let store = store(MAX_TOTAL_BYTES_LIMIT);
    store.begin(8, Network::Tcp, Some("a.test"), "a.test:443", 1);
    store.mark_decrypted(8);
    let index = store
        .open_exchange(8, HttpExchange::new("GET", "https://a.test/s", &[]))
        .unwrap();
    for i in 0..20_000u64 {
        store.push_message(
            8,
            index,
            StreamMessage {
                index: 0,
                at_ms: i,
                direction: Direction::Down,
                kind: MessageKind::Sse,
                label: None,
                id: None,
                code: None,
                data: vec![b'x'; 700],
                size: 700,
            },
        );
    }
    let inner = lock(&store.inner);
    let exchange = &inner.connections[&8].http[index];
    assert_eq!(exchange.messages.seen, 20_000);
    assert!(exchange.messages.kept.len() <= MAX_MESSAGES);
    assert!(exchange.messages.memory() <= MAX_MESSAGE_BYTES_TOTAL + MAX_MESSAGES * 64);
    assert_eq!(inner.used, inner.connections[&8].memory);
    assert_eq!(
        inner.connections[&8].memory,
        inner.connections[&8].memory_estimate()
    );
}

#[test]
fn exports_are_redacted_unless_asked_not_to() {
    let store = store(MAX_TOTAL_BYTES_LIMIT);
    store.begin(4, Network::Tcp, Some("a.test"), "a.test:443", 1);
    store.mark_decrypted(4);
    filed(&store, 4, "GET", "https://a.test/x?token=tok-value-1", 200);
    filed(&store, 4, "GET", "https://a.test/y", 200);

    let contains = |file: &[u8], needle: &[u8]| file.windows(needle.len()).any(|w| w == needle);
    for format in [
        ExportFormat::Pcapng,
        ExportFormat::Har,
        ExportFormat::Curl,
        ExportFormat::Code,
        ExportFormat::Postman,
        ExportFormat::Insomnia,
    ] {
        let request = ExportRequest::new(format);
        let file = export_file(&store, &request);
        assert!(!contains(&file, b"secret-value"), "{format:?}");
        assert!(!contains(&file, b"tok-value-1"), "{format:?}");
        assert!(contains(&file, redact::MASK.as_bytes()), "{format:?}");
        let raw = ExportRequest {
            redact: false,
            ..request
        };
        assert!(
            contains(&export_file(&store, &raw), b"secret-value"),
            "{format:?}"
        );
    }

    let one = ExportRequest {
        selection: Selection {
            id: Some(4),
            exchange: Some(1),
        },
        ..ExportRequest::new(ExportFormat::Curl)
    };
    let script = String::from_utf8(export_file(&store, &one)).unwrap();
    assert!(script.contains("https://a.test/y"));
    assert!(!script.contains("https://a.test/x"));
    let answer: Value = serde_json::from_slice(&export_answer(&store, &one)).unwrap();
    assert_eq!(answer["file_name"], "anixops-capture-4-1.sh");
    assert_eq!(answer["redacted"], true);
}

#[test]
fn zip_export_packs_listing_har_and_pcapng_redacted_unless_asked_not_to() {
    use base64::Engine as _;

    let store = store(MAX_TOTAL_BYTES_LIMIT);
    store.begin(4, Network::Tcp, Some("a.test"), "a.test:443", 1);
    store.mark_decrypted(4);
    filed(&store, 4, "GET", "https://a.test/x?token=tok-value-1", 200);
    store.begin(5, Network::Udp, None, "192.0.2.9:53", 2);
    store.record(5, Direction::Up, b"query");

    let answer: Value = serde_json::from_slice(&export_answer(
        &store,
        &ExportRequest::new(ExportFormat::Zip),
    ))
    .unwrap();
    assert!(answer["file_name"].as_str().unwrap().ends_with(".zip"));
    assert_eq!(answer["content_type"], "application/zip");
    let zip = base64::engine::general_purpose::STANDARD
        .decode(answer["data_base64"].as_str().unwrap())
        .unwrap();
    let files = archive::unzip(&zip);
    let names: Vec<_> = files.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        [
            "README.txt",
            "connections.json",
            "capture.har",
            "capture.pcapng"
        ]
    );
    let contains = |file: &[u8], needle: &[u8]| file.windows(needle.len()).any(|w| w == needle);
    for (name, data) in &files {
        assert!(!contains(data, b"secret-value"), "{name}");
        assert!(!contains(data, b"tok-value-1"), "{name}");
    }
    let listing: Value = serde_json::from_slice(&files[1].1).unwrap();
    assert_eq!(listing["redacted"], true);
    let connections = listing["connections"].as_array().unwrap();
    assert_eq!(connections.len(), 2);
    assert_eq!(connections[0]["id"], 4);
    assert_eq!(connections[0]["requests"][0]["method"], "GET");
    assert_eq!(connections[0]["requests"][0]["status"], 200);
    assert_eq!(connections[1]["network"], "udp");
    assert_eq!(connections[1]["upload"]["captured"], 5);
    assert_eq!(files[3].1, store.export_pcapng(None, true));

    let raw = ExportRequest {
        redact: false,
        ..ExportRequest::new(ExportFormat::Zip)
    };
    let files = archive::unzip(&export_file(&store, &raw));
    assert!(contains(&files[2].1, b"secret-value"));
    assert!(String::from_utf8_lossy(&files[0].1).contains("NOT masked"));

    // One connection: only its own files.
    let one = ExportRequest {
        selection: Selection {
            id: Some(5),
            exchange: None,
        },
        ..ExportRequest::new(ExportFormat::Zip)
    };
    let files = archive::unzip(&export_file(&store, &one));
    let names: Vec<_> = files.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["README.txt", "connections.json", "capture.pcapng"]);
}

fn decrypted(store: &CaptureStore, id: u64) {
    store.begin(id, Network::Tcp, Some("a.test"), "a.test:443", 1);
    store.mark_decrypted(id);
}

/// What the budget counts is what the connections hold.
fn assert_accounted(store: &CaptureStore) {
    let inner = lock(&store.inner);
    let sum: usize = inner
        .connections
        .values()
        .map(|captured| captured.memory)
        .sum();
    assert_eq!(inner.used, sum);
    for captured in inner.connections.values() {
        assert_eq!(captured.memory, captured.memory_estimate());
    }
}

#[test]
fn one_busy_connection_gives_up_its_own_oldest_bodies_only() {
    let store = store(DEFAULT_MAX_TOTAL_BYTES);
    decrypted(&store, 1);
    filed(&store, 1, "GET", "https://a.test/other", 200);
    decrypted(&store, 2);
    // One HTTP/2 connection loading images of 64 KiB each.
    let mut last = None;
    for i in 0..40 {
        let mut exchange = HttpExchange::new("GET", &format!("https://a.test/image/{i}"), &[]);
        exchange.status = Some(200);
        exchange.response_body = CapturedBody::of(&vec![b'x'; MAX_HTTP_BODY_BYTES]);
        let index = store.open_exchange(2, exchange);
        assert_eq!(index, Some(i), "every exchange is still filed");
        store.finish_exchange(2, i, None);
        last = index;
    }
    assert_eq!(last, Some(39));
    let status = store.status();
    assert!(status.used_bytes <= DEFAULT_MAX_TOTAL_BYTES, "{status:?}");
    assert!(status.dropped_bodies > 0, "{status:?}");
    assert_eq!(status.dropped_exchanges, 0, "{status:?}");
    assert!(
        store.connection_json(1).is_some(),
        "the other connection is not emptied for it"
    );
    let value = store.connection_json(2).unwrap();
    let http = value["http"].as_array().unwrap();
    assert_eq!(http.len(), 40);
    assert_eq!(http[39]["index"], 39);
    assert_eq!(http[39]["response"]["body"]["truncated"], false);
    // The oldest rows stay, their bodies marked truncated.
    assert_eq!(http[0]["url"], "https://a.test/image/0");
    assert_eq!(http[0]["response"]["body"]["truncated"], true);
    assert_eq!(http[0]["response"]["body"]["size"], MAX_HTTP_BODY_BYTES);
    {
        let inner = lock(&store.inner);
        assert!(inner.connections[&2].memory <= DEFAULT_MAX_TOTAL_BYTES / 2);
    }
    let rows = store.requests_json(0, None, None, &Filter::default());
    assert_eq!(rows["requests"].as_array().unwrap().len(), 41);
    assert_eq!(rows["dropped_before_seq"], 0);
    assert_accounted(&store);
}

#[test]
fn raw_bytes_past_a_connections_share_are_counted_not_kept() {
    let store = store(MIN_TOTAL_BYTES);
    store.begin(1, Network::Tcp, None, "192.0.2.1:80", 1);
    store.record(1, Direction::Up, b"GET / HTTP/1.1\r\n\r\n");
    store.begin(2, Network::Tcp, None, "192.0.2.1:80", 1);
    for _ in 0..40 {
        store.record(2, Direction::Down, &[7u8; 1460]);
    }
    // A gap would make the kept bytes lie: nothing past it is kept.
    store.record(2, Direction::Down, b"x");
    let value = store.connection_json(2).unwrap();
    assert_eq!(value["download"]["seen"], 40 * 1460 + 1);
    assert_eq!(value["download"]["truncated"], true);
    assert!(value["download"]["captured"].as_u64().unwrap() < 40 * 1460);
    assert!(store.connection_json(1).is_some(), "not dropped for it");
    assert_accounted(&store);
}

#[test]
fn clearing_keeps_open_connections_recording_under_new_indexes() {
    let store = store(MAX_TOTAL_BYTES_LIMIT);
    decrypted(&store, 3);
    let old = store
        .open_exchange(3, HttpExchange::new("GET", "https://a.test/old", &[]))
        .unwrap();
    assert_eq!(old, 0);
    store.clear();
    let status = store.status();
    assert_eq!((status.connections, status.used_bytes), (0, 0));

    let new = store
        .open_exchange(3, HttpExchange::new("GET", "https://a.test/new", &[]))
        .expect("the open connection records again");
    assert_eq!(new, 1, "an index is never given twice");
    // The request in flight across the clear ends without touching the
    // new one.
    let mut late = HttpExchange::new("GET", "https://a.test/old", &[]);
    late.status = Some(200);
    store.finish_exchange(3, old, Some(late));
    store.finish_exchange(3, new, None);
    let rows = store.requests_json(0, None, None, &Filter::default());
    let rows = rows["requests"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["url"], "https://a.test/new");
    assert_eq!(rows[0]["index"], 1);
    assert_eq!(store.exchange_json(3, 0, 0), Value::Null);
    assert_eq!(store.exchange_json(3, 1, 0)["url"], "https://a.test/new");
    assert_accounted(&store);

    // Closed and cleared, it is gone for good.
    store.end(3, 9);
    store.clear();
    assert!(store
        .open_exchange(3, HttpExchange::new("GET", "https://a.test/after", &[]))
        .is_none());
}

#[test]
fn exchanges_past_the_limit_roll_and_kept_rows_are_never_reported_dropped() {
    let store = store(MAX_TOTAL_BYTES_LIMIT);
    decrypted(&store, 1);
    filed(&store, 1, "GET", "https://a.test/first", 200);
    decrypted(&store, 2);
    for i in 0..MAX_HTTP_EXCHANGES + 6 {
        filed(&store, 2, "GET", &format!("https://a.test/{i}"), 200);
    }
    let value = store.connection_json(2).unwrap();
    let http = value["http"].as_array().unwrap();
    assert_eq!(http.len(), MAX_HTTP_EXCHANGES);
    assert_eq!(http[0]["index"], 6);
    assert_eq!(http[0]["url"], "https://a.test/6");
    assert_eq!(store.exchange_json(2, 5, 0), Value::Null);
    let newest = MAX_HTTP_EXCHANGES + 5;
    assert_eq!(
        store.exchange_json(2, newest, 0)["url"],
        format!("https://a.test/{newest}")
    );
    assert_eq!(store.status().dropped_exchanges, 6);
    let rows = store.requests_json(0, None, Some(MAX_REQUEST_ROWS), &Filter::default());
    // The first row (connection 1) is older than the rolled ones but
    // still kept, so a client must not drop it.
    assert_eq!(rows["dropped_before_seq"], 0);
    assert_eq!(
        rows["requests"].as_array().unwrap().len(),
        MAX_HTTP_EXCHANGES + 1
    );
    assert_accounted(&store);
}

#[test]
fn an_open_connection_dropped_for_the_budget_records_again() {
    let store = store(MIN_TOTAL_BYTES);
    decrypted(&store, 1);
    filed(&store, 1, "GET", "https://a.test/one", 200);
    for id in 2..=4 {
        store.begin(id, Network::Tcp, None, "192.0.2.1:80", 1);
        store.record(id, Direction::Down, &vec![0u8; 30 * 1024]);
    }
    assert!(store.connection_json(1).is_none(), "dropped for newer ones");
    let index = store
        .open_exchange(1, HttpExchange::new("GET", "https://a.test/two", &[]))
        .expect("not left out for the rest of its life");
    assert_eq!(index, 1);
    store.finish_exchange(1, index, None);
    let value = store.connection_json(1).unwrap();
    assert_eq!(value["http"][0]["url"], "https://a.test/two");
    assert!(store.status().used_bytes <= MIN_TOTAL_BYTES);
    assert_accounted(&store);
}

#[test]
fn loaded_sessions_take_ids_no_live_connection_has() {
    let dir = std::env::temp_dir().join(format!(
        "anixops-capture-load-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let store = store(MAX_TOTAL_BYTES_LIMIT);
    store
        .set_storage(dir.to_str().unwrap(), &[3u8; storage::KEY_LEN], None)
        .unwrap();
    decrypted(&store, 12);
    filed(&store, 12, "GET", "https://saved.test/1", 200);
    filed(&store, 12, "GET", "https://saved.test/2", 200);
    store.end(12, 5);
    let saved = store.save_session(Some("yesterday"), false).unwrap();
    let session = saved["session"]["session"].as_str().unwrap().to_string();
    store.clear();

    // A later tunnel run numbers its connections from 1 again: a live
    // request on connection 12 is in flight as the session loads.
    decrypted(&store, 12);
    let live = store
        .open_exchange(12, HttpExchange::new("POST", "https://live.test/x", &[]))
        .unwrap();
    store.load_session(&session, false).unwrap();
    let mut finished = HttpExchange::new("POST", "https://live.test/x", &[]);
    finished.status = Some(201);
    store.update_exchange(12, live, &finished);
    store.finish_exchange(12, live, Some(finished));
    store.end(12, 99);

    assert!(store.connection_json(12).is_none());
    let loaded = store.connection_json(LOADED_ID_BASE).unwrap();
    assert_eq!(loaded["id"], LOADED_ID_BASE);
    assert_eq!(loaded["http"][0]["url"], "https://saved.test/1");
    assert_eq!(loaded["http"][1]["url"], "https://saved.test/2");
    assert_eq!(loaded["ended_at_ms"], 5);
    let rows = store.requests_json(0, None, None, &Filter::default());
    let rows = rows["requests"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .all(|row| row["connection_id"] == LOADED_ID_BASE && row["url"] != "https://live.test/x"));

    // Capture back on: a live connection whatever its id leaves the
    // loaded one alone, and the budget counts both once.
    store.set(true, None);
    decrypted(&store, 12);
    assert!(store.connection_json(LOADED_ID_BASE).is_some());
    assert_eq!(store.status().connections, 2);
    assert_accounted(&store);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_run_session_is_one_id_for_live_copies_and_the_save_on_stop() {
    use base64::Engine as _;

    let dir = std::env::temp_dir().join(format!(
        "anixops-capture-run-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    let app_dir = dir.with_extension("app");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&app_dir);
    let tunnel = store(MAX_TOTAL_BYTES_LIMIT);
    let run = tunnel.run_session().to_string();
    assert!(storage::saved_at(&run).is_some(), "{run}");
    assert_ne!(CaptureStore::default().run_session(), run);
    assert_eq!(tunnel.status().run_session, run);
    decrypted(&tunnel, 7);
    filed(&tunnel, 7, "GET", "https://run.test/1", 200);

    // The app's copy while the tunnel runs: no tunnel storage needed.
    let app_key = [5u8; storage::KEY_LEN];
    let copy: Value = serde_json::from_slice(
        &tunnel
            .copy_session(None, &app_key, Some("断开时自动保存"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(copy["session"], run.as_str());
    let file = base64::engine::general_purpose::STANDARD
        .decode(copy["data_base64"].as_str().unwrap())
        .unwrap();
    let viewer = CaptureStore::default();
    viewer
        .set_storage(app_dir.to_str().unwrap(), &app_key, None)
        .unwrap();
    viewer.import_session(&run, &file).unwrap();
    viewer.load_session(&run, true).unwrap();
    // The live id: the app finds the connection it showed.
    assert_eq!(
        viewer.connection_json(7).unwrap()["http"][0]["url"],
        "https://run.test/1"
    );
    assert!(viewer.connection_json(LOADED_ID_BASE).is_none());

    // More comes in; the tunnel saves the run on stop, under the same id.
    filed(&tunnel, 7, "GET", "https://run.test/2", 200);
    tunnel
        .set_storage(dir.to_str().unwrap(), &[6u8; storage::KEY_LEN], None)
        .unwrap();
    let saved = tunnel.save_session(Some("断开时自动保存"), true).unwrap();
    assert_eq!(saved["session"]["session"], run.as_str());
    let again = tunnel.save_session(None, true).unwrap();
    assert_eq!(again["session"]["session"], run.as_str());
    assert_eq!(
        tunnel.sessions().unwrap()["sessions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Its copy replaces the app's earlier one.
    let copy: Value =
        serde_json::from_slice(&tunnel.copy_session(Some(&run), &app_key, None).unwrap()).unwrap();
    let file = base64::engine::general_purpose::STANDARD
        .decode(copy["data_base64"].as_str().unwrap())
        .unwrap();
    viewer.import_session(&run, &file).unwrap();
    assert_eq!(
        viewer.sessions().unwrap()["sessions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    viewer.load_session(&run, true).unwrap();
    assert_eq!(
        viewer.connection_json(7).unwrap()["http"][1]["url"],
        "https://run.test/2"
    );
    let listed = viewer.connections_json();
    assert_eq!(listed["closed"][0]["id"], 7);
    assert_eq!(listed["closed"][0]["captured"], true);
    assert!(listed["closed"][0]["ended_at_ms"].is_u64());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&app_dir);
}

fn head_value<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.split("\r\n\r\n").next()?.lines().find_map(|line| {
        let (key, value) = line.split_once(": ")?;
        key.eq_ignore_ascii_case(name).then_some(value)
    })
}

fn body_of(text: &str) -> &str {
    text.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

#[test]
fn pcapng_text_frames_the_bytes_it_writes() {
    let header = |name: &str, value: &str| (name.to_string(), value.to_string());
    let text = |bytes: Vec<u8>| String::from_utf8(bytes).unwrap();

    // Chunked on the wire, kept without its chunk framing.
    let mut chunked = HttpExchange::new("GET", "https://a.test/c", &[]);
    chunked.status = Some(200);
    chunked.response_headers = vec![header("Transfer-Encoding", "chunked")];
    chunked.response_body = CapturedBody::of(b"hello");
    let down = text(http_text(&chunked).1);
    assert_eq!(head_value(&down, "Transfer-Encoding"), None);
    assert_eq!(
        head_value(&down, "X-AnixOps-Original-Transfer-Encoding"),
        Some("chunked")
    );
    assert_eq!(head_value(&down, "Content-Length"), Some("5"));
    assert_eq!(body_of(&down), "hello");

    // Kept only in part.
    let mut cut = HttpExchange::new("GET", "https://a.test/big", &[]);
    cut.status = Some(200);
    cut.response_headers = vec![
        header("Content-Length", "2000000"),
        header("Content-Encoding", "gzip"),
    ];
    cut.response_body = CapturedBody {
        data: vec![b'x'; MAX_HTTP_BODY_BYTES],
        size: 2_000_000,
    };
    let down = text(http_text(&cut).1);
    assert_eq!(head_value(&down, "Content-Length"), Some("65536"));
    assert_eq!(
        head_value(&down, "X-AnixOps-Original-Content-Length"),
        Some("2000000")
    );
    assert_eq!(head_value(&down, TRUNCATED_HEADER), Some("65536/2000000"));
    assert_eq!(head_value(&down, "Content-Encoding"), None);
    assert_eq!(body_of(&down).len(), MAX_HTTP_BODY_BYTES);

    // HTTP/2 names no length at all.
    let mut h2 = HttpExchange::new("GET", "https://a.test/h2", &[]);
    h2.http_version = HTTP_2;
    h2.status = Some(200);
    h2.response_body = CapturedBody::of(b"{}");
    let down = text(http_text(&h2).1);
    assert_eq!(head_value(&down, "Content-Length"), Some("2"));

    // Masking changes the length of what is written.
    let mut login = HttpExchange::new(
        "POST",
        "https://a.test/login",
        &[
            header("Content-Type", "application/json"),
            header("Content-Length", "36"),
        ],
    );
    login.request_body = CapturedBody::of(br#"{"user":"a","password":"hunter2-x"}"#);
    login.status = Some(204);
    let up = text(http_text(&redacted(&login, true)).0);
    let written = body_of(&up);
    assert!(written.contains(redact::MASK), "{up}");
    assert_eq!(
        head_value(&up, "Content-Length"),
        Some(written.len().to_string().as_str())
    );
    assert_eq!(
        head_value(&up, "X-AnixOps-Original-Content-Length"),
        Some("36")
    );

    // No body by status or method: the head stays as it was.
    for (method, status) in [("HEAD", 200), ("GET", 204), ("GET", 304), ("GET", 101)] {
        let mut bodiless = HttpExchange::new(method, "https://a.test/n", &[]);
        bodiless.status = Some(status);
        bodiless.response_headers = vec![header("Content-Length", "1234")];
        let down = text(http_text(&bodiless).1);
        assert_eq!(
            head_value(&down, "Content-Length"),
            Some("1234"),
            "{method} {status}"
        );
        assert_eq!(head_value(&down, "X-AnixOps-Original-Content-Length"), None);
        assert_eq!(body_of(&down), "");
    }
    // A request without a body names no length.
    let get = text(http_text(&HttpExchange::new("GET", "https://a.test/", &[])).0);
    assert_eq!(head_value(&get, "Content-Length"), None);
}

/// The TCP payload a pcapng export carries from `server_port`.
fn payload_from(pcap: &[u8], server_port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 8 <= pcap.len() {
        let kind = u32::from_le_bytes(pcap[at..at + 4].try_into().unwrap());
        let length = u32::from_le_bytes(pcap[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 6 {
            let body = &pcap[at + 8..at + length - 4];
            let captured = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
            let packet = &body[20..20 + captured];
            if packet[0] >> 4 == 4 && packet[9] == 6 {
                let tcp = &packet[20..];
                if u16::from_be_bytes([tcp[0], tcp[1]]) == server_port {
                    out.extend_from_slice(&tcp[20..]);
                }
            }
        }
        at += length;
    }
    out
}

#[test]
fn pcapng_responses_read_back_one_by_one() {
    let store = store(MAX_TOTAL_BYTES_LIMIT);
    decrypted(&store, 6);
    let header = |name: &str, value: &str| (name.to_string(), value.to_string());
    // Still waiting for its response: written after the answered ones.
    store
        .open_exchange(6, HttpExchange::new("GET", "https://a.test/pending", &[]))
        .unwrap();
    let mut chunked = HttpExchange::new("GET", "https://a.test/chunked", &[]);
    chunked.status = Some(200);
    chunked.response_headers = vec![header("Transfer-Encoding", "chunked")];
    chunked.response_body = CapturedBody::of(b"hello");
    store.add_exchange(6, chunked);
    let mut h2 = HttpExchange::new("GET", "https://a.test/h2", &[]);
    h2.http_version = HTTP_2;
    h2.status = Some(200);
    h2.response_headers = vec![header("Content-Type", "application/json")];
    h2.response_body = CapturedBody::of(br#"{"access_token":"t-1","n":1}"#);
    store.add_exchange(6, h2);
    let mut cut = HttpExchange::new("GET", "https://a.test/big", &[]);
    cut.status = Some(200);
    cut.response_headers = vec![header("Content-Length", "2000000")];
    cut.response_body = CapturedBody {
        data: vec![b'x'; MAX_HTTP_BODY_BYTES],
        size: 2_000_000,
    };
    store.add_exchange(6, cut);
    let mut empty = HttpExchange::new("DELETE", "https://a.test/item", &[]);
    empty.status = Some(204);
    store.add_exchange(6, empty);

    for redact in [true, false] {
        let pcap = store.export_pcapng(Some(6), redact);
        let down = payload_from(&pcap, 443);
        let mut stream = down.as_slice();
        let mut statuses = Vec::new();
        while !stream.is_empty() {
            let end = stream
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("a whole head")
                + 4;
            let head = std::str::from_utf8(&stream[..end]).unwrap();
            assert!(head.starts_with("HTTP/1.1 "), "{head}");
            statuses.push(head[9..12].to_string());
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .map_or(0, |value| value.trim().parse::<usize>().unwrap());
            stream = &stream[end + length..];
        }
        assert_eq!(statuses, ["200", "200", "200", "204"], "redact {redact}");
        let up = payload_from(&pcap, 10_000 + 6);
        let up = String::from_utf8_lossy(&up);
        let last_request = up.rfind("GET /pending HTTP/1.1").unwrap();
        assert!(up.rfind("DELETE /item").unwrap() < last_request);
    }
}

#[test]
fn pcapng_masks_plain_http_heads() {
    let store = store(MAX_TOTAL_BYTES_LIMIT);
    store.begin(5, Network::Tcp, None, "192.0.2.1:80", 1);
    store.record(
        5,
        Direction::Up,
        b"GET / HTTP/1.1\r\nCookie: sid=plain-secret\r\n\r\n",
    );
    let masked = store.export_pcapng(None, true);
    assert!(!masked.windows(12).any(|w| w == b"plain-secret"));
    let raw = store.export_pcapng(None, false);
    assert!(raw.windows(12).any(|w| w == b"plain-secret"));
}
