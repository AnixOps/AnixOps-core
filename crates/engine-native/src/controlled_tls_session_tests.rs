use super::*;
use control_domain::{
    GrantedPermissions, HookPoint, HttpEvent, PluginManifest, PluginPackage, PluginPermission,
    PluginResult,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use std::collections::BTreeMap;
use std::io::{Cursor, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Each exchange runs a request and a response script in a fresh node
// process. Shared Windows runners have taken over 5 s to start node while
// the rest of the suite runs in parallel, so the script budget here is
// sized for that; the timeout path itself is covered by the 10 ms test.
// Socket timeouts stay above one script budget so a slow script is
// reported as a script timeout, not as a dropped connection.
const CONTROLLED_TLS_SCRIPT_TEST_TIMEOUT_MS: usize = 20_000;
const CONTROLLED_TLS_SCRIPT_TEST_SOCKET_TIMEOUT: Duration = Duration::from_secs(30);

#[test]
fn controlled_tls_connect_session_bounds_persistent_exchanges_over_live_sockets() {
    let script_runtime_root = std::env::temp_dir().join(format!(
        "networkcore-controlled-tls-script-contract-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&script_runtime_root);
    std::fs::create_dir_all(&script_runtime_root)
        .expect("controlled TLS script runtime directory should be created");
    let script_url = "https://scripts.networkcore.test/controlled-tls.js".to_string();
    let mut script_assets = BTreeMap::new();
    script_assets.insert(
        script_url.clone(),
        format!(
            "{}/../../third_party/mitm_anixops/mitm_anixops/tests/fixtures/runner_replay_script.js",
            env!("CARGO_MANIFEST_DIR")
        ),
    );
    let http_mitm_hook = NativeHttpMitmPluginHook::new(
        PluginInstance {
            manifest: PluginManifest {
                id: "networkcore.controlled-tls-script".to_string(),
                version: "0.1.0".to_string(),
                permissions: vec![
                    PluginPermission::ReadRequest,
                    PluginPermission::ModifyRequest,
                    PluginPermission::ReadResponse,
                    PluginPermission::ModifyResponse,
                    PluginPermission::PersistentStorage,
                ],
                hooks: vec![HookPoint::Request, HookPoint::Response],
            },
            loaded_source: None,
        },
        Arc::new(ControlledTlsScriptDispatchingMitmPluginService { script_url }),
    )
    .with_node_script_executor(NativeNodeScriptExecutor::new(
        NativeNodeScriptRuntimeConfig {
            node_binary: "node".to_string(),
            runner_path: format!(
                "{}/../../third_party/mitm_anixops/mitm_anixops/e2e/script_runtime/anixops_runner.js",
                env!("CARGO_MANIFEST_DIR")
            ),
            script_assets,
            persistent_store_path: Some(
                script_runtime_root.join("store.json").display().to_string(),
            ),
            sandbox: NativeNodeScriptSandbox::Unrestricted,
            max_timeout_ms: CONTROLLED_TLS_SCRIPT_TEST_TIMEOUT_MS,
            max_body_bytes: 4096,
        },
    ));
    let (mitm_ca_certificate_pem, mitm_ca_private_key_pem, mitm_ca_der) = test_ca_material();
    let (mitm_leaf_certificate_der, mitm_leaf_private_key_der) = issue_test_leaf(
        &mitm_ca_certificate_pem,
        &mitm_ca_private_key_pem,
        "example.com",
    );
    let downstream_material = NativeTlsLeafCertificateMaterial {
        authority: "example.com".to_string(),
        certificate_pem: String::new(),
        private_key_pem: String::new(),
        certificate_der: mitm_leaf_certificate_der,
        private_key_der: mitm_leaf_private_key_der,
    };
    let downstream_server_config =
        build_controlled_tls_termination_server_config(&downstream_material)
            .server_config
            .expect("test MITM leaf material should build a downstream server config");

    let (upstream_ca_certificate_pem, upstream_ca_private_key_pem, upstream_ca_der) =
        test_ca_material();
    let (upstream_leaf_certificate_der, upstream_leaf_private_key_der) = issue_test_leaf(
        &upstream_ca_certificate_pem,
        &upstream_ca_private_key_pem,
        "example.com",
    );
    let upstream_server_config =
        test_server_config(upstream_leaf_certificate_der, upstream_leaf_private_key_der);
    let upstream_client_config = test_client_config(upstream_ca_der);

    let upstream_listener =
        TcpListener::bind("127.0.0.1:0").expect("test upstream listener should bind");
    let upstream_address = upstream_listener
        .local_addr()
        .expect("test upstream listener should expose local address");
    let upstream_worker = thread::spawn(move || {
        let (stream, _) = upstream_listener
            .accept()
            .expect("test upstream should accept proxy TLS connection");
        let _ = stream.set_read_timeout(Some(CONTROLLED_TLS_SCRIPT_TEST_SOCKET_TIMEOUT));
        let _ = stream.set_write_timeout(Some(CONTROLLED_TLS_SCRIPT_TEST_SOCKET_TIMEOUT));
        let connection = ServerConnection::new(upstream_server_config)
            .expect("test upstream TLS connection should initialize");
        let mut tls_stream = StreamOwned::new(connection, stream);
        for exchange_index in 0..CONTROLLED_TLS_MAX_HTTP_EXCHANGES {
            let request = read_explicit_http_proxy_request(&mut tls_stream)
                .request
                .expect("test upstream should receive decrypted HTTP request");
            assert_eq!(request.origin_path, "/resource");
            assert!(std::str::from_utf8(&request.body)
                .expect("script-mutated upstream request body should be UTF-8")
                .contains("requestRuntime"));
            assert_eq!(
                plain_http_header_value(&request.headers, "Connection").as_deref(),
                Some(if exchange_index + 1 == CONTROLLED_TLS_MAX_HTTP_EXCHANGES {
                    "close"
                } else {
                    "keep-alive"
                }),
            );
            let response_body = b"{\"from\":\"upstream\"}";
            let connection = if exchange_index + 1 == CONTROLLED_TLS_MAX_HTTP_EXCHANGES {
                "close"
            } else {
                "keep-alive"
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{}",
                response_body.len(),
                connection,
                std::str::from_utf8(response_body)
                    .expect("test upstream response body should be UTF-8"),
            );
            tls_stream
                .write_all(response.as_bytes())
                .expect("test upstream should write HTTPS response");
            tls_stream
                .flush()
                .expect("test upstream should flush HTTPS response");
        }
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("test proxy listener should bind");
    let proxy_address = proxy_listener
        .local_addr()
        .expect("test proxy listener should expose local address");
    let downstream_client_config = test_client_config(mitm_ca_der);
    let downstream_client = thread::spawn(move || {
        let stream = TcpStream::connect(proxy_address)
            .expect("test TLS client should connect to controlled proxy session");
        let _ = stream.set_read_timeout(Some(CONTROLLED_TLS_SCRIPT_TEST_SOCKET_TIMEOUT));
        let _ = stream.set_write_timeout(Some(CONTROLLED_TLS_SCRIPT_TEST_SOCKET_TIMEOUT));
        let server_name = ServerName::try_from("example.com")
            .expect("test server name should parse")
            .to_owned();
        let connection = ClientConnection::new(downstream_client_config, server_name)
            .expect("test TLS client connection should initialize");
        let mut tls_stream = StreamOwned::new(connection, stream);
        for exchange_index in 0..CONTROLLED_TLS_MAX_HTTP_EXCHANGES {
            tls_stream
                .write_all(b"GET /resource HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .expect("test TLS client should write HTTP request");
            tls_stream
                .flush()
                .expect("test TLS client should flush HTTP request");
            let response = read_plain_http_proxy_response(&mut tls_stream)
                .response
                .expect("test TLS client should receive HTTP response");
            assert_eq!(response.status_code, 202);
            assert!(std::str::from_utf8(&response.body)
                .expect("script-mutated client response body should be UTF-8")
                .contains("responseRuntime"));
            assert_eq!(
                plain_http_header_value(&response.headers, "Connection").as_deref(),
                Some(if exchange_index + 1 == CONTROLLED_TLS_MAX_HTTP_EXCHANGES {
                    "close"
                } else {
                    "keep-alive"
                }),
            );
        }
    });

    let (proxy_stream, _) = proxy_listener
        .accept()
        .expect("test proxy should accept controlled TLS client connection");
    let _ = proxy_stream.set_read_timeout(Some(CONTROLLED_TLS_SCRIPT_TEST_SOCKET_TIMEOUT));
    let _ = proxy_stream.set_write_timeout(Some(CONTROLLED_TLS_SCRIPT_TEST_SOCKET_TIMEOUT));
    let outbound_stream = TcpStream::connect(upstream_address)
        .expect("test proxy should connect to upstream TLS server");
    let mut connect_request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());
    let connect_request = read_explicit_http_proxy_request(&mut connect_request)
        .request
        .expect("test CONNECT request should parse");
    let (exchange_completed, diagnostics) = run_controlled_tls_connect_http_exchange(
        &proxy_stream,
        outbound_stream,
        &connect_request,
        downstream_server_config,
        upstream_client_config,
        Some(&http_mitm_hook),
    );

    // Failed once on Windows (CI run 43629103710) with the request body
    // not rewritten by the node script; print what the session reported.
    assert!(exchange_completed, "diagnostics: {diagnostics:#?}");
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_READY_CODE
    }));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| { diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_EXECUTED_CODE }));
    downstream_client
        .join()
        .expect("test TLS client thread should finish");
    upstream_worker
        .join()
        .expect("test upstream TLS thread should finish");
    std::fs::remove_dir_all(&script_runtime_root)
        .expect("controlled TLS script runtime directory should be removed");
}

#[test]
fn controlled_tls_connect_session_negotiates_h2_with_client_and_upstream() {
    let (downstream_server_config, mitm_ca_der) = test_mitm_downstream_server_config();
    let (upstream_ca_certificate_pem, upstream_ca_private_key_pem, upstream_ca_der) =
        test_ca_material();
    let (upstream_leaf_certificate_der, upstream_leaf_private_key_der) = issue_test_leaf(
        &upstream_ca_certificate_pem,
        &upstream_ca_private_key_pem,
        "example.com",
    );
    let mut upstream_server_config =
        (*test_server_config(upstream_leaf_certificate_der, upstream_leaf_private_key_der)).clone();
    upstream_server_config.alpn_protocols = vec![b"h2".to_vec()];
    let upstream_server_config = Arc::new(upstream_server_config);
    let upstream_client_config = test_client_config(upstream_ca_der);

    let upstream_listener =
        TcpListener::bind("127.0.0.1:0").expect("test upstream listener should bind");
    let upstream_address = upstream_listener
        .local_addr()
        .expect("test upstream listener should expose local address");
    let upstream_worker = thread::spawn(move || {
        let (stream, _) = upstream_listener
            .accept()
            .expect("test upstream should accept proxy TLS connection");
        test_runtime().block_on(async move {
            stream
                .set_nonblocking(true)
                .expect("test upstream socket should become non-blocking");
            let stream = tokio::net::TcpStream::from_std(stream)
                .expect("test upstream socket should join the runtime");
            let tls_stream = tokio_rustls::TlsAcceptor::from(upstream_server_config)
                .accept(stream)
                .await
                .expect("test upstream TLS handshake should complete");
            assert_eq!(tls_stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
            let mut connection = h2::server::handshake(tls_stream)
                .await
                .expect("test upstream HTTP/2 handshake should complete");
            let (request, mut respond) = connection
                .accept()
                .await
                .expect("test upstream should receive a stream")
                .expect("test upstream stream should be valid");
            assert_eq!(request.uri().path(), "/resource");
            assert_eq!(
                request
                    .uri()
                    .authority()
                    .map(|authority| authority.as_str()),
                Some("example.com")
            );
            let response = http::Response::builder()
                .status(200)
                .header("content-length", "8")
                .body(())
                .expect("test upstream response head should build");
            let mut send = respond
                .send_response(response, false)
                .expect("test upstream response should send");
            send.send_data(bytes::Bytes::from_static(b"upstream"), true)
                .expect("test upstream body should send");
            while connection.accept().await.is_some() {}
        });
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("test proxy listener should bind");
    let proxy_address = proxy_listener
        .local_addr()
        .expect("test proxy listener should expose local address");
    let downstream_client = thread::spawn(move || {
        test_runtime().block_on(async move {
            let stream = tokio::net::TcpStream::connect(proxy_address)
                .await
                .expect("test h2 client should connect to controlled proxy session");
            let mut client_config = (*test_client_config(mitm_ca_der)).clone();
            client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let server_name = ServerName::try_from("example.com")
                .expect("test server name should parse")
                .to_owned();
            let tls_stream = tokio_rustls::TlsConnector::from(Arc::new(client_config))
                .connect(server_name, stream)
                .await
                .expect("test h2 client TLS handshake should complete");
            assert_eq!(tls_stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
            let (send_request, connection) = h2::client::handshake(tls_stream)
                .await
                .expect("test h2 client handshake should complete");
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let mut send_request = send_request
                .ready()
                .await
                .expect("test h2 client should be ready");
            let request = http::Request::builder()
                .uri("https://example.com/resource")
                .body(())
                .expect("test h2 request head should build");
            let (response, _) = send_request
                .send_request(request, true)
                .expect("test h2 request should send");
            let response = response.await.expect("test h2 response should arrive");
            assert_eq!(response.status(), 200);
            let mut body = response.into_body();
            let mut collected = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.expect("test h2 response chunk should arrive");
                let _ = body.flow_control().release_capacity(chunk.len());
                collected.extend_from_slice(&chunk);
            }
            assert_eq!(collected, b"upstream");
            drop(send_request);
            let _ = driver.await;
        });
    });

    let (proxy_stream, _) = proxy_listener
        .accept()
        .expect("test proxy should accept controlled TLS client connection");
    let outbound_stream = TcpStream::connect(upstream_address)
        .expect("test proxy should connect to upstream TLS server");
    let connect_request = test_connect_request();
    let client_hello =
        observe_http_connect_tls_client_hello_from_stream(&proxy_stream, &connect_request, true);
    assert!(client_hello.client_hello_observed);
    let (exchange_completed, diagnostics) = run_controlled_tls_connect_http_exchange(
        &proxy_stream,
        outbound_stream,
        &connect_request,
        downstream_server_config,
        upstream_client_config,
        None,
    );

    assert!(exchange_completed, "{diagnostics:#?}");
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_ALPN_NEGOTIATED_CODE
            && diagnostic.message.contains("ALPN h2")
    }));
    for code in [
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_SESSION_READY_CODE,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_STREAM_COMPLETED_CODE,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_READY_CODE,
    ] {
        assert!(diagnostics_contain_code(&diagnostics, code), "{code}");
    }
    downstream_client
        .join()
        .expect("test h2 client thread should finish");
    upstream_worker
        .join()
        .expect("test h2 upstream thread should finish");
}

#[test]
fn controlled_tls_connect_session_falls_back_to_http1_when_upstream_lacks_h2() {
    let (downstream_server_config, mitm_ca_der) = test_mitm_downstream_server_config();
    let (upstream_ca_certificate_pem, upstream_ca_private_key_pem, upstream_ca_der) =
        test_ca_material();
    let (upstream_leaf_certificate_der, upstream_leaf_private_key_der) = issue_test_leaf(
        &upstream_ca_certificate_pem,
        &upstream_ca_private_key_pem,
        "example.com",
    );
    let upstream_server_config =
        test_server_config(upstream_leaf_certificate_der, upstream_leaf_private_key_der);
    let upstream_client_config = test_client_config(upstream_ca_der);

    let upstream_listener =
        TcpListener::bind("127.0.0.1:0").expect("test upstream listener should bind");
    let upstream_address = upstream_listener
        .local_addr()
        .expect("test upstream listener should expose local address");
    let upstream_worker = thread::spawn(move || {
        let (stream, _) = upstream_listener
            .accept()
            .expect("test upstream should accept proxy TLS connection");
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let connection = ServerConnection::new(upstream_server_config)
            .expect("test upstream TLS connection should initialize");
        let mut tls_stream = StreamOwned::new(connection, stream);
        let request = read_explicit_http_proxy_request(&mut tls_stream)
            .request
            .expect("test upstream should receive decrypted HTTP/1.1 request");
        assert_eq!(request.origin_path, "/fallback");
        assert_eq!(tls_stream.conn.alpn_protocol(), Some(&b"http/1.1"[..]));
        tls_stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nfallback")
            .expect("test upstream should write HTTPS response");
        tls_stream
            .flush()
            .expect("test upstream should flush HTTPS response");
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("test proxy listener should bind");
    let proxy_address = proxy_listener
        .local_addr()
        .expect("test proxy listener should expose local address");
    let downstream_client = thread::spawn(move || {
        let stream = TcpStream::connect(proxy_address)
            .expect("test TLS client should connect to controlled proxy session");
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let mut client_config = (*test_client_config(mitm_ca_der)).clone();
        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let server_name = ServerName::try_from("example.com")
            .expect("test server name should parse")
            .to_owned();
        let connection = ClientConnection::new(Arc::new(client_config), server_name)
            .expect("test TLS client connection should initialize");
        let mut tls_stream = StreamOwned::new(connection, stream);
        tls_stream
            .write_all(b"GET /fallback HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            .expect("test TLS client should write HTTP request");
        tls_stream
            .flush()
            .expect("test TLS client should flush HTTP request");
        let response = read_plain_http_proxy_response(&mut tls_stream)
            .response
            .expect("test TLS client should receive HTTP/1.1 response");
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, b"fallback");
        assert_eq!(tls_stream.conn.alpn_protocol(), Some(&b"http/1.1"[..]));
    });

    let (proxy_stream, _) = proxy_listener
        .accept()
        .expect("test proxy should accept controlled TLS client connection");
    let outbound_stream = TcpStream::connect(upstream_address)
        .expect("test proxy should connect to upstream TLS server");
    let connect_request = test_connect_request();
    let client_hello =
        observe_http_connect_tls_client_hello_from_stream(&proxy_stream, &connect_request, true);
    assert!(client_hello.client_hello_observed);
    let (exchange_completed, diagnostics) = run_controlled_tls_connect_http_exchange(
        &proxy_stream,
        outbound_stream,
        &connect_request,
        downstream_server_config,
        upstream_client_config,
        None,
    );

    assert!(exchange_completed, "{diagnostics:#?}");
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_ALPN_NEGOTIATED_CODE
            && diagnostic.message.contains("ALPN http/1.1")
    }));
    assert!(!diagnostics_contain_code(
        &diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_H2_SESSION_READY_CODE
    ));
    downstream_client
        .join()
        .expect("test TLS client thread should finish");
    upstream_worker
        .join()
        .expect("test upstream TLS thread should finish");
}

fn test_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime should start")
}

fn test_connect_request() -> NativeExplicitHttpProxyRequest {
    let mut connect_request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());
    read_explicit_http_proxy_request(&mut connect_request)
        .request
        .expect("test CONNECT request should parse")
}

fn test_mitm_downstream_server_config() -> (Arc<ServerConfig>, Vec<u8>) {
    let (mitm_ca_certificate_pem, mitm_ca_private_key_pem, mitm_ca_der) = test_ca_material();
    let (mitm_leaf_certificate_der, mitm_leaf_private_key_der) = issue_test_leaf(
        &mitm_ca_certificate_pem,
        &mitm_ca_private_key_pem,
        "example.com",
    );
    let downstream_material = NativeTlsLeafCertificateMaterial {
        authority: "example.com".to_string(),
        certificate_pem: String::new(),
        private_key_pem: String::new(),
        certificate_der: mitm_leaf_certificate_der,
        private_key_der: mitm_leaf_private_key_der,
    };
    let downstream_server_config =
        build_controlled_tls_termination_server_config(&downstream_material)
            .server_config
            .expect("test MITM leaf material should build a downstream server config");
    (downstream_server_config, mitm_ca_der)
}

struct ControlledTlsScriptDispatchingMitmPluginService {
    script_url: String,
}

impl MitmPluginService for ControlledTlsScriptDispatchingMitmPluginService {
    fn validate_manifest(&self, _plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
        Vec::new()
    }

    fn load(
        &self,
        plugin_package: &PluginPackage,
        _granted_permissions: &GrantedPermissions,
    ) -> DomainResult<PluginInstance> {
        Ok(PluginInstance {
            manifest: plugin_package.manifest.clone(),
            loaded_source: None,
        })
    }

    fn handle_http_event(
        &self,
        _plugin_instance: &PluginInstance,
        _http_event: &HttpEvent,
    ) -> DomainResult<PluginResult> {
        Ok(PluginResult {
            audits: Vec::new(),
            diagnostics: Vec::new(),
        })
    }

    fn handle_http_mitm_event(
        &self,
        plugin_instance: &PluginInstance,
        http_event: &HttpMitmEvent,
    ) -> DomainResult<HttpMitmOutcome> {
        assert_eq!(
            plugin_instance.manifest.id,
            "networkcore.controlled-tls-script"
        );
        assert_eq!(http_event.url, "https://example.com/resource");

        let kind = match http_event.phase {
            HttpMitmPhase::Request => HttpMitmScriptKind::Request,
            HttpMitmPhase::Response => HttpMitmScriptKind::Response,
        };
        Ok(HttpMitmOutcome {
            action: HttpMitmAction::Continue,
            header_mutations: Vec::new(),
            body_mutation: None,
            script_dispatch: Some(HttpMitmScriptDispatch {
                kind,
                phase: http_event.phase,
                requires_body: true,
                timeout_ms: CONTROLLED_TLS_SCRIPT_TEST_TIMEOUT_MS,
                max_size: 1024,
                script_path: self.script_url.clone(),
                tag: "controlled-tls-script".to_string(),
                argument: "Mode=controlled-tls".to_string(),
                binary_body_mode: false,
            }),
            audits: Vec::new(),
            diagnostics: Vec::new(),
        })
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
        plugin_result.audits.clone()
    }
}

fn test_ca_material() -> (String, String, Vec<u8>) {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "NetworkCore controlled TLS test CA");
    distinguished_name.push(DnType::OrganizationName, "AnixOps NetworkCore");
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key_pair = KeyPair::generate().expect("test CA key should generate");
    let certificate = params
        .self_signed(&key_pair)
        .expect("test CA certificate should self-sign");
    (
        certificate.pem(),
        key_pair.serialize_pem(),
        certificate.der().as_ref().to_vec(),
    )
}

fn issue_test_leaf(
    ca_certificate_pem: &str,
    ca_private_key_pem: &str,
    host: &str,
) -> (Vec<u8>, Vec<u8>) {
    let issuer_key =
        KeyPair::from_pem(ca_private_key_pem).expect("test CA private key should parse");
    let issuer = Issuer::from_ca_cert_pem(ca_certificate_pem, issuer_key)
        .expect("test CA certificate should parse");
    let mut params =
        CertificateParams::new(vec![host.to_string()]).expect("test leaf authority should encode");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key_pair = KeyPair::generate().expect("test leaf key should generate");
    let certificate = params
        .signed_by(&key_pair, &issuer)
        .expect("test leaf should sign");
    (
        certificate.der().as_ref().to_vec(),
        key_pair.serialize_der(),
    )
}

fn test_server_config(certificate_der: Vec<u8>, private_key_der: Vec<u8>) -> Arc<ServerConfig> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("test rustls provider should support TLS 1.2 and TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der)),
            )
            .expect("test leaf key should match test leaf certificate");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn test_client_config(certificate_der: Vec<u8>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate_der))
        .expect("test CA should be a valid trust anchor");
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("test rustls provider should support TLS 1.2 and TLS 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}
