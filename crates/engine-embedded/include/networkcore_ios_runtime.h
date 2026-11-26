/*
 * NetworkCore embedded runtime C ABI for the iOS packet tunnel.
 *
 * Source of truth: crates/engine-embedded/src/ffi.rs. Keep the two in sync and bump
 * NETWORKCORE_IOS_ABI_VERSION on any incompatible change.
 *
 * Ownership:
 *   - Input buffers belong to the caller and are only read during the call.
 *   - NetworkCoreBuffer values are owned by the library; release each one once with
 *     networkcore_ios_runtime_free_buffer.
 *   - The runtime handle is released with networkcore_ios_runtime_free_handle.
 *   - networkcore_ios_measure_delay is also linked into the containing app, which tests
 *     nodes with it without starting a tunnel; so are networkcore_ios_checkup,
 *     networkcore_ios_mitm_inspect_plugin and networkcore_ios_decode_body.
 *   - The packet writer runs on the tunnel thread until stop_tunnel returns and must
 *     not call back into the library.
 */
#ifndef NETWORKCORE_IOS_RUNTIME_H
#define NETWORKCORE_IOS_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NETWORKCORE_IOS_ABI_VERSION 1u

#define NETWORKCORE_IOS_OK 0
#define NETWORKCORE_IOS_ERR_ARTIFACT_MISSING 1
#define NETWORKCORE_IOS_ERR_MISSING_SYMBOL 2
#define NETWORKCORE_IOS_ERR_ABI_MISMATCH 3
#define NETWORKCORE_IOS_ERR_SCHEMA_MISMATCH 4
#define NETWORKCORE_IOS_ERR_INVALID_ARGUMENT 5
#define NETWORKCORE_IOS_ERR_CONFIG_REJECTED 6
#define NETWORKCORE_IOS_ERR_RESOURCE_EXHAUSTED 7
#define NETWORKCORE_IOS_ERR_PANIC_CAUGHT 8
#define NETWORKCORE_IOS_ERR_INTERNAL_ERROR 9
#define NETWORKCORE_IOS_ERR_PACKET_DROPPED 10
#define NETWORKCORE_IOS_ERR_DELAY_TIMEOUT 11
#define NETWORKCORE_IOS_ERR_DELAY_FAILED 12

typedef struct NetworkCoreRuntime NetworkCoreRuntime;

typedef struct NetworkCoreBuffer {
    uint8_t *ptr;
    size_t len;
    size_t cap;
} NetworkCoreBuffer;

typedef void (*NetworkCorePacketWriter)(void *context, const uint8_t *packet, size_t len);

/* One IP packet borrowed for the duration of a call (feature set 4). */
typedef struct NetworkCorePacket {
    const uint8_t *ptr;
    size_t len;
} NetworkCorePacket;

/* Receives a burst of 1...64 packets in order; valid only during the call (feature set 4). */
typedef void (*NetworkCorePacketBatchWriter)(void *context, const NetworkCorePacket *packets, size_t count);

uint32_t networkcore_ios_abi_version(void);
uint32_t networkcore_ios_schema_version(void);
/* 7: mesh networks (`"type": "mesh"` outbounds, `mesh_*` and `capabilities` control commands). */
uint32_t networkcore_ios_feature_set_version(void);

int32_t networkcore_ios_runtime_init(const uint8_t *config, size_t config_len, NetworkCoreRuntime **out_handle);
int32_t networkcore_ios_runtime_start_tunnel(NetworkCoreRuntime *handle, NetworkCorePacketWriter writer, void *context);
int32_t networkcore_ios_runtime_input_packet(NetworkCoreRuntime *handle, const uint8_t *packet, size_t len);
/* Batched packet I/O (feature set 4): the tunnel hands packets that are ready together to `writer`
 * in one call, and input_packets queues one readPackets result under one lock. input_packets
 * writes the number queued to `out_accepted` (may be NULL) and returns
 * NETWORKCORE_IOS_ERR_PACKET_DROPPED when any packet was dropped. */
int32_t networkcore_ios_runtime_start_tunnel_batched(NetworkCoreRuntime *handle, NetworkCorePacketBatchWriter writer,
                                                     void *context);
int32_t networkcore_ios_runtime_input_packets(NetworkCoreRuntime *handle, const NetworkCorePacket *packets, size_t count,
                                              size_t *out_accepted);
int32_t networkcore_ios_runtime_stop_tunnel(NetworkCoreRuntime *handle);
int32_t networkcore_ios_runtime_collect_status(NetworkCoreRuntime *handle, NetworkCoreBuffer *out);
/* Runtime control (feature set 2): one JSON request {"cmd": ...} in, one JSON answer in `out`.
 * Commands: traffic, connections, close_connection {id}, close_all. See src/control.rs.
 * Returns NETWORKCORE_IOS_ERR_INVALID_ARGUMENT for a request that is longer than 4096 bytes,
 * not JSON, or not a known command. */
int32_t networkcore_ios_runtime_control(NetworkCoreRuntime *handle, const uint8_t *request, size_t request_len,
                                        NetworkCoreBuffer *out);
/* Delay test: time to the first HTTP response line of `url` through the outbound of `config`,
 * in milliseconds. Needs no runtime handle and blocks the calling thread up to timeout_ms
 * (1...60000). Returns NETWORKCORE_IOS_ERR_DELAY_TIMEOUT or NETWORKCORE_IOS_ERR_DELAY_FAILED when
 * the node did not answer. */
int32_t networkcore_ios_measure_delay(const uint8_t *config, size_t config_len, const uint8_t *url, size_t url_len,
                                      uint32_t timeout_ms, uint32_t *out_millis);
/* Node checkup (feature set 5): latency, and with "throughput" set the download speed and loaded
 * latency, of the outbound of `config`; see src/checkup.rs and docs/architecture/node-checkup.md.
 * `options` is a CheckupOptions JSON document (snake_case, at most 4096 bytes, unknown fields
 * rejected); options_len 0 (options may be NULL) runs the defaults. Writes the CheckupReport JSON
 * to `out`. Blocks the calling thread for the whole checkup; needs no runtime handle; only the user
 * starts it. Bad options return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT; a node that does not answer
 * returns NETWORKCORE_IOS_OK with the loss and failure in the report. */
int32_t networkcore_ios_checkup(const uint8_t *config, size_t config_len, const uint8_t *options, size_t options_len,
                                NetworkCoreBuffer *out);
/* MITM plugin inspection (feature set 3): imports one Loon / Surge / Quantumult X plugin text
 * (at most 1 MiB, UTF-8) and writes JSON to `out`: {"name", "level": "full|partial|unsupported",
 * "hostnames", "excluded_hostnames", "lines": {"supported", "partial", "unsupported", "deferred"},
 * "resources": [{"url", "kind": "script|map_local_data", "line"}], "report"}. Download the
 * "map_local_data" resources and pass them as mitm.resource_assets; scripts need the user's
 * consent first. Needs no runtime handle. */
int32_t networkcore_ios_mitm_inspect_plugin(const uint8_t *text, size_t text_len, NetworkCoreBuffer *out);
/* Decodes a captured body's Content-Encoding (gzip, x-gzip, deflate, br, zstd, several in a row)
 * for the inspector, in the app's own process: at most 16 MiB out, windows up to brotli's 16 MiB
 * and zstd's 8 MiB (RFC 9659). complete = 0 when capture kept only the start of the body; then,
 * or when the output reaches the limit, *truncated is set to 1. An unknown coding, an invalid body
 * or a window over the limit returns NETWORKCORE_IOS_ERR_INVALID_ARGUMENT; show the bytes as
 * captured then. Needs no runtime handle. */
int32_t networkcore_ios_decode_body(const uint8_t *data, size_t data_len, const uint8_t *content_encoding,
                                    size_t content_encoding_len, uint8_t complete, uint8_t *truncated,
                                    NetworkCoreBuffer *out);
/* Capture viewer (feature set 6): saved capture sessions opened with no runtime handle, in the
 * app's own process, while the tunnel is off. One JSON request {"cmd": ...} in, one JSON answer in
 * `out`: set_capture_storage {dir, key_base64}, capture_sessions, load_capture {session},
 * import_capture {session, data_base64} (a file from the engine's copy_capture), delete_capture,
 * clear_capture, capture, capture_requests, capture_connection, capture_exchange,
 * capture_h2_frames, export_capture (pcapng, har, zip, ...) and connections. Requests up to 96 MiB.
 * A refused request returns NETWORKCORE_IOS_ERR_INVALID_ARGUMENT with {"error": "<message>"} in
 * `out`. See src/capture_viewer.rs. */
int32_t networkcore_ios_capture_viewer(const uint8_t *request, size_t request_len, NetworkCoreBuffer *out);
/* Bound interface (macOS packet tunnel): pins every socket the engine opens to the interface with
 * this index (if_nametoindex), so it leaves through the physical network instead of looping into
 * the tunnel's default route. 0 leaves that family unpinned; both 0 removes the pin. Process-wide,
 * no runtime handle; call before start_tunnel and again when the network changes. Apple platforms
 * only (IP_BOUND_IF): elsewhere a non-zero index returns NETWORKCORE_IOS_ERR_INVALID_ARGUMENT. */
int32_t networkcore_ios_set_bound_interface(uint32_t ipv4_index, uint32_t ipv6_index);
void networkcore_ios_runtime_free_buffer(NetworkCoreBuffer buffer);
void networkcore_ios_runtime_free_handle(NetworkCoreRuntime *handle);

#ifdef __cplusplus
}
#endif

#endif /* NETWORKCORE_IOS_RUNTIME_H */
