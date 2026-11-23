# script-runtime

Loon-compatible HTTP script runtime for MITM `[Script]` dispatches (roadmap
M3, Loon plugin tier P1).

The `$`-API is implemented once in Rust (`ScriptHost`):

| Global | Behavior |
|---|---|
| `$request`, `$response` | URL, method, headers (object), UTF-8 body when `requires-body=true`; response status. Repeated header names are joined with `, `, except `Cookie` (HTTP/2 clients send one field per cookie), which is joined with `; ` so the value is one valid cookie list. `$done({headers})` replaces the message's header list as a whole (a removed name is removed), but a repeated name returned with exactly the joined value the script read becomes the original fields again (`restore_joined_headers`), so a script that only removes, say, `Content-Security-Policy` keeps every `Set-Cookie` field; a joined value the script changed goes out as one field. A response script's `$request` is the request the response answers: its headers as the request rules and scripts left them, and, with `requires-body=true`, its body when the data plane held it (a request rule or script read it; a body that was streamed to the origin, is over `max-size`, or is not UTF-8 outside binary mode is left out). |
| `bodyBytes` | Quantumult X view of a body, an `ArrayBuffer`. With `binary-body-mode` `body` is a `Uint8Array` and `bodyBytes` its buffer. Without it (Quantumult X `script-*-body` lines carry no such option) `body` stays text and `bodyBytes` is its UTF-8 bytes, made only when read; a body that is not UTF-8 reaches a script that reads `bodyBytes` as bytes only (no `body`), and other text scripts are deferred on it as before. `$done({bodyBytes})` (an `ArrayBuffer` or typed array) wins over `body`, also inside `response` and for `script-echo-response`. |
| `$argument` | The line's `argument=` value. |
| `$done(value)` | First call wins. Request phase: `url`, `headers`, `body`, or `response: {status, headers, body}` to answer without the origin. Response phase: `status` (number or status line), `headers`, `body`. `$done()` keeps the message. A body is a string in text mode; `bodyBytes` (an `ArrayBuffer` or typed array, see above) and, with `binary-body-mode`, a `Uint8Array` `body` carry bytes. |
| `$persistentStore.read/write/remove` | Shared key-value store; key ≤ 256 B, value ≤ 512 KiB, total ≤ 8 MiB. A missing key uses `networkcore.script.<tag>`. The file store (`JsonFileScriptStore`) writes a temporary sibling of its own (`<path>.tmp-<pid>-<n>`; leftovers of a crash are removed on open), flushes it to disk and renames it over the store (retried briefly when Windows holds the file); a write that changes nothing is skipped. `open_script_store` never fails a runtime: a file that is not a JSON object of strings is moved to `<path>.corrupt` (only the latest copy is kept) and the store starts empty; a file that cannot be read or moved leaves scripts an in-memory store. Runtimes of one process that open the same file while an earlier store of it is in use (an engine reload, a tunnel next to a local proxy) share that one store, so neither writes back a copy without the other's changes. |
| `$notification.post` | Collected in the outcome (16 at most). |
| `$httpClient.get/post/...` | Goes to a `ScriptHttpClient`; `DisabledScriptHttpClient` (the default) returns an error to the callback. Redirects are followed (at most `SCRIPT_HTTP_CLIENT_MAX_REDIRECTS`, 5, within the one timeout) unless the options say `auto-redirect: false` (Surge, Loon) or `redirection: false` / `opts.redirection: false` (Quantumult X, Env.js). `binary-mode: true` hands the callback a `Uint8Array`; otherwise the body is UTF-8 text. A `Uint8Array` / `ArrayBuffer` request body (or `bodyBytes`) is sent as its bytes. The method (also `$task.fetch`'s `opts.method`) must be an RFC 9110 token of at most 32 bytes (`is_http_method_token`); anything else (spaces, CR / LF, NUL, non-ASCII) is refused in Rust before a request is made and the callback gets `networkcore: invalid $httpClient method`. |
| `$prefs.valueForKey/setValueForKey/removeValueForKey` | Quantumult X names for `$persistentStore`; same store. `removeAllValues` returns `false`. |
| `$notify(title, subtitle, content, options)` | Quantumult X name for `$notification.post`; `options["open-url"]` is the URL. |
| `$task.fetch(options)` | Quantumult X; a promise over `$httpClient` resolving `{statusCode, headers, body, bodyBytes}` (`body` is the UTF-8 text, `bodyBytes` an `ArrayBuffer` of the bytes) or rejecting `{error}`; a request may carry `bodyBytes`. Defined only when the script uses `$task` and never names `$loon`, because cross-client scripts (Env.js) check `$task` first and must take their Loon branch. |
| `$response.statusCode` | Same as `$response.status`, for Quantumult X scripts. |
| `console.*`, `setTimeout`, `clearTimeout` | Logs are collected (128 lines); timers run inside the dispatch budget. |
| `$loon`, `$script` | `NetworkCore/<version>`; script name and type. |

An engine binding implements `JsEngineContext` (evaluate sloppy-mode global
code, drain promise jobs) and defines one host function, `__nc_host(op,
payload)`, that forwards to `ScriptHost::call`. `run_script` evaluates the
shared `src/prelude.js` and the script, then services timers and `$httpClient`
callbacks until `$done`, idle, or the deadline. `finish_outcome` maps the
result the same way for every engine.

The desktop binding is QuickJS-ng through rquickjs (`QuickJsScriptRuntime`).
Each dispatch gets a fresh runtime with a heap limit and an interrupt handler
for the wall-clock timeout, so Loon's `timeout` and `max-size` hold even for
busy loops. Scripts have no file system, process, or network access of their
own. The iOS packet tunnel uses this binding too (decided 2026-10-24, until an
App Store build moves to JavaScriptCore); rquickjs ships no iOS bindings, so on
iOS targets the `bindgen` feature generates them from Xcode's libclang.

The Apple binding is JavaScriptCore through its public C API
(`JscScriptRuntime`, cargo feature `javascriptcore`, Apple targets only; roadmap
M4). Its public API has no interrupt and no heap limit, so each dispatch runs on
a worker thread under a watchdog:

- timers and `$httpClient` callbacks stop at the deadline in the shared event
  loop, as with QuickJS;
- synchronous JavaScript still running at the deadline is reported as
  `script.timeout`, and the worker is abandoned and counted as stuck; while
  `MAX_STUCK_WORKERS` (2) workers are stuck, new dispatches fail fast with
  `script.engine`, and the caller should disable the script and restart;
- memory is bounded only by the body caps checked before the script runs
  (`ENFORCES_HEAP_LIMIT = false`).

`tests/fixtures/conformance/<case>.js` plus `<case>.json` (invocation, initial
store, limits, expected outcome, and optional `requires` engine capabilities)
form the engine-neutral conformance suite. QuickJS runs every fixture; the CI
job "JavaScriptCore script conformance" (macOS) runs the same files with
JavaScriptCore, which may skip only `memory-limit` (`requires: heap-limit`).
