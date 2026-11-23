// Quantumult X: `bodyBytes` in the request, `opts.redirection`, and
// `bodyBytes` (an ArrayBuffer) next to the text `body` in the answer.
$task.fetch({
  url: "https://stub.example.test/echo",
  method: "POST",
  bodyBytes: new Uint8Array([1, 2]).buffer,
  opts: { redirection: false }
}).then(function (echo) {
  return $task.fetch({ url: "https://stub.example.test/bytes" }).then(function (bytes) {
    $done({
      body: echo.body + "#" + new Uint8Array(bytes.bodyBytes).join(",") + "#" + bytes.body.length +
        "#" + bytes.body.charCodeAt(2).toString(16)
    });
  });
});
