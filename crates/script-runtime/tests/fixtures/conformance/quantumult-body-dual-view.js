// Quantumult X scripts get the text `body` and `bodyBytes` side by side
// without binary-body-mode, and `bodyBytes` in `$done` wins over `body`.
var json = JSON.parse($response.body);
var bytes = new Uint8Array($response.bodyBytes);
$done({ body: "unused", bodyBytes: new Uint8Array([bytes.length, json.n, 0xff]).buffer });
