// A body that is not UTF-8 (protobuf) reaches a text-mode script that reads
// `bodyBytes` as bytes only.
var view = new Uint8Array($response.bodyBytes);
$done({ bodyBytes: view.slice(1).buffer, headers: { "X-Text": typeof $response.body } });
