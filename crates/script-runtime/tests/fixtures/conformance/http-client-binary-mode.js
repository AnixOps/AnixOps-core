// Surge `binary-mode`: the callback's data is a Uint8Array of the bytes as
// sent, never text with U+FFFD in place of bytes that are not UTF-8.
$httpClient.get({ url: "https://stub.example.test/bytes", "binary-mode": true }, function (error, response, data) {
  var text = "";
  $httpClient.get("https://stub.example.test/bytes", function (error2, response2, plain) {
    text = plain;
    $done({
      body: (data instanceof Uint8Array) + ":" + Array.prototype.join.call(data, ",") +
        ":" + (typeof text) + ":" + text.length
    });
  });
});
