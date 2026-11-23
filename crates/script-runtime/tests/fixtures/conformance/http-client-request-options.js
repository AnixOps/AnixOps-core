// A Uint8Array body goes out as its bytes; `auto-redirect: false` turns
// redirects off (they are followed by default).
$httpClient.post(
  { url: "https://stub.example.test/echo", body: new Uint8Array([0, 255, 16]), "auto-redirect": false },
  function (error, response, off) {
    $httpClient.post({ url: "https://stub.example.test/echo", body: "x" }, function (error2, response2, on) {
      $done({ body: off + "\n" + on });
    });
  }
);
