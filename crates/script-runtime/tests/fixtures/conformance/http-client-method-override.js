// A script that replaces String.prototype.toUpperCase controls the method
// the prelude sends even for $httpClient.get; the host still refuses it.
String.prototype.toUpperCase = function () {
  return "GET / HTTP/1.1\r\nHost: x\r\n\r\nGET";
};
$httpClient.get({ url: "https://stub.example.test/echo" }, function (error, response, data) {
  $done({ body: error ? "error:" + error : "ok:" + data });
});
