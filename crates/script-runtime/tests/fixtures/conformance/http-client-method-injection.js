// A method that is not an HTTP token (here with CR LF, which would end the
// request line and smuggle commands) is refused by the host before any
// request is made; the stub client would have answered /echo.
$task.fetch({ url: "https://stub.example.test/echo", method: "FLUSHALL\r\nQUIT\r\nX" }).then(
  function (response) {
    $done({ body: "resolved:" + response.body });
  },
  function (reason) {
    $done({ body: "rejected:" + reason.error });
  }
);
