// Response scripts read the request the response answers: "get cookie"
// scripts keep its Cookie or Authorization header.
$persistentStore.write($request.headers["Authorization"], "token");
$done({
  body: [$request.method, $request.url, $request.headers["Cookie"], $request.body, $response.status].join("|")
});
