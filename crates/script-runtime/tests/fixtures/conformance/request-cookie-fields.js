// Split Cookie fields read as one cookie list joined with "; ", and come
// back as the original fields when the script leaves them alone.
var headers = $request.headers;
headers["X-Cookie-Seen"] = headers["cookie"];
$done({ headers: headers });
