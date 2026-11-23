// A script that changes the joined Set-Cookie value gets one field with
// exactly what it returned.
var headers = $response.headers;
headers["Set-Cookie"] = "only=1";
$done({ headers: headers });
