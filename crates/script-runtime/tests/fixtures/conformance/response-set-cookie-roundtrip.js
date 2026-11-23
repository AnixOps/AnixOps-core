// A script that only removes one response header hands the rest back as it
// read them; the three Set-Cookie fields (one with a comma in Expires) must
// stay three fields, not one joined value.
var headers = $response.headers;
delete headers["Content-Security-Policy"];
$done({ headers: headers });
