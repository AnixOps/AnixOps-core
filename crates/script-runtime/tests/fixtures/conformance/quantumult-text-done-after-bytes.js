// Reading `bodyBytes` does not change what `$done($response)` sends: the
// text body the script edited.
var length = $response.bodyBytes.byteLength;
$response.body = $response.body.toUpperCase() + length;
$done($response);
