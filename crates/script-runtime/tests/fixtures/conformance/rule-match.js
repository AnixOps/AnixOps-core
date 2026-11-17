// Rule script (Surge `SCRIPT,<name>,<policy>`): `$request` describes the
// connection, and only `$done({matched: true})` is a match.
var parts = [
  $script.type,
  typeof $response,
  $request.hostname,
  $request.destIP,
  $request.destPort,
  $request.sourceIP,
  $request.inPort,
  $request.processName,
  $request.protocol,
  $request.userAgent,
  $argument
];
$notification.post("rule", "", parts.join(","));
$done({ matched: $request.hostname.endsWith(".corp.example") && $request.destPort === 443 });
