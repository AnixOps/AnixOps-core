// Anything other than `matched: true` is no match, and the body or response
// a rule script passes changes nothing.
$done({ matched: "yes", body: "ignored", response: { status: 500 } });
