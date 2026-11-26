#!/usr/bin/env python3
"""A stand-in for Control's device API, for the device service smoke test.

Serves HTTPS on 127.0.0.1 (certificate for "localhost") and answers the
device without the Agent (docs/deploy/mesh-device.md) the way the panel
does, with no networks:

- POST /api/v5/mesh/device/enroll: 201 for the credential mse_ci-smoke.
- GET /api/v5/mesh/device/config: 200 {"data":{"networks":[]}}.
- POST /api/v5/mesh/device/report: 204.

Config and report need the device token; while the file DIR/revoke exists
both answer 401, as for a revoked device. Each request is counted in
DIR/<kind>.count. The port is written to DIR/port once the server listens.

    mesh-device-mock-control.py --cert LEAF.pem --key LEAF.key --dir DIR
"""

import argparse
import http.server
import json
import os
import ssl
import sys

CREDENTIAL = "mse_ci-smoke"
TOKEN = "msd_ci-smoke-token"
DEVICE_ID = 5


def count(directory, kind):
    path = os.path.join(directory, kind + ".count")
    try:
        with open(path, encoding="ascii") as handle:
            value = int(handle.read().strip() or "0")
    except FileNotFoundError:
        value = 0
    with open(path, "w", encoding="ascii") as handle:
        handle.write(str(value + 1))


def handler(directory):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # noqa: N802 - stdlib name
            sys.stderr.write("mock-control: " + (fmt % args) + "\n")

        def answer(self, status, body=None):
            data = b"" if body is None else json.dumps(body).encode()
            self.send_response(status)
            if body is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def body(self):
            length = int(self.headers.get("Content-Length") or "0")
            return json.loads(self.rfile.read(length) or b"null")

        def authorized(self):
            if os.path.exists(os.path.join(directory, "revoke")):
                return False
            return self.headers.get("Authorization") == "Bearer " + TOKEN

        def do_POST(self):  # noqa: N802 - stdlib name
            if self.path == "/api/v5/mesh/device/enroll":
                count(directory, "enroll")
                request = self.body()
                if request.get("token") != CREDENTIAL or not request.get("device_key"):
                    self.answer(401, {"error": {"code": "unauthorized"}})
                    return
                self.answer(
                    201,
                    {
                        "data": {
                            "device_id": DEVICE_ID,
                            "device_token": TOKEN,
                            "config": {"networks": []},
                        }
                    },
                )
            elif self.path == "/api/v5/mesh/device/report":
                count(directory, "report")
                self.body()
                if not self.authorized():
                    self.answer(401, {"error": {"code": "unauthorized"}})
                    return
                self.answer(204)
            else:
                self.answer(404, {"error": {"code": "not_found"}})

        def do_GET(self):  # noqa: N802 - stdlib name
            if self.path.split("?", 1)[0] == "/api/v5/mesh/device/config":
                count(directory, "config")
                if not self.authorized():
                    self.answer(401, {"error": {"code": "unauthorized"}})
                    return
                self.answer(200, {"data": {"networks": []}})
            else:
                self.answer(404, {"error": {"code": "not_found"}})

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--dir", required=True)
    args = parser.parse_args()
    os.makedirs(args.dir, exist_ok=True)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler(args.dir))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    with open(os.path.join(args.dir, "port"), "w", encoding="ascii") as handle:
        handle.write(str(server.server_address[1]))
    server.serve_forever()


if __name__ == "__main__":
    main()
