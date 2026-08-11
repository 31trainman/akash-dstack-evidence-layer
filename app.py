#!/usr/bin/env python3
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.getenv("PORT", "8080"))
IMAGE_ID = os.getenv("IMAGE_ID", "UNPINNED")
CONFIG_ID = os.getenv("CONFIG_ID", "akash-dstack-poc-v0.2")

def identity():
    material = json.dumps(
        {"image": IMAGE_ID, "config": CONFIG_ID, "tee": "cpu-gpu"},
        sort_keys=True,
    ).encode()
    return {
        "service": "akash-dstack-evidence-layer",
        "version": "0.2",
        "tee_requested": "cpu-gpu",
        "image_id": IMAGE_ID,
        "config_id": CONFIG_ID,
        "workload_identity_sha256": hashlib.sha256(material).hexdigest(),
        "secret_state": "LOCKED",
        "policy": "DENY_UNTIL_REMOTE_ATTESTATION_AND_WORKLOAD_BINDING",
    }

class Handler(BaseHTTPRequestHandler):
    def send_json(self, code, payload):
        body = json.dumps(payload, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {"status": "ok", "secret_state": "LOCKED"})
        elif self.path == "/identity":
            self.send_json(200, identity())
        elif self.path == "/":
            self.send_json(200, {
                "name": "Akash → dstack evidence-layer PoC",
                "endpoints": ["/health", "/identity"],
                "warning": "No KMS master secret is stored in this workload."
            })
        else:
            self.send_json(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)

if __name__ == "__main__":
    print(json.dumps(identity(), indent=2), flush=True)
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
