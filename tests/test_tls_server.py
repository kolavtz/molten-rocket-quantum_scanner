"""
Minimal TLS test server for verifying private-IP scanning.

Runs an HTTPS server on 127.0.0.1:4443 using a self-signed certificate.
This lets us prove the QuantumShield scanner works on localhost/private IPs.

Usage:
    python tests/test_tls_server.py
    # Then scan 127.0.0.1:4443 via the web UI
"""

import http.server
import ssl
import os
import sys

PORT = 4443
CERT = os.path.join(os.path.dirname(__file__), "test_cert.pem")
KEY  = os.path.join(os.path.dirname(__file__), "test_key.pem")


class TestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>QuantumShield Test TLS Server</h1>"
                         b"<p>This server is running on a private IP for scan verification.</p>")

    def log_message(self, fmt, *args):
        print(f"[TLS-TEST] {args[0]}")


def main():
    if not os.path.exists(CERT) or not os.path.exists(KEY):
        print("ERROR: test_cert.pem and test_key.pem not found in tests/")
        print("Generate them first with the cryptography library.")
        sys.exit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)

    server = http.server.HTTPServer(("127.0.0.1", PORT), TestHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"TLS test server running on https://127.0.0.1:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")


if __name__ == "__main__":
    main()
