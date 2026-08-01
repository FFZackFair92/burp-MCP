"""
Mock del ponte HTTP di Burp, per test locali senza avviare Burp.

Riproduce ESATTAMENTE il contratto di BridgeServer.java:
  - richiede l'header  X-Burp-Token: <token>  (altrimenti 401)
  - GET /ping -> 200 {"status":"ok","product":...,"version":...,"edition":...}

Uso standalone:
  python mock_burp.py            # porta 9876, token "changeme"
  python mock_burp.py 9999 segreto
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_handler(token: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silenzia il logging su stderr
            pass

        def _send(self, code: int, payload: dict):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.headers.get("X-Burp-Token") != token:
                self._send(401, {"error": "unauthorized"})
                return
            if self.path == "/ping":
                self._send(200, {
                    "status": "ok",
                    "product": "Burp Suite Community Edition",
                    "version": "2026.4.0",
                    "edition": "COMMUNITY_EDITION",
                })
            else:
                self._send(404, {"error": "not found"})

    return Handler


def serve(port: int = 9876, token: str = "changeme") -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(token))
    return httpd


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 9876
    t = sys.argv[2] if len(sys.argv) > 2 else "changeme"
    server = serve(p, t)
    print(f"Mock Burp bridge su http://127.0.0.1:{p} (token: {t})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
