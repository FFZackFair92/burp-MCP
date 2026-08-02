"""
Mock del ponte HTTP di Burp, per test locali senza avviare Burp.

Riproduce il contratto di BridgeServer.java + Commands.java (Fase 2):
  - richiede l'header  X-Burp-Token: <token>  (altrimenti 401)
  - GET  /ping
  - GET  /scope/check?url=       -> {"url","in_scope"}   (in scope se host termina in example.com)
  - POST /scope/add|remove?url=
  - GET  /proxy/history          -> {"items":[...],"count","total_matched","offset"}
  - GET  /sitemap                -> come sopra
  - GET  /message?source&index   -> {"request","response",...}
  - POST /http/send?host&port&secure&force  (body = raw request)
                                 -> 403 out_of_scope se host non in scope e force!=true

Uso standalone:  python mock_burp.py [porta] [token]
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs


def _in_scope(host: str) -> bool:
    return bool(host) and host.lower().endswith("example.com")


def make_handler(token: str):
    # stato in-memory condiviso tra le richieste (per i test Fase 4)
    state = {"intercept": False}
    storage = {"project": {}, "global": {}}
    organizer = []  # [{"id","status"}]
    collab = {"active": False, "server": "polling.burpcollaborator.net", "next_id": 1, "interactions": []}
    ws_msgs = [
        {"index": 0, "ws_id": 1, "direction": "CLIENT_TO_SERVER", "listener_port": 8080,
         "url": "http://example.com/ws", "host": "example.com", "payload": "hello"},
        {"index": 1, "ws_id": 1, "direction": "SERVER_TO_CLIENT", "listener_port": 8080,
         "url": "http://example.com/ws", "host": "example.com", "payload": "world"},
    ]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code: int, payload: dict):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _auth_ok(self) -> bool:
            return self.headers.get("X-Burp-Token") == token

        def _query(self):
            return {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}

        def _path(self):
            return urlsplit(self.path).path

        def _read_body(self) -> str:
            n = int(self.headers.get("Content-Length", "0") or "0")
            return self.rfile.read(n).decode("utf-8", "replace") if n else ""

        # ---- GET ----
        def do_GET(self):
            if not self._auth_ok():
                return self._send(401, {"error": "unauthorized"})
            path, q = self._path(), self._query()

            if path == "/ping":
                return self._send(200, {
                    "status": "ok", "product": "Burp Suite Community Edition",
                    "version": "2026.4.0", "edition": "COMMUNITY_EDITION",
                })
            if path == "/scope/check":
                url = q.get("url", "")
                return self._send(200, {"url": url, "in_scope": _in_scope(urlsplit(url).hostname or "")})
            if path in ("/proxy/history", "/sitemap"):
                items = [
                    {"index": 0, "method": "GET", "url": "http://example.com/",
                     "host": "example.com", "status": 200, "length": 120, "mime": "HTML"},
                    {"index": 1, "method": "POST", "url": "http://example.com/login",
                     "host": "example.com", "status": 302, "length": 0, "mime": "NONE"},
                ]
                host = q.get("host", "").lower()
                if host:
                    items = [it for it in items if host in it["host"].lower()]
                return self._send(200, {"total_matched": len(items), "count": len(items),
                                        "offset": int(q.get("offset", "0")), "items": items})
            if path == "/message":
                idx = int(q.get("index", "0"))
                return self._send(200, {
                    "source": q.get("source", "proxy"), "index": idx,
                    "truncated": False,
                    "request": f"GET /item/{idx} HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "response": f"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nok-{idx}",
                })

            # ---- Fase 4 ----
            if path == "/proxy/intercept":
                return self._send(200, {"intercept_enabled": state["intercept"]})
            if path == "/organizer/list":
                return self._send(200, {"count": len(organizer), "items": organizer})
            if path == "/sitemap/issues":
                return self._send(200, {"total": 0, "count": 0,
                                        "offset": int(q.get("offset", "0")), "items": []})
            if path == "/ws/history":
                items = [{k: m[k] for k in ("index", "ws_id", "direction",
                                            "listener_port", "url", "host")}
                         | {"length": len(m["payload"])} for m in ws_msgs]
                host = q.get("host", "").lower()
                if host:
                    items = [it for it in items if host in it["host"].lower()]
                return self._send(200, {"total_matched": len(items), "count": len(items),
                                        "offset": int(q.get("offset", "0")), "items": items})
            if path == "/ws/message":
                idx = int(q.get("index", "0"))
                if idx >= len(ws_msgs):
                    return self._send(404, {"error": "index fuori range (ws)"})
                m = ws_msgs[idx]
                return self._send(200, {"index": idx, "ws_id": m["ws_id"],
                                        "direction": m["direction"], "truncated": False,
                                        "payload": m["payload"]})
            if path == "/project":
                return self._send(200, {"name": "Temporary project", "id": "temp-1"})
            if path == "/storage/get":
                scope = q.get("scope", "project")
                key = q.get("key", "")
                d = storage.get(scope, {})
                return self._send(200, {"scope": scope, "key": key,
                                        "exists": key in d, "value": d.get(key)})
            if path == "/storage/keys":
                scope = q.get("scope", "project")
                d = storage.get(scope, {})
                return self._send(200, {"scope": scope, "count": len(d),
                                        "keys": list(d.keys())})

            # ---- Fase 5 ----
            if path == "/collaborator/status":
                return self._send(200, {"active": collab["active"],
                                        "server": collab["server"] if collab["active"] else None})
            if path == "/collaborator/interactions":
                items = collab["interactions"]
                idf = q.get("interaction_id", "")
                if idf:
                    items = [i for i in items if i["interaction_id"] == idf]
                limit = int(q.get("limit", "100"))
                return self._send(200, {"count": min(len(items), limit),
                                        "total": len(collab["interactions"]),
                                        "items": items[:limit]})
            if path == "/extension/info":
                return self._send(200, {"filename": "burp-mcp-bridge-0.1.0.jar", "is_bapp": False})
            return self._send(404, {"error": "not found"})

        # ---- POST ----
        def do_POST(self):
            if not self._auth_ok():
                return self._send(401, {"error": "unauthorized"})
            path, q = self._path(), self._query()
            body = self._read_body()

            if path in ("/scope/add", "/scope/remove"):
                key = "added" if path.endswith("add") else "removed"
                return self._send(200, {key: q.get("url", "")})

            if path == "/http/send":
                host = q.get("host", "")
                port = q.get("port", "0")
                secure = q.get("secure", "false") == "true"
                force = q.get("force", "false") == "true"
                default_port = "443" if secure else "80"
                netloc = host if port == default_port else f"{host}:{port}"
                # path dalla request-line della raw
                first = body.split("\r\n", 1)[0]
                req_path = first.split(" ")[1] if len(first.split(" ")) >= 2 else "/"
                url = f"{'https' if secure else 'http'}://{netloc}{req_path}"
                if not force and not _in_scope(host):
                    return self._send(403, {"error": "out_of_scope", "url": url,
                                            "hint": "usa force=true per inviare comunque"})
                return self._send(200, {
                    "url": url, "status": 200, "length": len(body), "mime": "HTML",
                    "time_ms": 1, "truncated": False,
                    "response": "HTTP/1.1 200 OK\r\n\r\n[echo]\r\n" + body,
                })

            if path in ("/repeater/send", "/intruder/send"):
                host = q.get("host", "")
                port = q.get("port", "0")
                secure = q.get("secure", "false") == "true"
                force = q.get("force", "false") == "true"
                default_port = "443" if secure else "80"
                netloc = host if port == default_port else f"{host}:{port}"
                first = body.split("\r\n", 1)[0]
                req_path = first.split(" ")[1] if len(first.split(" ")) >= 2 else "/"
                url = f"{'https' if secure else 'http'}://{netloc}{req_path}"
                if not force and not _in_scope(host):
                    return self._send(403, {"error": "out_of_scope", "url": url})
                target = "repeater" if path.endswith("repeater/send") else "intruder"
                return self._send(200, {"sent": True, "target": target, "url": url})

            # ---- Fase 4 ----
            if path == "/proxy/intercept/enable":
                state["intercept"] = True
                return self._send(200, {"intercept_enabled": True})
            if path == "/proxy/intercept/disable":
                state["intercept"] = False
                return self._send(200, {"intercept_enabled": False})
            if path == "/comparer/send":
                return self._send(200, {"sent": True, "target": "comparer", "length": len(body)})
            if path == "/organizer/send":
                host = q.get("host", "")
                port = q.get("port", "0")
                secure = q.get("secure", "false") == "true"
                default_port = "443" if secure else "80"
                netloc = host if port == default_port else f"{host}:{port}"
                first = body.split("\r\n", 1)[0]
                req_path = first.split(" ")[1] if len(first.split(" ")) >= 2 else "/"
                url = f"{'https' if secure else 'http'}://{netloc}{req_path}"
                organizer.append({"id": len(organizer) + 1, "status": "NEW"})
                return self._send(200, {"sent": True, "target": "organizer", "url": url})
            if path == "/sitemap/add":
                idx = int(q.get("index", "0"))
                return self._send(200, {"added": True,
                                        "url": f"http://example.com/item/{idx}"})
            if path == "/storage/set":
                scope = q.get("scope", "project")
                key = q.get("key", "")
                storage.setdefault(scope, {})[key] = body
                return self._send(200, {"scope": scope, "key": key,
                                        "saved": True, "length": len(body)})
            if path == "/storage/delete":
                scope = q.get("scope", "project")
                key = q.get("key", "")
                storage.get(scope, {}).pop(key, None)
                return self._send(200, {"scope": scope, "key": key, "deleted": True})

            # ---- Fase 5 ----
            if path == "/collaborator/generate":
                count = int(q.get("count", "1"))
                collab["active"] = True
                items = []
                for _ in range(count):
                    iid = f"int-{collab['next_id']}"
                    collab["next_id"] += 1
                    items.append({"payload": f"{iid}.{collab['server']}", "interaction_id": iid})
                    # simula un hit DNS immediato, cosi' i test possono esercitare il poll
                    collab["interactions"].append({
                        "interaction_id": iid, "type": "DNS",
                        "time": "2026-08-02T00:00:00Z[UTC]",
                        "client_ip": "203.0.113.5", "client_port": 53212,
                        "detail": "dns_query_type=A",
                    })
                return self._send(200, {"count": count, "server": collab["server"], "items": items})
            if path == "/collaborator/reset":
                collab.update(active=False, next_id=1, interactions=[])
                return self._send(200, {"reset": True})
            if path == "/dashboard/event":
                return self._send(200, {"logged": True, "level": q.get("level", "info")})
            if path == "/extension/log":
                return self._send(200, {"logged": True, "stream": q.get("stream", "output")})

            return self._send(404, {"error": "not found"})

    return Handler


def serve(port: int = 9876, token: str = "changeme") -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(token))


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 9876
    t = sys.argv[2] if len(sys.argv) > 2 else "changeme"
    server = serve(p, t)
    print(f"Mock Burp bridge su http://127.0.0.1:{p} (token: {t})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
