"""
Test locale Fase 6 (senza Burp): opzioni di progetto/utente, task engine, editor
attivo, HTTP/2 in http_send, regex sul contenuto della proxy history, random_string.
Avvia il mock esteso ed esercita i tool via client MCP.

Eseguire:  python test_fase6.py
"""

import asyncio
import os
import threading

PORT = 9876
TOKEN = "changeme"

os.environ["BURP_BRIDGE_URL"] = f"http://127.0.0.1:{PORT}"
os.environ["BURP_BRIDGE_TOKEN"] = TOKEN
os.environ["BURP_BRIDGE_TIMEOUT"] = "5"

import mock_burp                      # noqa: E402
import burp_mcp_server as srv         # noqa: E402
from fastmcp import Client            # noqa: E402


def _extract(result):
    for attr in ("data", "structured_content"):
        val = getattr(result, attr, None)
        if isinstance(val, dict):
            return val
    return result


async def run():
    async with Client(srv.mcp) as c:
        names = {t.name for t in await c.list_tools()}
        expected = {"burp_options_get", "burp_options_set", "task_engine",
                    "editor_get", "editor_set", "random_string"}
        assert expected <= names, f"tool mancanti: {expected - names}"
        print("  [ok] tool Fase 6 esposti:", ", ".join(sorted(expected)))

        # opzioni: export con redazione delle credenziali
        d = _extract(await c.call_tool("burp_options_get", {"scope": "project"}))
        up = d["options"]["project_options"]["connections"]["upstream_proxy"]
        assert up["password"] == "***", d
        d = _extract(await c.call_tool("burp_options_get", {"scope": "project", "redact": False}))
        assert d["options"]["project_options"]["connections"]["upstream_proxy"]["password"] == "segreta", d
        print("  [ok] burp_options_get (redazione password)")

        new = {"project_options": {"target": {"scope": {"include": [{"host": "example.com"}]}}}}
        d = _extract(await c.call_tool("burp_options_set", {"options": new}))
        assert d.get("confirm_required") is True, d
        d = _extract(await c.call_tool("burp_options_set", {"options": {"wrong": {}}, "confirm": True}))
        assert "error" in d, d
        d = _extract(await c.call_tool("burp_options_set", {"options": new, "confirm": True}))
        assert d.get("applied") is True, d
        d = _extract(await c.call_tool("burp_options_get", {}))
        assert d["options"]["project_options"]["target"]["scope"]["include"][0]["host"] == "example.com", d
        print("  [ok] burp_options_set (conferma, radice, applicazione)")

        # task engine
        d = _extract(await c.call_tool("task_engine", {}))
        assert d.get("state") == "RUNNING", d
        d = _extract(await c.call_tool("task_engine", {"action": "pause"}))
        assert d.get("state") == "PAUSED", d
        d = _extract(await c.call_tool("task_engine", {"action": "resume"}))
        assert d.get("state") == "RUNNING", d
        print("  [ok] task_engine (status/pause/resume)")

        # editor attivo
        d = _extract(await c.call_tool("editor_get", {}))
        assert "Host: example.com" in d.get("text", ""), d
        d = _extract(await c.call_tool("editor_set", {"text": "POST /x HTTP/1.1\r\n\r\n"}))
        assert d.get("set") is True, d
        d = _extract(await c.call_tool("editor_get", {}))
        assert d["text"].startswith("POST /x"), d
        print("  [ok] editor_get / editor_set")

        # http_send con HTTP/2
        d = _extract(await c.call_tool("http_send", {"url": "https://example.com/", "http_mode": "http2"}))
        assert d.get("mode") == "HTTP_2" and d.get("status") == 200, d
        d = _extract(await c.call_tool("http_send", {"url": "https://example.com/", "http_mode": "boh"}))
        assert "error" in d, d
        print("  [ok] http_send http_mode (http2 + errore su modo sconosciuto)")

        # proxy history: regex sul contenuto
        d = _extract(await c.call_tool("proxy_history", {"content_regex": "^POST"}))
        assert d.get("count") == 1 and d["items"][0]["method"] == "POST", d
        print("  [ok] proxy_history content_regex")

        # random_string (lato server MCP, nessuna chiamata al ponte)
        d = _extract(await c.call_tool("random_string", {"length": 24, "charset": "hex"}))
        assert len(d["value"]) == 24 and set(d["value"]) <= set("0123456789abcdef"), d
        print("  [ok] random_string")


def main():
    httpd = mock_burp.serve(PORT, TOKEN)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"Mock Burp (Fase 6) su 127.0.0.1:{PORT}")
    try:
        asyncio.run(run())
        print("\nTUTTI I TEST FASE 6 PASSATI ✔")
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
