"""
Test locale Fase 4 (senza Burp): proxy intercept, comparer, organizer,
sitemap add/issues, websocket history, project, storage config.
Avvia il mock esteso ed esercita i tool via client MCP.

Eseguire:  python test_fase4.py
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
        expected = {"proxy_intercept", "comparer_send", "organizer_send", "organizer_list",
                    "sitemap_add", "sitemap_issues", "websocket_history", "get_ws_message",
                    "project_info", "config_get", "config_set", "config_delete", "config_keys"}
        assert expected <= names, f"tool mancanti: {expected - names}"
        print("  [ok] tool Fase 4 esposti:", ", ".join(sorted(expected)))

        # proxy intercept: status -> enable -> disable
        d = _extract(await c.call_tool("proxy_intercept", {"action": "status"}))
        assert d.get("intercept_enabled") is False, d
        d = _extract(await c.call_tool("proxy_intercept", {"action": "enable"}))
        assert d.get("intercept_enabled") is True, d
        d = _extract(await c.call_tool("proxy_intercept", {}))
        assert d.get("intercept_enabled") is True, d
        d = _extract(await c.call_tool("proxy_intercept", {"action": "disable"}))
        assert d.get("intercept_enabled") is False, d
        d = _extract(await c.call_tool("proxy_intercept", {"action": "boh"}))
        assert "error" in d, d
        print("  [ok] proxy_intercept (status/enable/disable + validazione)")

        # comparer: da testo e da indici
        d = _extract(await c.call_tool("comparer_send", {"items": ["aaa", "bbb"]}))
        assert d.get("sent") == 2 and d.get("failed") == 0, d
        d = _extract(await c.call_tool("comparer_send",
                                       {"source": "proxy", "indices": [0, 1], "part": "response"}))
        assert d.get("sent") == 2, d
        d = _extract(await c.call_tool("comparer_send", {}))
        assert "error" in d, d
        print("  [ok] comparer_send (testo + indici + validazione)")

        # organizer: send (no scope-guard) + list
        d = _extract(await c.call_tool("organizer_send", {"url": "http://evil.com/x"}))
        assert d.get("sent") is True and d.get("target") == "organizer", d
        d = _extract(await c.call_tool("organizer_send", {"url": "http://example.com/y"}))
        assert d.get("sent") is True, d
        d = _extract(await c.call_tool("organizer_list", {}))
        assert d.get("count") == 2 and len(d["items"]) == 2, d
        print("  [ok] organizer_send (no scope-guard) + organizer_list")

        # sitemap add + issues
        d = _extract(await c.call_tool("sitemap_add", {"index": 1, "source": "proxy"}))
        assert d.get("added") is True, d
        d = _extract(await c.call_tool("sitemap_issues", {}))
        assert d.get("total") == 0 and d.get("items") == [], d
        print("  [ok] sitemap_add + sitemap_issues")

        # websocket history + message
        d = _extract(await c.call_tool("websocket_history", {}))
        assert d.get("count") == 2 and d["items"][0]["length"] == 5, d
        d = _extract(await c.call_tool("websocket_history", {"host": "example.com"}))
        assert d.get("count") == 2, d
        d = _extract(await c.call_tool("get_ws_message", {"index": 1}))
        assert d.get("payload") == "world" and d.get("direction") == "SERVER_TO_CLIENT", d
        print("  [ok] websocket_history + get_ws_message")

        # project
        d = _extract(await c.call_tool("project_info", {}))
        assert d.get("name") and d.get("id"), d
        print("  [ok] project_info")

        # storage: set/get/keys/delete su project e global
        d = _extract(await c.call_tool("config_set", {"key": "note", "value": "ciao", "scope": "project"}))
        assert d.get("saved") is True, d
        d = _extract(await c.call_tool("config_get", {"key": "note", "scope": "project"}))
        assert d.get("exists") is True and d.get("value") == "ciao", d
        d = _extract(await c.call_tool("config_get", {"key": "note", "scope": "global"}))
        assert d.get("exists") is False, d  # scope separati
        d = _extract(await c.call_tool("config_set", {"key": "g", "value": "1", "scope": "global"}))
        assert d.get("saved") is True, d
        d = _extract(await c.call_tool("config_keys", {"scope": "project"}))
        assert "note" in d["keys"], d
        d = _extract(await c.call_tool("config_delete", {"key": "note", "scope": "project"}))
        assert d.get("deleted") is True, d
        d = _extract(await c.call_tool("config_get", {"key": "note", "scope": "project"}))
        assert d.get("exists") is False, d
        print("  [ok] config_set/get/keys/delete (scope project|global separati)")


def main():
    httpd = mock_burp.serve(PORT, TOKEN)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"Mock Burp (Fase 4) su 127.0.0.1:{PORT}")
    try:
        asyncio.run(run())
        print("\nTUTTI I TEST FASE 4 PASSATI ✔")
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
