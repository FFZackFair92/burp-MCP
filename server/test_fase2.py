"""
Test locale Fase 2 (senza Burp): avvia il mock esteso ed esercita TUTTI i tool
MCP via client FastMCP in-memory, piu' unit test sulla costruzione della raw request.

Eseguire:  python test_fase2.py
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


def unit_build_raw():
    raw, host, port, secure = srv._build_raw_request(
        "POST", "http://example.com/api?x=1", {"X-Test": "1"}, "a=b")
    assert host == "example.com" and port == 80 and secure is False
    assert raw.startswith("POST /api?x=1 HTTP/1.1\r\n"), raw
    assert "Host: example.com\r\n" in raw
    assert "X-Test: 1\r\n" in raw
    assert "Content-Length: 3\r\n" in raw
    assert raw.endswith("\r\n\r\na=b")
    # https -> porta 443 non nell'header Host
    raw2, h2, p2, s2 = srv._build_raw_request("GET", "https://example.com/", None, "")
    assert p2 == 443 and s2 is True and "Host: example.com\r\n" in raw2
    print("  [ok] _build_raw_request (http/https, Host, Content-Length)")


async def tools():
    async with Client(srv.mcp) as c:
        names = {t.name for t in await c.list_tools()}
        expected = {"burp_status", "scope_check", "scope_add", "scope_remove",
                    "proxy_history", "sitemap", "get_message", "http_send"}
        assert expected <= names, f"tool mancanti: {expected - names}"
        print("  [ok] tool esposti:", ", ".join(sorted(expected)))

        d = _extract(await c.call_tool("scope_check", {"url": "http://example.com/x"}))
        assert d.get("in_scope") is True, d
        d = _extract(await c.call_tool("scope_check", {"url": "http://evil.com/x"}))
        assert d.get("in_scope") is False, d
        print("  [ok] scope_check in/out scope")

        d = _extract(await c.call_tool("proxy_history", {"host": "example.com"}))
        assert d.get("count") == 2 and d["items"][0]["index"] == 0, d
        print("  [ok] proxy_history -> {} voci".format(d["count"]))

        d = _extract(await c.call_tool("sitemap", {}))
        assert d.get("count") == 2, d
        print("  [ok] sitemap")

        d = _extract(await c.call_tool("get_message", {"index": 0, "source": "proxy"}))
        assert "request" in d and "response" in d, d
        print("  [ok] get_message")

        d = _extract(await c.call_tool("http_send", {
            "url": "http://example.com/api?x=1", "method": "POST",
            "headers": {"X-Test": "1"}, "body": "a=b"}))
        assert d.get("status") == 200, d
        assert "POST /api?x=1 HTTP/1.1" in d["response"], d
        assert "X-Test: 1" in d["response"] and "a=b" in d["response"], d
        print("  [ok] http_send (in scope) -> raw corretta, status", d["status"])

        d = _extract(await c.call_tool("http_send", {"url": "http://evil.com/"}))
        assert d.get("error") == "out_of_scope", d
        print("  [ok] http_send fuori scope -> bloccato dallo scope-guard")

        d = _extract(await c.call_tool("http_send", {"url": "http://evil.com/", "force": True}))
        assert d.get("status") == 200, d
        print("  [ok] http_send fuori scope + force=True -> inviata")


def main():
    httpd = mock_burp.serve(PORT, TOKEN)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"Mock Burp (Fase 2) su 127.0.0.1:{PORT}")
    try:
        unit_build_raw()
        asyncio.run(tools())
        print("\nTUTTI I TEST FASE 2 PASSATI ✔")
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
