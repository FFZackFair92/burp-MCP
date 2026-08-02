"""
Test locale Fase 3 (senza Burp): send_to_repeater/intruder, compare_responses,
utilities encode/decode/hash. Avvia il mock esteso ed esercita i tool via client MCP.

Eseguire:  python test_fase3.py
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
        expected = {"send_to_repeater", "send_to_intruder", "compare_responses",
                    "encode", "decode", "hash_text"}
        assert expected <= names, f"tool mancanti: {expected - names}"
        print("  [ok] tool Fase 3 esposti:", ", ".join(sorted(expected)))

        d = _extract(await c.call_tool("send_to_repeater", {"url": "http://example.com/a"}))
        assert d.get("sent") is True and d.get("target") == "repeater", d
        d = _extract(await c.call_tool("send_to_repeater", {"url": "http://evil.com/a"}))
        assert d.get("error") == "out_of_scope", d
        d = _extract(await c.call_tool("send_to_repeater", {"url": "http://evil.com/a", "force": True}))
        assert d.get("sent") is True, d
        print("  [ok] send_to_repeater (scope-guard + force)")

        d = _extract(await c.call_tool("send_to_intruder", {"url": "http://example.com/a"}))
        assert d.get("sent") is True and d.get("target") == "intruder", d
        print("  [ok] send_to_intruder")

        d = _extract(await c.call_tool("compare_responses", {"index_a": 0, "index_b": 1}))
        assert d.get("equal") is False and "ok-0" in d["diff"] and "ok-1" in d["diff"], d
        d = _extract(await c.call_tool("compare_responses", {"index_a": 2, "index_b": 2}))
        assert d.get("equal") is True, d
        print("  [ok] compare_responses (diff + uguaglianza)")

        # utilities round-trip
        for scheme in ("base64", "url", "url_plus", "hex", "html", "gzip_b64"):
            enc = _extract(await c.call_tool("encode", {"data": "a=<b> & c/1", "scheme": scheme}))
            dec = _extract(await c.call_tool("decode", {"data": enc["output"], "scheme": scheme}))
            assert dec["output"] == "a=<b> & c/1", (scheme, enc, dec)
        print("  [ok] encode/decode round-trip su tutti gli scheme")

        h = _extract(await c.call_tool("hash_text", {"data": "abc", "algo": "sha256"}))
        assert h["hex"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", h
        print("  [ok] hash_text sha256('abc') corretto")


def main():
    httpd = mock_burp.serve(PORT, TOKEN)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"Mock Burp (Fase 3) su 127.0.0.1:{PORT}")
    try:
        asyncio.run(run())
        print("\nTUTTI I TEST FASE 3 PASSATI ✔")
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
