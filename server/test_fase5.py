"""
Test locale Fase 5 (senza Burp): Collaborator, Dashboard event log, Extensions
output/info. Avvia il mock esteso ed esercita i tool via client MCP.

Eseguire:  python test_fase5.py
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
        expected = {"collaborator_status", "collaborator_generate", "collaborator_interactions",
                    "collaborator_reset", "dashboard_event", "extension_log", "extension_info"}
        assert expected <= names, f"tool mancanti: {expected - names}"
        print("  [ok] tool Fase 5 esposti:", ", ".join(sorted(expected)))

        # collaborator: inattivo finche' non si genera un payload
        d = _extract(await c.call_tool("collaborator_status", {}))
        assert d.get("active") is False, d

        d = _extract(await c.call_tool("collaborator_generate", {"count": 2}))
        assert d.get("count") == 2 and len(d["items"]) == 2, d
        assert all("payload" in it and "interaction_id" in it for it in d["items"]), d
        iid_a = d["items"][0]["interaction_id"]
        iid_b = d["items"][1]["interaction_id"]
        print("  [ok] collaborator_generate (2 payload)")

        d = _extract(await c.call_tool("collaborator_status", {}))
        assert d.get("active") is True and d.get("server"), d
        print("  [ok] collaborator_status (attivo dopo generate)")

        # ogni payload generato dal mock produce un hit DNS immediato (per esercitare il poll)
        d = _extract(await c.call_tool("collaborator_interactions", {}))
        assert d.get("total") == 2 and len(d["items"]) == 2, d
        d = _extract(await c.call_tool("collaborator_interactions", {"interaction_id": iid_a}))
        assert len(d["items"]) == 1 and d["items"][0]["interaction_id"] == iid_a, d
        assert d["items"][0]["type"] == "DNS", d
        print("  [ok] collaborator_interactions (tutte + filtro per interaction_id)")

        d = _extract(await c.call_tool("collaborator_reset", {}))
        assert d.get("reset") is True, d
        d = _extract(await c.call_tool("collaborator_status", {}))
        assert d.get("active") is False, d
        d = _extract(await c.call_tool("collaborator_interactions", {}))
        assert d.get("total") == 0, d
        print("  [ok] collaborator_reset (svuota client e interazioni)")

        # dashboard event log
        d = _extract(await c.call_tool("dashboard_event", {"message": "smoke test", "level": "info"}))
        assert d.get("logged") is True and d.get("level") == "info", d
        d = _extract(await c.call_tool("dashboard_event", {"message": "boom", "level": "critical"}))
        assert d.get("logged") is True and d.get("level") == "critical", d
        print("  [ok] dashboard_event (info + critical)")

        # extensions: output/error log + info
        d = _extract(await c.call_tool("extension_log", {"message": "ciao", "stream": "output"}))
        assert d.get("logged") is True and d.get("stream") == "output", d
        d = _extract(await c.call_tool("extension_log", {"message": "errore", "stream": "error"}))
        assert d.get("stream") == "error", d
        d = _extract(await c.call_tool("extension_info", {}))
        assert d.get("filename") and "is_bapp" in d, d
        print("  [ok] extension_log (output/error) + extension_info")


def main():
    httpd = mock_burp.serve(PORT, TOKEN)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"Mock Burp (Fase 5) su 127.0.0.1:{PORT}")
    try:
        asyncio.run(run())
        print("\nTUTTI I TEST FASE 5 PASSATI ✔")
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
