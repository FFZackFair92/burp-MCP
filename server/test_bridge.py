"""
Test locale del ponte, senza Burp.

Avvia il mock (mock_burp.py), poi:
  1) esercita il server MCP vero via client FastMCP in-memory (protocollo MCP
     completo: list_tools + call_tool burp_status) sul percorso "felice";
  2) verifica i percorsi d'errore (token errato -> 401, connessione rifiutata).

Eseguire:  python test_bridge.py
"""

import asyncio
import os
import threading

PORT = 9876
TOKEN = "changeme"

# Configura l'ambiente PRIMA di importare il server (legge le env all'import).
os.environ["BURP_BRIDGE_URL"] = f"http://127.0.0.1:{PORT}"
os.environ["BURP_BRIDGE_TOKEN"] = TOKEN
os.environ["BURP_BRIDGE_TIMEOUT"] = "5"

import mock_burp                      # noqa: E402
import burp_mcp_server as srv         # noqa: E402
from fastmcp import Client            # noqa: E402


def _extract(result):
    """Ricava il dict dal risultato di call_tool, robusto tra versioni FastMCP."""
    for attr in ("data", "structured_content"):
        val = getattr(result, attr, None)
        if isinstance(val, dict):
            return val
    return result


async def happy_path_via_mcp():
    async with Client(srv.mcp) as client:
        tools = await client.list_tools()
        names = [t.name for t in tools]
        assert "burp_status" in names, f"tool mancante: {names}"

        result = await client.call_tool("burp_status", {})
        data = _extract(result)
        assert data.get("reachable") is True, data
        assert "Community" in data.get("product", ""), data
        print("  [ok] MCP call_tool burp_status -> reachable, product:",
              data.get("product"), "| version:", data.get("version"))


def error_paths():
    # Token errato -> 401 gestito
    srv.BRIDGE_TOKEN = "sbagliato"
    d = srv.burp_status()
    assert d["reachable"] is False and "Token" in d["error"], d
    print("  [ok] token errato -> 401 gestito:", d["error"])
    srv.BRIDGE_TOKEN = TOKEN

    # Porta chiusa -> connessione rifiutata gestita
    srv.BRIDGE_URL = "http://127.0.0.1:9"
    d = srv.burp_status()
    assert d["reachable"] is False and "rifiutata" in d["error"], d
    print("  [ok] porta chiusa -> connessione rifiutata gestita")
    srv.BRIDGE_URL = f"http://127.0.0.1:{PORT}"


def main():
    httpd = mock_burp.serve(PORT, TOKEN)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    print(f"Mock Burp avviato su 127.0.0.1:{PORT}")
    try:
        asyncio.run(happy_path_via_mcp())
        error_paths()
        print("\nTUTTI I TEST PASSATI ✔")
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
