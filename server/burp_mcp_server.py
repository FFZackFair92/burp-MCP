"""
Server MCP (FastMCP) per Burp — Fase 1: il ponte.

Espone a Claude Desktop un solo strumento, burp_status(), che verifica la
connessione all'estensione "Burp MCP Bridge" tramite il suo endpoint /ping.

Configurazione via variabili d'ambiente (con default sensati):
  BURP_BRIDGE_URL    -> URL del ponte HTTP        (default http://127.0.0.1:9876)
  BURP_BRIDGE_TOKEN  -> token condiviso           (default "changeme")
  BURP_BRIDGE_TIMEOUT-> timeout richieste, secondi (default 10)

I comandi veri (proxy history, sitemap, repeater, ...) verranno aggiunti qui
come nuovi @mcp.tool una volta che il ponte e' confermato funzionante.
"""

import os

import httpx
from fastmcp import FastMCP

BRIDGE_URL = os.environ.get("BURP_BRIDGE_URL", "http://127.0.0.1:9876").rstrip("/")
BRIDGE_TOKEN = os.environ.get("BURP_BRIDGE_TOKEN", "changeme")
TIMEOUT = float(os.environ.get("BURP_BRIDGE_TIMEOUT", "10"))

mcp = FastMCP("burp-mcp")


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=BRIDGE_URL,
        headers={"X-Burp-Token": BRIDGE_TOKEN},
        timeout=TIMEOUT,
        # Il ponte e' su loopback: mai passare da un eventuale proxy di sistema.
        trust_env=False,
    )


def _get(path: str) -> dict:
    """GET verso il ponte. Solleva per status >= 400."""
    with _client() as client:
        resp = client.get(path)
        resp.raise_for_status()
        return resp.json()


@mcp.tool
def burp_status() -> dict:
    """Verifica la connessione al ponte HTTP dell'estensione Burp.

    Ritorna un dizionario con:
      - reachable: True/False
      - bridge_url: URL contattato
      - se raggiungibile: product, version, edition di Burp
      - se non raggiungibile: error con una spiegazione leggibile
    """
    try:
        data = _get("/ping")
        return {"reachable": True, "bridge_url": BRIDGE_URL, **data}
    except httpx.ConnectError:
        return {
            "reachable": False,
            "bridge_url": BRIDGE_URL,
            "error": "Connessione rifiutata: l'estensione non e' caricata in Burp "
                     "oppure la porta e' sbagliata.",
        }
    except httpx.TimeoutException:
        return {
            "reachable": False,
            "bridge_url": BRIDGE_URL,
            "error": f"Timeout dopo {TIMEOUT}s contattando il ponte.",
        }
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code
        hint = "Token errato: controlla BURP_BRIDGE_TOKEN e il token in Burp." \
            if code == 401 else f"Risposta HTTP {code} dal ponte."
        return {"reachable": False, "bridge_url": BRIDGE_URL, "error": hint}
    except Exception as exc:  # pragma: no cover - rete/parsing imprevisti
        return {
            "reachable": False,
            "bridge_url": BRIDGE_URL,
            "error": f"{type(exc).__name__}: {exc}",
        }


if __name__ == "__main__":
    # Trasporto stdio: e' quello che usa Claude Desktop.
    mcp.run()
