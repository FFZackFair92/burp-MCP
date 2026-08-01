# Burp MCP — ponte + server MCP per Claude Desktop

MCP server per pilotare **Burp Suite (Community)** da Claude Desktop.

Architettura:

```
Claude Desktop  <--stdio-->  server MCP (Python/FastMCP)  <--HTTP loopback-->  estensione Burp (Montoya)
                              server/burp_mcp_server.py                          extension/  (BridgeServer.java)
```

## Stato: Fase 1 — il ponte ✅

È implementata solo la **connessione**: l'estensione apre un server HTTP locale
con l'endpoint `GET /ping`; il server MCP espone lo strumento `burp_status()` che
lo interroga. I comandi veri (proxy history, sitemap, repeater, …) arrivano dopo.

Contratto del ponte:

| Metodo | Path   | Auth (header)              | Risposta 200 |
|--------|--------|----------------------------|--------------|
| GET    | /ping  | `X-Burp-Token: <token>`    | `{"status":"ok","product":...,"version":...,"edition":...}` |

Senza token valido → `401`.

---

## 1) Estensione Burp (il ponte)

Serve un JDK (17+). Da `extension/`:

```bash
gradle jar          # oppure: ./gradlew jar  se generi il wrapper
```

Produce `extension/build/libs/burp-mcp-bridge-0.1.0.jar`.

Caricala in Burp: **Extensions → Installed → Add → Extension type: Java →**
seleziona il `.jar`. Nel tab **Output** dovresti vedere:

```
[Burp MCP Bridge] In ascolto su http://127.0.0.1:9876
[Burp MCP Bridge] Token (X-Burp-Token): changeme
```

Config opzionale (system property o variabile d'ambiente):
`BURP_MCP_PORT` (default 9876), `BURP_MCP_TOKEN` (default `changeme`).

## 2) Server MCP (Python)

```bash
cd server
python -m pip install -r requirements.txt
python burp_mcp_server.py       # avvio manuale (stdio)
```

Registralo in Claude Desktop → vedi `server/claude_desktop_config.example.json`
(su Windows: `%APPDATA%\Claude\claude_desktop_config.json`). Poi in chat:
*"chiama burp_status"* → deve rispondere `reachable: true`.

Variabili: `BURP_BRIDGE_URL` (default `http://127.0.0.1:9876`),
`BURP_BRIDGE_TOKEN` (default `changeme`), `BURP_BRIDGE_TIMEOUT` (default 10).

> ⚠️ Usa lo stesso token nell'estensione e nel server MCP.

## 3) Test locale (senza Burp)

```bash
cd server
python test_bridge.py
```

Usa `mock_burp.py` (che replica il contratto di `BridgeServer.java`) per validare
il protocollo MCP e la gestione degli errori senza avviare Burp.

---

## Sicurezza

Il ponte ascolta **solo su 127.0.0.1** ed è protetto da token. Cambia il token
di default (`changeme`) prima di un uso reale.

## Roadmap

- [x] Fase 1 — ponte + `burp_status()` (health check)
- [ ] Fase 2 — comandi: `proxy_history`, `sitemap`, `send_to_repeater`, `active/passive` (Pro), …
