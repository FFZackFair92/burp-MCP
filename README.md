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

Serve **solo un JDK 17+** nel PATH (verifica con `javac -version`). Da `extension/`:

```bat
build.bat            :: Windows  (senza Gradle: scarica Montoya, compila, crea il jar)
```
```bash
./build.sh           # Linux/macOS
# in alternativa, se hai Gradle:  gradle jar
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

## Comandi (tool MCP)

Fase 1: `burp_status`.
Fase 2 (Community): `scope_check` / `scope_add` / `scope_remove`, `proxy_history`,
`sitemap`, `get_message`, `http_send`.
Fase 3: `send_to_repeater`, `send_to_intruder`, `compare_responses`,
`encode` / `decode` / `hash_text` (utilities pure Python).
Fase 4 (Community — controllo app):
- `proxy_intercept(action=status|enable|disable)` — accende/spegne l'intercept del Proxy.
- `comparer_send(items | source+indices)` — manda blob al Comparer (si accumulano).
- `organizer_send(...)` + `organizer_list()` — archivia richieste nell'Organizer (no scope-guard).
- `sitemap_add(index, source)` — aggiunge alla Site map una voce di proxy/sitemap.
- `sitemap_issues()` — elenca gli audit issue presenti (in Community di norma vuoto).
- `websocket_history()` + `get_ws_message(index)` — storico e payload dei messaggi WebSocket.
- `project_info()` — nome/id del progetto corrente.
- `config_get/set/delete/keys(scope=project|global)` — scratchpad persistente (chiave/valore string).

- `http_send`, `send_to_repeater`, `send_to_intruder` hanno **scope-guard**: rifiutano
  URL fuori dallo scope di Burp salvo `force=true`. Rate-limit su `http_send` via
  `BURP_SEND_MIN_INTERVAL` (secondi tra invii).
- Endpoint del ponte: `/ping`, `/scope/*`, `/proxy/history`, `/sitemap`, `/message`,
  `/http/send`, `/repeater/send`, `/intruder/send`, `/proxy/intercept*`, `/comparer/send`,
  `/organizer/*`, `/sitemap/add`, `/sitemap/issues`, `/ws/*`, `/project`, `/storage/*`,
  `/collaborator/*`, `/dashboard/event`, `/extension/*`.

Fase 5 (Community — Collaborator, Dashboard, Extensions):
- `collaborator_generate(count, custom_data)` — genera N payload OOB (canary DNS/HTTP/SMTP);
  usa il server Collaborator pubblico, funziona anche in Community.
- `collaborator_interactions(interaction_id, limit)` — legge le interazioni ricevute
  (poll manuale: nessun push, va richiamato dopo aver piazzato il payload nel target).
- `collaborator_status()` / `collaborator_reset()` — stato del client / lo scarta.
  La secret key persiste nello storage di progetto: un reload dell'estensione nello
  stesso progetto Burp ripristina lo stesso client (i payload restano interrogabili).
- `dashboard_event(message, level=info|debug|error|critical)` — scrive nell'Event log
  della tab **Dashboard**.
- `extension_log(message, stream=output|error)` — scrive nella tab Output/Errors della
  nostra riga in **Extensions → Installed**.
- `extension_info()` — filename del jar e flag `is_bapp` della nostra estensione.

Test locali: `python test_bridge.py`, `python test_fase2.py`, `python test_fase3.py`,
`python test_fase4.py`, `python test_fase5.py`.

## Copertura tab di Burp (screenshot barra strumenti)

| Tab            | Copertura | Tool / route |
|----------------|-----------|--------------|
| Dashboard      | Parziale  | `dashboard_event` scrive nell'Event log; niente scanner (richiede Pro) |
| Target         | Sì        | `sitemap*`, `scope_*` |
| Proxy          | Sì        | `proxy_history`, `proxy_intercept`, `get_message`, `websocket_history` |
| Intruder       | Invio     | `send_to_intruder` (avvio/config attacco resta manuale, no API Montoya) |
| Repeater       | Sì        | `send_to_repeater` |
| Collaborator   | Sì        | `collaborator_generate/interactions/status/reset` |
| Sequencer      | No        | Nessuna API Montoya pubblica per pilotare l'analisi di entropia |
| Decoder        | Sì (equivalente) | `encode`/`decode`/`hash_text` (pure Python, stesso risultato del tool UI) |
| Comparer       | Sì        | `comparer_send`, `compare_responses` |
| Logger         | No        | Montoya non espone lo storico della tab Logger (solo Proxy/WS history) |
| Organizer      | Sì        | `organizer_send`, `organizer_list` |
| Extensions     | Parziale  | `extension_log`/`extension_info` solo per la nostra riga; Montoya non permette di enumerare/pilotare altre estensioni o il BApp Store |
| Discover       | No        | Feature AI nativa di Burp, nessuna API |

Le voci "No" sono state verificate leggendo il constant-pool delle classi in
`extension/lib/montoya-api-2026.4.jar` (nessuna classe `sequencer`/`discover`,
nessun metodo per enumerare estensioni): non sono limitazioni di Community,
mancano proprio nell'API pubblica anche in Pro.

## Roadmap

- [x] Fase 1 — ponte + `burp_status()`
- [x] Fase 2 — scope, `proxy_history`, `sitemap`, `get_message`, `http_send` (scope-guard)
- [x] Fase 3 — `send_to_repeater`, `send_to_intruder`, `compare_responses`, utilities (encode/decode/hash)
- [x] Fase 4 (Community) — intercept, Comparer, Organizer, sitemap add/issues, WebSocket, project, storage
- [x] Fase 5 (Community) — Collaborator, Dashboard event log, Extensions output/info
- [ ] Fase 6 (solo Pro) — scanner attivo/passivo (audit issue reali)
