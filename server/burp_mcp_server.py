"""
Server MCP (FastMCP) per Burp.

Fase 1: ponte + burp_status().
Fase 2: comandi da ethical hacker (scope, proxy history, sitemap, message, http send).
Tutto compatibile con Burp Community. I comandi che INVIANO richieste hanno
scope-guard di default (rifiutano URL fuori scope, override con force=True) e un
rate-limit opzionale.

Config (variabili d'ambiente):
  BURP_BRIDGE_URL          URL del ponte            (default http://127.0.0.1:9876)
  BURP_BRIDGE_TOKEN        token condiviso          (default "changeme")
  BURP_BRIDGE_TIMEOUT      timeout secondi          (default 30)
  BURP_SEND_MIN_INTERVAL   ritardo minimo tra invii (default 0 = disattivo)
"""

import base64
import difflib
import gzip
import hashlib
import html
import json
import os
import re
import time
from urllib.parse import quote, quote_plus, unquote, unquote_plus, urlsplit

import httpx
from fastmcp import FastMCP

BRIDGE_URL = os.environ.get("BURP_BRIDGE_URL", "http://127.0.0.1:9876").rstrip("/")
BRIDGE_TOKEN = os.environ.get("BURP_BRIDGE_TOKEN", "changeme")
TIMEOUT = float(os.environ.get("BURP_BRIDGE_TIMEOUT", "30"))
MIN_INTERVAL = float(os.environ.get("BURP_SEND_MIN_INTERVAL", "0"))

mcp = FastMCP("burp-mcp")

_last_send = 0.0


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=BRIDGE_URL,
        headers={"X-Burp-Token": BRIDGE_TOKEN},
        timeout=TIMEOUT,
        trust_env=False,  # loopback: mai passare da un proxy
    )


def _api(method: str, path: str, params: dict | None = None, body: str | None = None) -> dict:
    """Chiama il ponte e ritorna sempre un dict (errori inclusi, leggibili)."""
    clean = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
    try:
        with _client() as client:
            resp = client.request(
                method, path, params=clean,
                content=body.encode("utf-8") if isinstance(body, str) else body,
            )
        resp.raise_for_status()
        return resp.json()
    except httpx.ConnectError:
        return {"error": "Connessione rifiutata: estensione non caricata in Burp o porta errata."}
    except httpx.TimeoutException:
        return {"error": f"Timeout dopo {TIMEOUT}s contattando il ponte."}
    except httpx.HTTPStatusError as exc:
        try:
            j = exc.response.json()
        except Exception:
            j = {}
        if not isinstance(j, dict):
            j = {"detail": j}
        j.setdefault("error", f"HTTP {exc.response.status_code}")
        j["http_status"] = exc.response.status_code
        return j
    except Exception as exc:  # pragma: no cover
        return {"error": f"{type(exc).__name__}: {exc}"}


# --------------------------------------------------------------------------- #
#  Fase 1
# --------------------------------------------------------------------------- #
@mcp.tool
def burp_status() -> dict:
    """Verifica la connessione al ponte Burp e ritorna prodotto/versione/edizione."""
    data = _api("GET", "/ping")
    if "error" in data:
        return {"reachable": False, "bridge_url": BRIDGE_URL, **data}
    return {"reachable": True, "bridge_url": BRIDGE_URL, **data}


# --------------------------------------------------------------------------- #
#  Scope
# --------------------------------------------------------------------------- #
@mcp.tool
def scope_check(url: str) -> dict:
    """Verifica se un URL e' nello scope di Burp. Usalo prima di testare un target."""
    return _api("GET", "/scope/check", {"url": url})


@mcp.tool
def scope_add(url: str) -> dict:
    """Aggiunge un URL/prefisso allo scope di Burp."""
    return _api("POST", "/scope/add", {"url": url})


@mcp.tool
def scope_remove(url: str) -> dict:
    """Rimuove un URL/prefisso dallo scope di Burp."""
    return _api("POST", "/scope/remove", {"url": url})


@mcp.tool
def scope_bootstrap(urls: list | str) -> dict:
    """Aggiunge molti URL/prefissi allo scope in una sola chiamata.

    Utile dopo un riavvio di Burp (Community usa progetti temporanei che
    perdono lo scope). 'urls' puo' essere una lista JSON, oppure una stringa
    con URL separati da newline, virgola o spazio.

    Ritorna il numero di aggiunti/falliti e il dettaglio per URL.
    """
    if isinstance(urls, str):
        s = urls.strip()
        if s.startswith("["):
            try:
                urls = json.loads(s)
            except json.JSONDecodeError as e:
                return {"error": f"lista JSON non valida: {e}"}
        else:
            urls = [u for u in re.split(r"[\s,]+", s) if u]
    if not isinstance(urls, list) or not urls:
        return {"error": "fornisci una lista non vuota di URL."}

    results, added, failed = [], 0, 0
    for u in urls:
        u = str(u).strip()
        if not u:
            continue
        r = _api("POST", "/scope/add", {"url": u})
        ok = "error" not in r
        added += ok
        failed += (not ok)
        results.append({"url": u, "ok": ok, "detail": r})
    return {"added": added, "failed": failed, "total": added + failed, "results": results}


# --------------------------------------------------------------------------- #
#  Ricognizione: proxy history / sitemap / message
# --------------------------------------------------------------------------- #
@mcp.tool
def proxy_history(host: str | None = None, in_scope: bool | None = None,
                  status: int | None = None, method: str | None = None,
                  search: str | None = None, limit: int = 100, offset: int = 0) -> dict:
    """Elenca lo storico del Proxy di Burp con filtri.

    host: sottostringa host; in_scope: solo in/out scope; status: codice esatto;
    method: GET/POST/...; search: regex sull'URL; limit/offset: paginazione.
    Ogni voce ha un 'index' usabile con get_message(source='proxy', index=...).
    """
    return _api("GET", "/proxy/history", {
        "host": host,
        "in_scope": None if in_scope is None else str(in_scope).lower(),
        "status": None if status is None else str(status),
        "method": method,
        "search": search,
        "limit": str(limit),
        "offset": str(offset),
    })


@mcp.tool
def sitemap(host: str | None = None, in_scope: bool | None = None,
            limit: int = 100, offset: int = 0) -> dict:
    """Elenca la Site map di Burp (filtri host/in_scope, paginazione).

    Ogni voce ha un 'index' usabile con get_message(source='sitemap', index=...).
    """
    return _api("GET", "/sitemap", {
        "host": host,
        "in_scope": None if in_scope is None else str(in_scope).lower(),
        "limit": str(limit),
        "offset": str(offset),
    })


@mcp.tool
def get_message(index: int, source: str = "proxy", max_chars: int = 20000) -> dict:
    """Richiesta+risposta complete di una voce.

    source: 'proxy' (default) o 'sitemap'; index: dall'elenco corrispondente.
    """
    return _api("GET", "/message", {
        "source": source, "index": str(index), "max": str(max_chars),
    })


# --------------------------------------------------------------------------- #
#  Invio richieste (scope-guarded)
# --------------------------------------------------------------------------- #
def _build_raw_request(method: str, url: str, headers: dict | None, body: str):
    """Costruisce (raw_request, host, port, secure) da parametri amichevoli."""
    parts = urlsplit(url)
    if not parts.hostname:
        raise ValueError(f"URL non valido: {url}")
    secure = parts.scheme == "https"
    port = parts.port or (443 if secure else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    default_port = 443 if secure else 80
    host_hdr = parts.hostname if port == default_port else f"{parts.hostname}:{port}"

    hdrs = {"Host": host_hdr}
    for k, v in (headers or {}).items():
        hdrs[k] = v  # l'utente puo' sovrascrivere Host
    if body and not any(k.lower() == "content-length" for k in hdrs):
        hdrs["Content-Length"] = str(len(body.encode("utf-8")))
    if not any(k.lower() == "connection" for k in hdrs):
        hdrs["Connection"] = "close"

    lines = [f"{method.upper()} {path} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in hdrs.items()]
    raw = "\r\n".join(lines) + "\r\n\r\n" + (body or "")
    return raw, parts.hostname, port, secure


def _resolve_send(url, method, headers, body, raw, host, port, secure):
    """Normalizza gli input dei tool d'invio in (raw, host, port, secure). Puo' sollevare ValueError."""
    # 'headers' puo' arrivare come stringa JSON (alcuni transport MCP non passano i dict).
    if isinstance(headers, str):
        s = headers.strip()
        if not s:
            headers = None
        else:
            try:
                headers = json.loads(s)
            except json.JSONDecodeError as e:
                raise ValueError(f"'headers' non e' un JSON valido: {e}")
        if headers is not None and not isinstance(headers, dict):
            raise ValueError("'headers' deve essere un oggetto/dizionario.")

    if raw is None:
        if not url:
            raise ValueError("Serve 'url' (modalita' amichevole) oppure 'raw'+host/port/secure.")
        return _build_raw_request(method, url, headers, body)

    # Modalita' raw: Montoya rifiuta i terminatori LF-only. Normalizzo la sezione
    # header a CRLF preservando il body invariato (Content-Length resta coerente).
    parts_rb = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
    head = parts_rb[0].rstrip("\r\n")
    head = head.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
    body_part = parts_rb[1] if len(parts_rb) > 1 else ""
    raw = head + "\r\n\r\n" + body_part

    if url and (host is None or port is None or secure is None):
        parts = urlsplit(url)
        secure = parts.scheme == "https" if secure is None else secure
        host = parts.hostname if host is None else host
        port = (parts.port or (443 if secure else 80)) if port is None else port
    if not host or not port or secure is None:
        raise ValueError("In modalita' raw servono host, port e secure (o un url da cui ricavarli).")
    return raw, host, port, secure


@mcp.tool
def http_send(url: str | None = None, method: str = "GET",
              headers: dict | str | None = None, body: str = "",
              raw: str | None = None, host: str | None = None,
              port: int | None = None, secure: bool | None = None,
              force: bool = False, max_chars: int = 8000) -> dict:
    """Invia una richiesta HTTP tramite Burp e ritorna la risposta.

    Due modalita':
      - amichevole: passa url (+ method, headers dict, body).
      - raw: passa raw (richiesta HTTP grezza) + host, port, secure.

    Scope-guard: se l'URL NON e' nello scope di Burp la richiesta e' rifiutata,
    a meno di force=True. Rispetta BURP_SEND_MIN_INTERVAL tra invii.
    """
    global _last_send

    try:
        raw, host, port, secure = _resolve_send(url, method, headers, body, raw, host, port, secure)
    except ValueError as e:
        return {"error": str(e)}

    if MIN_INTERVAL > 0:
        wait = _last_send + MIN_INTERVAL - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_send = time.monotonic()

    return _api("POST", "/http/send", {
        "host": host, "port": str(port),
        "secure": str(bool(secure)).lower(),
        "force": str(bool(force)).lower(),
        "max": str(max_chars),
    }, body=raw)


@mcp.tool
def send_to_repeater(url: str | None = None, method: str = "GET",
                     headers: dict | str | None = None, body: str = "",
                     raw: str | None = None, host: str | None = None,
                     port: int | None = None, secure: bool | None = None,
                     name: str | None = None, force: bool = False) -> dict:
    """Manda una richiesta al Repeater di Burp (la apre in una tab, non la trasmette).

    Stessi input di http_send + 'name' (etichetta della tab). Scope-guard attivo.
    """
    try:
        raw, host, port, secure = _resolve_send(url, method, headers, body, raw, host, port, secure)
    except ValueError as e:
        return {"error": str(e)}
    return _api("POST", "/repeater/send", {
        "host": host, "port": str(port),
        "secure": str(bool(secure)).lower(),
        "force": str(bool(force)).lower(), "name": name,
    }, body=raw)


@mcp.tool
def send_to_intruder(url: str | None = None, method: str = "GET",
                     headers: dict | str | None = None, body: str = "",
                     raw: str | None = None, host: str | None = None,
                     port: int | None = None, secure: bool | None = None,
                     name: str | None = None, force: bool = False) -> dict:
    """Manda una richiesta all'Intruder di Burp (per attacchi parametrici).

    Nota: in Community l'Intruder e' rallentato. Scope-guard attivo.
    """
    try:
        raw, host, port, secure = _resolve_send(url, method, headers, body, raw, host, port, secure)
    except ValueError as e:
        return {"error": str(e)}
    return _api("POST", "/intruder/send", {
        "host": host, "port": str(port),
        "secure": str(bool(secure)).lower(),
        "force": str(bool(force)).lower(), "name": name,
    }, body=raw)


@mcp.tool
def compare_responses(index_a: int, index_b: int, source: str = "proxy",
                      part: str = "response", max_diff_lines: int = 200) -> dict:
    """Confronta due messaggi (dal proxy o dalla sitemap) e ritorna un diff unificato.

    source: 'proxy' o 'sitemap'; part: 'response' o 'request'.
    """
    if part not in ("request", "response"):
        return {"error": "part deve essere 'request' o 'response'"}
    a = _api("GET", "/message", {"source": source, "index": str(index_a), "max": "1000000"})
    if "error" in a:
        return {"error": f"A: {a['error']}"}
    b = _api("GET", "/message", {"source": source, "index": str(index_b), "max": "1000000"})
    if "error" in b:
        return {"error": f"B: {b['error']}"}
    ta = a.get(part, "") or ""
    tb = b.get(part, "") or ""
    diff = list(difflib.unified_diff(
        ta.splitlines(), tb.splitlines(),
        fromfile=f"{source}#{index_a}", tofile=f"{source}#{index_b}", lineterm=""))
    return {
        "equal": ta == tb,
        "len_a": len(ta), "len_b": len(tb),
        "diff_truncated": len(diff) > max_diff_lines,
        "diff": "\n".join(diff[:max_diff_lines]),
    }


# --------------------------------------------------------------------------- #
#  Utilities (pure Python, non richiedono Burp)
# --------------------------------------------------------------------------- #
_ENC_SCHEMES = ["base64", "url", "url_plus", "hex", "html", "gzip_b64"]


@mcp.tool
def encode(data: str, scheme: str) -> dict:
    """Codifica una stringa. scheme: base64 | url | url_plus | hex | html | gzip_b64."""
    try:
        raw = data.encode("utf-8")
        if scheme == "base64":
            out = base64.b64encode(raw).decode()
        elif scheme == "url":
            out = quote(data, safe="")
        elif scheme == "url_plus":
            out = quote_plus(data)
        elif scheme == "hex":
            out = raw.hex()
        elif scheme == "html":
            out = html.escape(data)
        elif scheme == "gzip_b64":
            out = base64.b64encode(gzip.compress(raw)).decode()
        else:
            return {"error": f"scheme sconosciuto: {scheme}", "supported": _ENC_SCHEMES}
        return {"scheme": scheme, "output": out}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@mcp.tool
def decode(data: str, scheme: str) -> dict:
    """Decodifica una stringa. scheme: base64 | url | url_plus | hex | html | gzip_b64."""
    try:
        if scheme == "base64":
            out = base64.b64decode(data).decode("utf-8", "replace")
        elif scheme == "url":
            out = unquote(data)
        elif scheme == "url_plus":
            out = unquote_plus(data)
        elif scheme == "hex":
            out = bytes.fromhex(data.strip()).decode("utf-8", "replace")
        elif scheme == "html":
            out = html.unescape(data)
        elif scheme == "gzip_b64":
            out = gzip.decompress(base64.b64decode(data)).decode("utf-8", "replace")
        else:
            return {"error": f"scheme sconosciuto: {scheme}", "supported": _ENC_SCHEMES}
        return {"scheme": scheme, "output": out}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@mcp.tool
def hash_text(data: str, algo: str = "sha256") -> dict:
    """Calcola l'hash di una stringa. algo: md5, sha1, sha256, sha512, ..."""
    try:
        h = hashlib.new(algo)
        h.update(data.encode("utf-8"))
        return {"algo": algo, "hex": h.hexdigest()}
    except Exception as e:
        return {"error": f"algoritmo non valido o errore: {e}"}


# --------------------------------------------------------------------------- #
#  Fase 4 — controllo app (Community-safe)
# --------------------------------------------------------------------------- #
@mcp.tool
def proxy_intercept(action: str = "status") -> dict:
    """Controlla l'intercept del Proxy di Burp.

    action: 'status' (default) | 'enable' | 'disable'.
    """
    action = (action or "status").lower()
    if action == "status":
        return _api("GET", "/proxy/intercept")
    if action == "enable":
        return _api("POST", "/proxy/intercept/enable")
    if action == "disable":
        return _api("POST", "/proxy/intercept/disable")
    return {"error": "action deve essere 'status', 'enable' o 'disable'"}


@mcp.tool
def comparer_send(items: list | str | None = None, source: str | None = None,
                  indices: list | str | None = None, part: str = "response") -> dict:
    """Manda uno o piu' blob al Comparer di Burp (si accumulano nella tab).

    Due modalita':
      - testo: 'items' = lista di stringhe (o una singola stringa).
      - da Burp: 'source' ('proxy'|'sitemap') + 'indices' (lista di index) e
        'part' ('response'|'request'): recupera i messaggi e li invia.
    """
    payloads: list[str] = []

    if items is not None:
        if isinstance(items, str):
            payloads = [items]
        elif isinstance(items, list):
            payloads = [str(x) for x in items]
        else:
            return {"error": "'items' deve essere una lista o una stringa."}

    if indices is not None:
        if part not in ("request", "response"):
            return {"error": "part deve essere 'request' o 'response'"}
        if isinstance(indices, str):
            try:
                indices = json.loads(indices) if indices.strip().startswith("[") \
                    else [int(x) for x in re.split(r"[\s,]+", indices.strip()) if x]
            except (json.JSONDecodeError, ValueError) as e:
                return {"error": f"'indices' non valido: {e}"}
        src = (source or "proxy").lower()
        for idx in indices:
            m = _api("GET", "/message", {"source": src, "index": str(idx), "max": "1000000"})
            if "error" in m:
                return {"error": f"index {idx}: {m['error']}"}
            payloads.append(m.get(part, "") or "")

    if not payloads:
        return {"error": "fornisci 'items' oppure 'indices'."}

    sent, failed = 0, 0
    for p in payloads:
        r = _api("POST", "/comparer/send", body=p)
        ok = "error" not in r
        sent += ok
        failed += (not ok)
    return {"sent": sent, "failed": failed, "total": len(payloads), "target": "comparer"}


@mcp.tool
def organizer_send(url: str | None = None, method: str = "GET",
                   headers: dict | str | None = None, body: str = "",
                   raw: str | None = None, host: str | None = None,
                   port: int | None = None, secure: bool | None = None) -> dict:
    """Salva una richiesta nell'Organizer di Burp (nessuna trasmissione).

    Stessi input di http_send. Nessuno scope-guard: e' solo archiviazione locale.
    """
    try:
        raw, host, port, secure = _resolve_send(url, method, headers, body, raw, host, port, secure)
    except ValueError as e:
        return {"error": str(e)}
    return _api("POST", "/organizer/send", {
        "host": host, "port": str(port), "secure": str(bool(secure)).lower(),
    }, body=raw)


@mcp.tool
def organizer_list() -> dict:
    """Elenca gli item salvati nell'Organizer (id + status)."""
    return _api("GET", "/organizer/list")


@mcp.tool
def sitemap_add(index: int, source: str = "proxy") -> dict:
    """Aggiunge alla Site map una voce esistente di proxy history o sitemap.

    source: 'proxy' (default) o 'sitemap'; index: dall'elenco corrispondente.
    """
    return _api("POST", "/sitemap/add", {"source": source, "index": str(index)})


@mcp.tool
def sitemap_issues(limit: int = 100, offset: int = 0, max_chars: int = 2000) -> dict:
    """Elenca gli audit issue nella Site map (in Community di norma vuoto,
    salvo issue aggiunti da altre estensioni)."""
    return _api("GET", "/sitemap/issues", {
        "limit": str(limit), "offset": str(offset), "max": str(max_chars),
    })


@mcp.tool
def websocket_history(host: str | None = None, limit: int = 100, offset: int = 0) -> dict:
    """Elenca lo storico dei messaggi WebSocket del Proxy (filtro host, paginazione).

    Ogni voce ha un 'index' usabile con get_ws_message(index=...).
    """
    return _api("GET", "/ws/history", {
        "host": host, "limit": str(limit), "offset": str(offset),
    })


@mcp.tool
def get_ws_message(index: int, max_chars: int = 20000) -> dict:
    """Payload completo di un messaggio WebSocket (dall'elenco websocket_history)."""
    return _api("GET", "/ws/message", {"index": str(index), "max": str(max_chars)})


@mcp.tool
def project_info() -> dict:
    """Nome e id del progetto Burp corrente."""
    return _api("GET", "/project")


# --------------------------------------------------------------------------- #
#  Storage persistente (scratchpad dentro Burp: chiave/valore string)
#  scope='project' -> legato al progetto; scope='global' -> preferenze utente.
# --------------------------------------------------------------------------- #
@mcp.tool
def config_get(key: str, scope: str = "project") -> dict:
    """Legge un valore string dallo storage di Burp. scope: 'project' | 'global'."""
    return _api("GET", "/storage/get", {"key": key, "scope": scope})


@mcp.tool
def config_set(key: str, value: str, scope: str = "project") -> dict:
    """Scrive un valore string nello storage di Burp. scope: 'project' | 'global'.

    Utile per far persistere note/stato tra le sessioni (in Community il progetto
    e' temporaneo, quindi per dati durevoli usa scope='global')."""
    return _api("POST", "/storage/set", {"key": key, "scope": scope}, body=value)


@mcp.tool
def config_delete(key: str, scope: str = "project") -> dict:
    """Cancella una chiave dallo storage di Burp. scope: 'project' | 'global'."""
    return _api("POST", "/storage/delete", {"key": key, "scope": scope})


@mcp.tool
def config_keys(scope: str = "project") -> dict:
    """Elenca le chiavi string presenti nello storage. scope: 'project' | 'global'."""
    return _api("GET", "/storage/keys", {"scope": scope})


if __name__ == "__main__":
    mcp.run()
