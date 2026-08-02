package burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.organizer.OrganizerItem;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.project.Project;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burpmcp.BridgeServer.Response;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Comandi Fase 2 registrati sul ponte.
 * Input via query param (parsati da BridgeServer), output JSON.
 * Tutto compatibile con Burp Community.
 */
final class Commands {

    private Commands() {
    }

    static void register(BridgeServer server, MontoyaApi api) {

        // ---------- SCOPE ----------
        server.route("GET", "/scope/check", req -> {
            String url = req.q("url", "");
            if (url.isEmpty()) return bad("parametro 'url' mancante");
            boolean in = api.scope().isInScope(url);
            return new Response(200, "{\"url\":" + BridgeServer.jsonStr(url) + ",\"in_scope\":" + in + "}");
        });

        server.route("POST", "/scope/add", req -> {
            String url = req.q("url", "");
            if (url.isEmpty()) return bad("parametro 'url' mancante");
            api.scope().includeInScope(url);
            return new Response(200, "{\"added\":" + BridgeServer.jsonStr(url) + "}");
        });

        server.route("POST", "/scope/remove", req -> {
            String url = req.q("url", "");
            if (url.isEmpty()) return bad("parametro 'url' mancante");
            api.scope().excludeFromScope(url);
            return new Response(200, "{\"removed\":" + BridgeServer.jsonStr(url) + "}");
        });

        // ---------- PROXY HISTORY ----------
        server.route("GET", "/proxy/history", req -> {
            String hostF = req.q("host", "").toLowerCase();
            String inScopeF = req.q("in_scope", "");
            String statusF = req.q("status", "");
            String methodF = req.q("method", "");
            String search = req.q("search", "");
            int limit = clampInt(req.q("limit", "100"), 1, 1000, 100);
            int offset = clampInt(req.q("offset", "0"), 0, Integer.MAX_VALUE, 0);
            Pattern rx = compileSafe(search);

            List<ProxyHttpRequestResponse> hist = api.proxy().history();
            StringBuilder arr = new StringBuilder("[");
            int matched = 0, emitted = 0, skipped = 0;
            for (int i = 0; i < hist.size(); i++) {
                ProxyHttpRequestResponse e = hist.get(i);
                HttpRequest rq = e.finalRequest();
                HttpResponse rs = e.response();
                if (rq == null) continue;
                String url = rq.url();
                String host = rq.httpService() != null ? rq.httpService().host() : "";
                String method = rq.method();
                int status = rs != null ? (rs.statusCode() & 0xffff) : 0;

                if (!hostF.isEmpty() && !host.toLowerCase().contains(hostF)) continue;
                if (!methodF.isEmpty() && !method.equalsIgnoreCase(methodF)) continue;
                if (!statusF.isEmpty()) {
                    try {
                        if (status != Integer.parseInt(statusF.trim())) continue;
                    } catch (NumberFormatException ignored) {
                    }
                }
                if (!inScopeF.isEmpty()) {
                    boolean want = inScopeF.equalsIgnoreCase("true") || inScopeF.equals("1");
                    if (api.scope().isInScope(url) != want) continue;
                }
                if (rx != null && !rx.matcher(url).find()) continue;

                matched++;
                if (skipped < offset) {
                    skipped++;
                    continue;
                }
                if (emitted >= limit) continue;
                if (emitted > 0) arr.append(',');
                int length = (rs != null && rs.body() != null) ? rs.body().length() : 0;
                String mime = rs != null ? String.valueOf(rs.mimeType()) : "";
                arr.append(entryJson(i, method, url, host, status, length, mime));
                emitted++;
            }
            arr.append("]");
            return new Response(200, "{\"total_matched\":" + matched + ",\"count\":" + emitted
                    + ",\"offset\":" + offset + ",\"items\":" + arr + "}");
        });

        // ---------- SITEMAP ----------
        server.route("GET", "/sitemap", req -> {
            String hostF = req.q("host", "").toLowerCase();
            String inScopeF = req.q("in_scope", "");
            int limit = clampInt(req.q("limit", "100"), 1, 1000, 100);
            int offset = clampInt(req.q("offset", "0"), 0, Integer.MAX_VALUE, 0);

            List<HttpRequestResponse> items = api.siteMap().requestResponses();
            StringBuilder arr = new StringBuilder("[");
            int matched = 0, emitted = 0, skipped = 0;
            for (int i = 0; i < items.size(); i++) {
                HttpRequestResponse rr = items.get(i);
                HttpRequest rq = rr.request();
                if (rq == null) continue;
                HttpResponse rs = rr.response();
                String url = rq.url();
                String host = rq.httpService() != null ? rq.httpService().host() : "";

                if (!hostF.isEmpty() && !host.toLowerCase().contains(hostF)) continue;
                if (!inScopeF.isEmpty()) {
                    boolean want = inScopeF.equalsIgnoreCase("true") || inScopeF.equals("1");
                    if (api.scope().isInScope(url) != want) continue;
                }

                matched++;
                if (skipped < offset) {
                    skipped++;
                    continue;
                }
                if (emitted >= limit) continue;
                if (emitted > 0) arr.append(',');
                int status = rs != null ? (rs.statusCode() & 0xffff) : 0;
                int length = (rs != null && rs.body() != null) ? rs.body().length() : 0;
                String mime = rs != null ? String.valueOf(rs.mimeType()) : "";
                arr.append(entryJson(i, rq.method(), url, host, status, length, mime));
                emitted++;
            }
            arr.append("]");
            return new Response(200, "{\"total_matched\":" + matched + ",\"count\":" + emitted
                    + ",\"offset\":" + offset + ",\"items\":" + arr + "}");
        });

        // ---------- MESSAGE (req/resp completi) ----------
        server.route("GET", "/message", req -> {
            String source = req.q("source", "proxy").toLowerCase();
            int index = clampInt(req.q("index", "-1"), -1, Integer.MAX_VALUE, -1);
            int max = clampInt(req.q("max", "20000"), 100, 2000000, 20000);
            if (index < 0) return bad("parametro 'index' mancante o non valido");

            HttpRequest rq;
            HttpResponse rs;
            if (source.equals("sitemap")) {
                List<HttpRequestResponse> items = api.siteMap().requestResponses();
                if (index >= items.size()) return notFound("index fuori range (sitemap)");
                HttpRequestResponse rr = items.get(index);
                rq = rr.request();
                rs = rr.response();
            } else {
                List<ProxyHttpRequestResponse> hist = api.proxy().history();
                if (index >= hist.size()) return notFound("index fuori range (proxy)");
                ProxyHttpRequestResponse e = hist.get(index);
                rq = e.finalRequest();
                rs = e.response();
            }
            String reqStr = rq != null ? rq.toString() : "";
            String resStr = rs != null ? rs.toString() : "";
            boolean truncated = reqStr.length() > max || resStr.length() > max;
            if (reqStr.length() > max) reqStr = reqStr.substring(0, max);
            if (resStr.length() > max) resStr = resStr.substring(0, max);
            return new Response(200, "{"
                    + "\"source\":" + BridgeServer.jsonStr(source) + ","
                    + "\"index\":" + index + ","
                    + "\"truncated\":" + truncated + ","
                    + "\"request\":" + BridgeServer.jsonStr(reqStr) + ","
                    + "\"response\":" + BridgeServer.jsonStr(resStr)
                    + "}");
        });

        // ---------- HTTP SEND (scope-guarded) ----------
        server.route("POST", "/http/send", req -> {
            String host = req.q("host", "");
            int port = clampInt(req.q("port", "0"), 0, 65535, 0);
            boolean secure = req.q("secure", "false").equalsIgnoreCase("true");
            boolean force = req.q("force", "false").equalsIgnoreCase("true");
            int max = clampInt(req.q("max", "8000"), 100, 2000000, 8000);
            String raw = req.body;

            if (host.isEmpty() || port == 0) return bad("parametri 'host'/'port' mancanti");
            if (raw == null || raw.isEmpty()) return bad("corpo (raw request) mancante");

            HttpService service = HttpService.httpService(host, port, secure);
            HttpRequest request = HttpRequest.httpRequest(service, raw);
            String url = request.url();

            if (!force && !api.scope().isInScope(url)) {
                return new Response(403, "{\"error\":\"out_of_scope\",\"url\":" + BridgeServer.jsonStr(url)
                        + ",\"hint\":\"usa force=true per inviare comunque\"}");
            }

            long t0 = System.nanoTime();
            HttpRequestResponse rr = api.http().sendRequest(request);
            long ms = (System.nanoTime() - t0) / 1000000L;
            HttpResponse rs = rr.response();

            int status = rs != null ? (rs.statusCode() & 0xffff) : 0;
            int length = (rs != null && rs.body() != null) ? rs.body().length() : 0;
            String mime = rs != null ? String.valueOf(rs.mimeType()) : "";
            String resStr = rs != null ? rs.toString() : "";
            boolean truncated = resStr.length() > max;
            if (truncated) resStr = resStr.substring(0, max);

            return new Response(200, "{"
                    + "\"url\":" + BridgeServer.jsonStr(url) + ","
                    + "\"status\":" + status + ","
                    + "\"length\":" + length + ","
                    + "\"mime\":" + BridgeServer.jsonStr(mime) + ","
                    + "\"time_ms\":" + ms + ","
                    + "\"truncated\":" + truncated + ","
                    + "\"response\":" + BridgeServer.jsonStr(resStr)
                    + "}");
        });

        // ---------- SEND TO REPEATER ----------
        server.route("POST", "/repeater/send", req -> {
            Object[] built = buildGuarded(api, req);
            if (built[0] != null) return (Response) built[0];
            HttpRequest request = (HttpRequest) built[1];
            String name = req.q("name", "");
            if (name.isEmpty()) api.repeater().sendToRepeater(request);
            else api.repeater().sendToRepeater(request, name);
            return new Response(200, "{\"sent\":true,\"target\":\"repeater\",\"url\":"
                    + BridgeServer.jsonStr(request.url()) + "}");
        });

        // ---------- SEND TO INTRUDER ----------
        server.route("POST", "/intruder/send", req -> {
            Object[] built = buildGuarded(api, req);
            if (built[0] != null) return (Response) built[0];
            HttpRequest request = (HttpRequest) built[1];
            String name = req.q("name", "");
            if (name.isEmpty()) api.intruder().sendToIntruder(request);
            else api.intruder().sendToIntruder(request, name);
            return new Response(200, "{\"sent\":true,\"target\":\"intruder\",\"url\":"
                    + BridgeServer.jsonStr(request.url()) + "}");
        });

        // ================= FASE 4 (Community-safe) ================= //

        // ---------- PROXY INTERCEPT ----------
        server.route("GET", "/proxy/intercept", req ->
                new Response(200, "{\"intercept_enabled\":" + api.proxy().isInterceptEnabled() + "}"));

        server.route("POST", "/proxy/intercept/enable", req -> {
            api.proxy().enableIntercept();
            return new Response(200, "{\"intercept_enabled\":true}");
        });

        server.route("POST", "/proxy/intercept/disable", req -> {
            api.proxy().disableIntercept();
            return new Response(200, "{\"intercept_enabled\":false}");
        });

        // ---------- COMPARER (un item per chiamata, si accumulano nella tab) ----------
        server.route("POST", "/comparer/send", req -> {
            String raw = req.body != null ? req.body : "";
            api.comparer().sendToComparer(ByteArray.byteArray(raw));
            return new Response(200, "{\"sent\":true,\"target\":\"comparer\",\"length\":" + raw.length() + "}");
        });

        // ---------- ORGANIZER ----------
        server.route("POST", "/organizer/send", req -> {
            Object[] built = buildRequest(req);
            if (built[0] != null) return (Response) built[0];
            HttpRequest request = (HttpRequest) built[1];
            api.organizer().sendToOrganizer(request);
            return new Response(200, "{\"sent\":true,\"target\":\"organizer\",\"url\":"
                    + BridgeServer.jsonStr(request.url()) + "}");
        });

        server.route("GET", "/organizer/list", req -> {
            List<OrganizerItem> items = api.organizer().items();
            StringBuilder arr = new StringBuilder("[");
            for (int i = 0; i < items.size(); i++) {
                if (i > 0) arr.append(',');
                OrganizerItem it = items.get(i);
                arr.append("{\"id\":").append(it.id())
                        .append(",\"status\":").append(BridgeServer.jsonStr(String.valueOf(it.status())))
                        .append("}");
            }
            arr.append("]");
            return new Response(200, "{\"count\":" + items.size() + ",\"items\":" + arr + "}");
        });

        // ---------- SITEMAP ADD (da una voce esistente di proxy/sitemap) ----------
        server.route("POST", "/sitemap/add", req -> {
            String source = req.q("source", "proxy").toLowerCase();
            int index = clampInt(req.q("index", "-1"), -1, Integer.MAX_VALUE, -1);
            if (index < 0) return bad("parametro 'index' mancante o non valido");

            HttpRequest rq;
            HttpResponse rs;
            if (source.equals("sitemap")) {
                List<HttpRequestResponse> items = api.siteMap().requestResponses();
                if (index >= items.size()) return notFound("index fuori range (sitemap)");
                HttpRequestResponse rr = items.get(index);
                rq = rr.request();
                rs = rr.response();
            } else {
                List<ProxyHttpRequestResponse> hist = api.proxy().history();
                if (index >= hist.size()) return notFound("index fuori range (proxy)");
                ProxyHttpRequestResponse e = hist.get(index);
                rq = e.finalRequest();
                rs = e.response();
            }
            if (rq == null) return bad("voce senza richiesta");
            HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(rq, rs);
            api.siteMap().add(rr);
            return new Response(200, "{\"added\":true,\"url\":" + BridgeServer.jsonStr(rq.url()) + "}");
        });

        // ---------- SITEMAP ISSUES (audit issue presenti; in Community di norma vuoto) ----------
        server.route("GET", "/sitemap/issues", req -> {
            int limit = clampInt(req.q("limit", "100"), 1, 1000, 100);
            int offset = clampInt(req.q("offset", "0"), 0, Integer.MAX_VALUE, 0);
            int max = clampInt(req.q("max", "2000"), 100, 200000, 2000);

            List<AuditIssue> issues = api.siteMap().issues();
            StringBuilder arr = new StringBuilder("[");
            int emitted = 0;
            for (int i = offset; i < issues.size() && emitted < limit; i++) {
                AuditIssue is = issues.get(i);
                if (emitted > 0) arr.append(',');
                String detail = is.detail() != null ? is.detail() : "";
                if (detail.length() > max) detail = detail.substring(0, max);
                arr.append("{")
                        .append("\"index\":").append(i).append(',')
                        .append("\"name\":").append(BridgeServer.jsonStr(is.name())).append(',')
                        .append("\"severity\":").append(BridgeServer.jsonStr(String.valueOf(is.severity()))).append(',')
                        .append("\"confidence\":").append(BridgeServer.jsonStr(String.valueOf(is.confidence()))).append(',')
                        .append("\"base_url\":").append(BridgeServer.jsonStr(is.baseUrl())).append(',')
                        .append("\"detail\":").append(BridgeServer.jsonStr(detail))
                        .append("}");
                emitted++;
            }
            arr.append("]");
            return new Response(200, "{\"total\":" + issues.size() + ",\"count\":" + emitted
                    + ",\"offset\":" + offset + ",\"items\":" + arr + "}");
        });

        // ---------- WEBSOCKET HISTORY ----------
        server.route("GET", "/ws/history", req -> {
            String hostF = req.q("host", "").toLowerCase();
            int limit = clampInt(req.q("limit", "100"), 1, 1000, 100);
            int offset = clampInt(req.q("offset", "0"), 0, Integer.MAX_VALUE, 0);

            List<ProxyWebSocketMessage> msgs = api.proxy().webSocketHistory();
            StringBuilder arr = new StringBuilder("[");
            int matched = 0, emitted = 0, skipped = 0;
            for (int i = 0; i < msgs.size(); i++) {
                ProxyWebSocketMessage m = msgs.get(i);
                HttpRequest up = m.upgradeRequest();
                String url = up != null ? up.url() : "";
                String host = (up != null && up.httpService() != null) ? up.httpService().host() : "";
                if (!hostF.isEmpty() && !host.toLowerCase().contains(hostF)) continue;
                matched++;
                if (skipped < offset) {
                    skipped++;
                    continue;
                }
                if (emitted >= limit) continue;
                if (emitted > 0) arr.append(',');
                int len = m.payload() != null ? m.payload().length() : 0;
                arr.append("{")
                        .append("\"index\":").append(i).append(',')
                        .append("\"ws_id\":").append(m.webSocketId()).append(',')
                        .append("\"direction\":").append(BridgeServer.jsonStr(String.valueOf(m.direction()))).append(',')
                        .append("\"listener_port\":").append(m.listenerPort()).append(',')
                        .append("\"url\":").append(BridgeServer.jsonStr(url)).append(',')
                        .append("\"host\":").append(BridgeServer.jsonStr(host)).append(',')
                        .append("\"length\":").append(len)
                        .append("}");
                emitted++;
            }
            arr.append("]");
            return new Response(200, "{\"total_matched\":" + matched + ",\"count\":" + emitted
                    + ",\"offset\":" + offset + ",\"items\":" + arr + "}");
        });

        server.route("GET", "/ws/message", req -> {
            int index = clampInt(req.q("index", "-1"), -1, Integer.MAX_VALUE, -1);
            int max = clampInt(req.q("max", "20000"), 100, 2000000, 20000);
            if (index < 0) return bad("parametro 'index' mancante o non valido");
            List<ProxyWebSocketMessage> msgs = api.proxy().webSocketHistory();
            if (index >= msgs.size()) return notFound("index fuori range (ws)");
            ProxyWebSocketMessage m = msgs.get(index);
            String payload = m.payload() != null ? m.payload().toString() : "";
            boolean truncated = payload.length() > max;
            if (truncated) payload = payload.substring(0, max);
            return new Response(200, "{"
                    + "\"index\":" + index + ","
                    + "\"ws_id\":" + m.webSocketId() + ","
                    + "\"direction\":" + BridgeServer.jsonStr(String.valueOf(m.direction())) + ","
                    + "\"truncated\":" + truncated + ","
                    + "\"payload\":" + BridgeServer.jsonStr(payload)
                    + "}");
        });

        // ---------- PROJECT ----------
        server.route("GET", "/project", req -> {
            Project p = api.project();
            return new Response(200, "{\"name\":" + BridgeServer.jsonStr(p.name())
                    + ",\"id\":" + BridgeServer.jsonStr(p.id()) + "}");
        });

        // ---------- STORAGE (persistence: chiave/valore string) ----------
        // scope=project -> extensionData() (legato al progetto); scope=global -> preferences()
        server.route("GET", "/storage/get", req -> {
            String scope = req.q("scope", "project").toLowerCase();
            String key = req.q("key", "");
            if (key.isEmpty()) return bad("parametro 'key' mancante");
            String val = scope.equals("global")
                    ? api.persistence().preferences().getString(key)
                    : api.persistence().extensionData().getString(key);
            return new Response(200, "{\"scope\":" + BridgeServer.jsonStr(scope)
                    + ",\"key\":" + BridgeServer.jsonStr(key)
                    + ",\"exists\":" + (val != null)
                    + ",\"value\":" + BridgeServer.jsonStr(val) + "}");
        });

        server.route("GET", "/storage/keys", req -> {
            String scope = req.q("scope", "project").toLowerCase();
            Set<String> keys = scope.equals("global")
                    ? api.persistence().preferences().stringKeys()
                    : api.persistence().extensionData().stringKeys();
            StringBuilder arr = new StringBuilder("[");
            boolean first = true;
            for (String k : keys) {
                if (!first) arr.append(',');
                arr.append(BridgeServer.jsonStr(k));
                first = false;
            }
            arr.append("]");
            return new Response(200, "{\"scope\":" + BridgeServer.jsonStr(scope)
                    + ",\"count\":" + keys.size() + ",\"keys\":" + arr + "}");
        });

        server.route("POST", "/storage/set", req -> {
            String scope = req.q("scope", "project").toLowerCase();
            String key = req.q("key", "");
            if (key.isEmpty()) return bad("parametro 'key' mancante");
            String value = req.body != null ? req.body : "";
            if (scope.equals("global")) api.persistence().preferences().setString(key, value);
            else api.persistence().extensionData().setString(key, value);
            return new Response(200, "{\"scope\":" + BridgeServer.jsonStr(scope)
                    + ",\"key\":" + BridgeServer.jsonStr(key) + ",\"saved\":true,\"length\":" + value.length() + "}");
        });

        server.route("POST", "/storage/delete", req -> {
            String scope = req.q("scope", "project").toLowerCase();
            String key = req.q("key", "");
            if (key.isEmpty()) return bad("parametro 'key' mancante");
            if (scope.equals("global")) api.persistence().preferences().deleteString(key);
            else api.persistence().extensionData().deleteString(key);
            return new Response(200, "{\"scope\":" + BridgeServer.jsonStr(scope)
                    + ",\"key\":" + BridgeServer.jsonStr(key) + ",\"deleted\":true}");
        });
    }

    /**
     * Costruisce l'HttpRequest da host/port/secure + raw body e applica lo scope-guard.
     * Ritorna [errorResponse|null, HttpRequest|null]: se [0] != null e' un errore da ritornare.
     */
    private static Object[] buildGuarded(MontoyaApi api, BridgeServer.Request req) {
        Object[] built = buildRequest(req);
        if (built[0] != null) return built;
        HttpRequest request = (HttpRequest) built[1];
        boolean force = req.q("force", "false").equalsIgnoreCase("true");
        String url = request.url();
        if (!force && !api.scope().isInScope(url)) {
            return new Object[]{new Response(403, "{\"error\":\"out_of_scope\",\"url\":"
                    + BridgeServer.jsonStr(url) + ",\"hint\":\"usa force=true per inviare comunque\"}"), null};
        }
        return new Object[]{null, request};
    }

    /**
     * Costruisce l'HttpRequest da host/port/secure + raw body, SENZA scope-guard.
     * Ritorna [errorResponse|null, HttpRequest|null].
     */
    private static Object[] buildRequest(BridgeServer.Request req) {
        String host = req.q("host", "");
        int port = clampInt(req.q("port", "0"), 0, 65535, 0);
        boolean secure = req.q("secure", "false").equalsIgnoreCase("true");
        String raw = req.body;
        if (host.isEmpty() || port == 0) return new Object[]{bad("parametri 'host'/'port' mancanti"), null};
        if (raw == null || raw.isEmpty()) return new Object[]{bad("corpo (raw request) mancante"), null};

        HttpService service = HttpService.httpService(host, port, secure);
        HttpRequest request = HttpRequest.httpRequest(service, raw);
        return new Object[]{null, request};
    }

    private static String entryJson(int index, String method, String url, String host,
                                    int status, int length, String mime) {
        return "{"
                + "\"index\":" + index + ","
                + "\"method\":" + BridgeServer.jsonStr(method) + ","
                + "\"url\":" + BridgeServer.jsonStr(url) + ","
                + "\"host\":" + BridgeServer.jsonStr(host) + ","
                + "\"status\":" + status + ","
                + "\"length\":" + length + ","
                + "\"mime\":" + BridgeServer.jsonStr(mime)
                + "}";
    }

    private static Response bad(String msg) {
        return new Response(400, "{\"error\":" + BridgeServer.jsonStr(msg) + "}");
    }

    private static Response notFound(String msg) {
        return new Response(404, "{\"error\":" + BridgeServer.jsonStr(msg) + "}");
    }

    private static int clampInt(String s, int min, int max, int def) {
        int v;
        try {
            v = Integer.parseInt(s.trim());
        } catch (Exception e) {
            return def;
        }
        if (v < min) return min;
        if (v > max) return max;
        return v;
    }

    private static Pattern compileSafe(String rx) {
        if (rx == null || rx.isEmpty()) return null;
        try {
            return Pattern.compile(rx);
        } catch (Exception e) {
            return Pattern.compile(Pattern.quote(rx));
        }
    }
}
