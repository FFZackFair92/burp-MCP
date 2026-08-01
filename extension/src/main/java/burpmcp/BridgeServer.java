package burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Version;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;

/**
 * Il "ponte": un server HTTP che gira dentro Burp, in ascolto solo su loopback.
 *
 * Contratto (usato dal server MCP Python e dal mock di test):
 *   - Ogni richiesta deve avere l'header  X-Burp-Token: <token>  (altrimenti 401).
 *   - GET /ping -> 200 {"status":"ok","product":"...","version":"...","edition":"..."}
 *
 * Per aggiungere un comando in futuro: http.createContext("/mio/comando", handler).
 */
public class BridgeServer {

    private final MontoyaApi api;
    private final int port;
    private final String token;
    private HttpServer http;

    public BridgeServer(MontoyaApi api, int port, String token) {
        this.api = api;
        this.port = port;
        this.token = token;
    }

    public void start() throws IOException {
        http = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        http.createContext("/ping", authed(this::handlePing));
        http.setExecutor(Executors.newFixedThreadPool(4));
        http.start();
    }

    public void stop() {
        if (http != null) {
            http.stop(0);
            http = null;
        }
    }

    /** Wrapper che applica il controllo del token prima di ogni handler. */
    private HttpHandler authed(HttpHandler inner) {
        return exchange -> {
            String provided = exchange.getRequestHeaders().getFirst("X-Burp-Token");
            if (token == null || !token.equals(provided)) {
                respond(exchange, 401, "{\"error\":\"unauthorized\"}");
                return;
            }
            try {
                inner.handle(exchange);
            } catch (Exception e) {
                respond(exchange, 500, "{\"error\":" + jsonStr(String.valueOf(e.getMessage())) + "}");
            }
        };
    }

    private void handlePing(HttpExchange ex) throws IOException {
        Version v = api.burpSuite().version();
        String version = v.major() + "." + v.minor() + "." + v.build();
        String body = "{"
                + "\"status\":\"ok\","
                + "\"product\":" + jsonStr(v.name()) + ","
                + "\"version\":" + jsonStr(version) + ","
                + "\"edition\":" + jsonStr(String.valueOf(v.edition()))
                + "}";
        respond(ex, 200, body);
    }

    private void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    /** Escaping minimale per stringhe JSON (evita dipendenze esterne). */
    private static String jsonStr(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.append("\"").toString();
    }
}
