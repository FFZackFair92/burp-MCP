package burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Version;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Il "ponte": un mini server HTTP che gira dentro Burp, solo su loopback.
 *
 * Implementato con java.net.ServerSocket (modulo java.base) perche' il
 * classloader delle estensioni di Burp NON espone com.sun.net.httpserver
 * (modulo jdk.httpserver) -> ClassNotFoundException.
 *
 * Contratto (usato dal server MCP Python e dal mock di test):
 *   - Ogni richiesta deve avere l'header  X-Burp-Token: <token>  (altrimenti 401).
 *   - GET /ping -> 200 {"status":"ok","product":...,"version":...,"edition":...}
 *
 * Per aggiungere un comando in futuro: route("GET", "/mio/comando", req -> ...).
 */
public class BridgeServer {

    /** Handler di una richiesta: riceve la Request e produce una Response. */
    @FunctionalInterface
    public interface Handler {
        Response handle(Request req) throws Exception;
    }

    public static final class Request {
        public final String method;
        public final String path;
        public final Map<String, String> headers; // chiavi in minuscolo
        public final Map<String, String> query;   // query param gia' URL-decodati
        public final String body;

        Request(String method, String path, Map<String, String> headers,
                Map<String, String> query, String body) {
            this.method = method;
            this.path = path;
            this.headers = headers;
            this.query = query;
            this.body = body;
        }

        /** Valore di un query param o default. */
        public String q(String name, String def) {
            String v = query.get(name);
            return (v == null || v.isEmpty()) ? def : v;
        }
    }

    public static final class Response {
        public final int status;
        public final String json;

        public Response(int status, String json) {
            this.status = status;
            this.json = json;
        }
    }

    private static final int MAX_HEADER_BYTES = 64 * 1024;
    private static final int MAX_BODY_BYTES = 8 * 1024 * 1024;
    private static final int SOCKET_TIMEOUT_MS = 15000;

    private final MontoyaApi api;
    private final int port;
    private final String token;
    private final Map<String, Handler> routes = new HashMap<>(); // chiave "METHOD PATH"

    private ServerSocket serverSocket;
    private ExecutorService workers;
    private volatile boolean running;

    public BridgeServer(MontoyaApi api, int port, String token) {
        this.api = api;
        this.port = port;
        this.token = token;
        registerRoutes();
    }

    /** Qui si registrano gli endpoint. Fase 1: solo /ping. */
    private void registerRoutes() {
        route("GET", "/ping", req -> {
            Version v = api.burpSuite().version();
            String version = v.major() + "." + v.minor() + "." + v.build();
            String body = "{"
                    + "\"status\":\"ok\","
                    + "\"product\":" + jsonStr(v.name()) + ","
                    + "\"version\":" + jsonStr(version) + ","
                    + "\"edition\":" + jsonStr(String.valueOf(v.edition()))
                    + "}";
            return new Response(200, body);
        });
    }

    public void route(String method, String path, Handler handler) {
        routes.put(method.toUpperCase() + " " + path, handler);
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port, 50, InetAddress.getByName("127.0.0.1"));
        workers = Executors.newFixedThreadPool(8);
        running = true;
        Thread accept = new Thread(this::acceptLoop, "burp-mcp-bridge-accept");
        accept.setDaemon(true);
        accept.start();
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (IOException ignored) {
        }
        if (workers != null) workers.shutdownNow();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket client = serverSocket.accept();
                workers.submit(() -> handleConnection(client));
            } catch (IOException e) {
                if (running) {
                    api.logging().logToError("[Burp MCP Bridge] accept: " + e.getMessage());
                }
                // se non running, e' la chiusura normale del socket
            }
        }
    }

    private void handleConnection(Socket socket) {
        try {
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            String headerBlock = readHeaderBlock(in);
            if (headerBlock == null || headerBlock.isEmpty()) {
                writeResponse(out, 400, "{\"error\":\"bad request\"}");
                return;
            }

            String[] lines = headerBlock.split("\r\n");
            String[] requestLine = lines[0].split(" ");
            if (requestLine.length < 2) {
                writeResponse(out, 400, "{\"error\":\"bad request line\"}");
                return;
            }
            String method = requestLine[0].toUpperCase();
            String rawPath = requestLine[1];
            String path = rawPath;
            Map<String, String> query = new HashMap<>();
            int q = rawPath.indexOf('?');
            if (q >= 0) {
                path = rawPath.substring(0, q);
                parseQuery(rawPath.substring(q + 1), query);
            }

            Map<String, String> headers = new HashMap<>();
            for (int i = 1; i < lines.length; i++) {
                int c = lines[i].indexOf(':');
                if (c > 0) {
                    String name = lines[i].substring(0, c).trim().toLowerCase();
                    String value = lines[i].substring(c + 1).trim();
                    headers.put(name, value);
                }
            }

            // Corpo (se presente Content-Length)
            String body = "";
            String cl = headers.get("content-length");
            if (cl != null) {
                int len;
                try {
                    len = Integer.parseInt(cl.trim());
                } catch (NumberFormatException e) {
                    len = 0;
                }
                if (len > MAX_BODY_BYTES) {
                    writeResponse(out, 413, "{\"error\":\"payload too large\"}");
                    return;
                }
                body = readBody(in, len);
            }

            // Auth
            if (token == null || !token.equals(headers.get("x-burp-token"))) {
                writeResponse(out, 401, "{\"error\":\"unauthorized\"}");
                return;
            }

            Handler handler = routes.get(method + " " + path);
            if (handler == null) {
                writeResponse(out, 404, "{\"error\":\"not found\"}");
                return;
            }

            try {
                Response resp = handler.handle(new Request(method, path, headers, query, body));
                writeResponse(out, resp.status, resp.json);
            } catch (Exception e) {
                writeResponse(out, 500, "{\"error\":" + jsonStr(String.valueOf(e.getMessage())) + "}");
            }
        } catch (IOException e) {
            // connessione interrotta: ignora
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    /** Legge i byte fino a CRLFCRLF e li ritorna come stringa ASCII (header). */
    private static String readHeaderBlock(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int b;
        int matched = 0; // stato per riconoscere \r\n\r\n
        while ((b = in.read()) != -1) {
            buf.write(b);
            if ((matched == 0 || matched == 2) && b == '\r') {
                matched++;
            } else if ((matched == 1 || matched == 3) && b == '\n') {
                matched++;
                if (matched == 4) break;
            } else {
                matched = 0;
            }
            if (buf.size() > MAX_HEADER_BYTES) break;
        }
        return buf.toString("US-ASCII");
    }

    /** Parsa una query string (a=1&b=2) con URL-decoding nel map fornito. */
    private static void parseQuery(String qs, Map<String, String> out) {
        if (qs == null || qs.isEmpty()) return;
        for (String pair : qs.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String k, v;
            try {
                if (eq >= 0) {
                    k = URLDecoder.decode(pair.substring(0, eq), "UTF-8");
                    v = URLDecoder.decode(pair.substring(eq + 1), "UTF-8");
                } else {
                    k = URLDecoder.decode(pair, "UTF-8");
                    v = "";
                }
                out.put(k, v);
            } catch (Exception ignored) {
                // param malformato: salta
            }
        }
    }

    /** Legge esattamente len byte del corpo (UTF-8). */
    private static String readBody(InputStream in, int len) throws IOException {
        byte[] data = new byte[len];
        int off = 0;
        while (off < len) {
            int r = in.read(data, off, len - off);
            if (r == -1) break;
            off += r;
        }
        return new String(data, 0, off, StandardCharsets.UTF_8);
    }

    private static void writeResponse(OutputStream out, int status, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        StringBuilder head = new StringBuilder();
        head.append("HTTP/1.1 ").append(status).append(' ').append(reason(status)).append("\r\n");
        head.append("Content-Type: application/json; charset=utf-8\r\n");
        head.append("Content-Length: ").append(body.length).append("\r\n");
        head.append("Connection: close\r\n");
        head.append("\r\n");
        out.write(head.toString().getBytes(StandardCharsets.US_ASCII));
        out.write(body);
        out.flush();
    }

    private static String reason(int status) {
        switch (status) {
            case 200: return "OK";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 404: return "Not Found";
            case 413: return "Payload Too Large";
            case 500: return "Internal Server Error";
            default:  return "Status";
        }
    }

    /** Escaping minimale per stringhe JSON (evita dipendenze esterne). */
    static String jsonStr(String s) {
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
