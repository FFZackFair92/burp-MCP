package burpmcp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Punto di ingresso dell'estensione Burp.
 *
 * Fase 1 (il ponte): avvia un piccolo server HTTP locale che l'MCP server Python
 * usa per parlare con Burp. Per ora espone solo /ping (health check).
 * I comandi veri (proxy history, sitemap, repeater, ...) verranno aggiunti dopo,
 * registrando nuovi context su BridgeServer.
 */
public class BurpMcpExtension implements BurpExtension {

    private BridgeServer server;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Burp MCP Bridge");

        int port = intProp("BURP_MCP_PORT", 9876);
        String token = strConf("BURP_MCP_TOKEN", "changeme");

        try {
            server = new BridgeServer(api, port, token);
            Commands.register(server, api);   // Fase 2: scope, proxy history, sitemap, message, http send
            server.start();
            api.logging().logToOutput("[Burp MCP Bridge] In ascolto su http://127.0.0.1:" + port);
            api.logging().logToOutput("[Burp MCP Bridge] Token (X-Burp-Token): " + token);
            api.logging().logToOutput("[Burp MCP Bridge] Endpoint: /ping /scope/* /proxy/history /sitemap /message /http/send");
        } catch (Exception e) {
            api.logging().logToError("[Burp MCP Bridge] Avvio fallito: " + e.getMessage());
        }

        api.extension().registerUnloadingHandler(() -> {
            if (server != null) {
                server.stop();
            }
            api.logging().logToOutput("[Burp MCP Bridge] Server fermato.");
        });
    }

    private static int intProp(String key, int fallback) {
        String v = conf(key);
        if (v == null) return fallback;
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static String strConf(String key, String fallback) {
        String v = conf(key);
        return (v == null || v.isBlank()) ? fallback : v.trim();
    }

    /** Legge prima una system property (-Dkey=...), poi una variabile d'ambiente. */
    private static String conf(String key) {
        String v = System.getProperty(key);
        if (v == null) v = System.getenv(key);
        return v;
    }
}
