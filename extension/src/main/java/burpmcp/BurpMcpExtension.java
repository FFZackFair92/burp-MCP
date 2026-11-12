package burpmcp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

import java.security.SecureRandom;
import java.util.HexFormat;

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
        // Token: quello scelto dall'utente (BURP_MCP_TOKEN), altrimenti uno casuale
        // generato al primo avvio e ricordato nelle preferenze di Burp. Il vecchio
        // default "changeme" non e' piu' accettato: chiunque sulla macchina lo conosce.
        String configured = conf("BURP_MCP_TOKEN");
        boolean userToken = configured != null && !configured.isBlank()
                && !WEAK_TOKEN.equals(configured.trim());
        boolean firstRun = false;
        String token;
        if (userToken) {
            token = configured.trim();
        } else {
            Preferences prefs = api.persistence().preferences();
            token = prefs.getString(PREF_TOKEN);
            if (token == null || token.isBlank()) {
                token = randomToken();
                prefs.setString(PREF_TOKEN, token);
                firstRun = true;
            }
        }
        boolean showFull = firstRun || "1".equals(conf("BURP_MCP_SHOW_TOKEN"));

        try {
            server = new BridgeServer(api, port, token);
            Commands.register(server, api);   // Fase 2: scope, proxy history, sitemap, message, http send
            ExtraCommands.register(server, api); // Fase 6: opzioni Burp, task engine, editor attivo
            server.start();
            api.logging().logToOutput("[Burp MCP Bridge] In ascolto su http://127.0.0.1:" + port);
            if (showFull) {
                api.logging().logToOutput("[Burp MCP Bridge] Token (X-Burp-Token): " + token);
                api.logging().logToOutput("[Burp MCP Bridge] Copialo in BURP_BRIDGE_TOKEN nella config del server MCP.");
            } else {
                api.logging().logToOutput("[Burp MCP Bridge] Token (X-Burp-Token): " + mask(token)
                        + (userToken ? "  (da BURP_MCP_TOKEN)" : "  (generato, salvato nelle preferenze di Burp)"));
                api.logging().logToOutput("[Burp MCP Bridge] Per rivederlo per intero avvia Burp con BURP_MCP_SHOW_TOKEN=1.");
            }
            if (configured != null && WEAK_TOKEN.equals(configured.trim())) {
                api.logging().logToError("[Burp MCP Bridge] BURP_MCP_TOKEN=changeme ignorato: usato un token casuale.");
            }
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

    private static final String WEAK_TOKEN = "changeme";
    private static final String PREF_TOKEN = "burp_mcp_bridge_token";

    /** 32 byte casuali in esadecimale. */
    private static String randomToken() {
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        return HexFormat.of().formatHex(raw);
    }

    private static String mask(String token) {
        return token.length() <= 8 ? "****" : token.substring(0, 4) + "…" + token.substring(token.length() - 2);
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

    /** Legge prima una system property (-Dkey=...), poi una variabile d'ambiente. */
    private static String conf(String key) {
        String v = System.getProperty(key);
        if (v == null) v = System.getenv(key);
        return v;
    }
}
