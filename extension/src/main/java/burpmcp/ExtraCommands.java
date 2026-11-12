package burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.TaskExecutionEngine;
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState;
import burpmcp.BridgeServer.Response;

import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Frame;
import java.awt.KeyboardFocusManager;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Fase 6: comandi aggiunti confrontando con l'estensione MCP ufficiale di PortSwigger
 * (PortSwigger/mcp-server): opzioni di progetto/utente in JSON, stato del task
 * execution engine, lettura/scrittura dell'editor di messaggi attivo.
 * Tutto disponibile anche in Burp Community.
 */
final class ExtraCommands {

    private ExtraCommands() {
    }

    static void register(BridgeServer server, MontoyaApi api) {

        // ---------- OPZIONI BURP (project / user) ----------
        server.route("GET", "/options/export", req -> {
            String scope = req.q("scope", "project");
            String pathsQ = req.q("paths", "").trim();
            String[] paths = pathsQ.isEmpty() ? new String[0] : pathsQ.split(",");
            for (int i = 0; i < paths.length; i++) paths[i] = paths[i].trim();
            String json;
            if (scope.equalsIgnoreCase("user")) json = api.burpSuite().exportUserOptionsAsJson(paths);
            else if (scope.equalsIgnoreCase("project")) json = api.burpSuite().exportProjectOptionsAsJson(paths);
            else return bad("scope deve essere 'project' o 'user'");
            return new Response(200, "{\"scope\":" + BridgeServer.jsonStr(scope.toLowerCase())
                    + ",\"options\":" + BridgeServer.jsonStr(json) + "}");
        });

        server.route("POST", "/options/import", req -> {
            String scope = req.q("scope", "project");
            String json = req.body;
            if (json == null || json.trim().isEmpty()) return bad("corpo (JSON delle opzioni) mancante");
            api.logging().logToOutput("[Burp MCP Bridge] import opzioni " + scope + ": " + json.length() + " caratteri");
            if (scope.equalsIgnoreCase("user")) api.burpSuite().importUserOptionsFromJson(json);
            else if (scope.equalsIgnoreCase("project")) api.burpSuite().importProjectOptionsFromJson(json);
            else return bad("scope deve essere 'project' o 'user'");
            return new Response(200, "{\"applied\":true,\"scope\":" + BridgeServer.jsonStr(scope.toLowerCase()) + "}");
        });

        // ---------- TASK EXECUTION ENGINE ----------
        server.route("GET", "/task-engine", req -> {
            TaskExecutionEngine engine = api.burpSuite().taskExecutionEngine();
            return new Response(200, "{\"state\":" + BridgeServer.jsonStr(String.valueOf(engine.getState())) + "}");
        });

        server.route("POST", "/task-engine", req -> {
            String s = req.q("state", "").toLowerCase();
            TaskExecutionEngineState target;
            if (s.equals("running") || s.equals("resume")) target = TaskExecutionEngineState.RUNNING;
            else if (s.equals("paused") || s.equals("pause")) target = TaskExecutionEngineState.PAUSED;
            else return bad("state deve essere 'running' o 'paused'");
            api.burpSuite().taskExecutionEngine().setState(target);
            return new Response(200, "{\"state\":" + BridgeServer.jsonStr(String.valueOf(target)) + "}");
        });

        // ---------- EDITOR ATTIVO (quello col focus nella finestra di Burp) ----------
        server.route("GET", "/editor", req -> {
            AtomicReference<String> text = new AtomicReference<>();
            AtomicReference<Boolean> editable = new AtomicReference<>(false);
            onEdt(() -> {
                JTextArea ed = activeEditor(api);
                if (ed != null) {
                    text.set(ed.getText());
                    editable.set(ed.isEditable());
                }
            });
            if (text.get() == null) return new Response(404, "{\"error\":\"nessun editor attivo\","
                    + "\"hint\":\"clicca dentro un editor di richiesta/risposta in Burp\"}");
            return new Response(200, "{\"editable\":" + editable.get() + ",\"text\":" + BridgeServer.jsonStr(text.get()) + "}");
        });

        server.route("POST", "/editor", req -> {
            String body = req.body == null ? "" : req.body;
            AtomicReference<String> outcome = new AtomicReference<>("none");
            onEdt(() -> {
                JTextArea ed = activeEditor(api);
                if (ed == null) return;
                if (!ed.isEditable()) {
                    outcome.set("readonly");
                    return;
                }
                ed.setText(body);
                outcome.set("ok");
            });
            switch (outcome.get()) {
                case "ok":
                    return new Response(200, "{\"set\":true,\"length\":" + body.length() + "}");
                case "readonly":
                    return new Response(409, "{\"error\":\"l'editor attivo non e' modificabile\"}");
                default:
                    return new Response(404, "{\"error\":\"nessun editor attivo\"}");
            }
        });
    }

    private static JTextArea activeEditor(MontoyaApi api) {
        Frame frame = api.userInterface().swingUtils().suiteFrame();
        Component owner = KeyboardFocusManager.getCurrentKeyboardFocusManager().getPermanentFocusOwner();
        if (!(owner instanceof JTextArea)) return null;
        for (Component c = owner; c != null; c = c.getParent()) {
            if (c == frame) return (JTextArea) owner;
        }
        return null;
    }

    private static void onEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
            return;
        }
        try {
            SwingUtilities.invokeAndWait(r);
        } catch (Exception e) {
            throw new RuntimeException("errore sul thread Swing: " + e, e);
        }
    }

    private static Response bad(String msg) {
        return new Response(400, "{\"error\":" + BridgeServer.jsonStr(msg) + "}");
    }
}
