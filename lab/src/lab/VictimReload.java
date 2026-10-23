package lab;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

/**
 * Realistic current-release scenario: the configuration is loaded at startup (empty MDC),
 * the attacker then puts untrusted data into the Thread Context Map, and the application
 * reconfigures Log4j (Configurator.reconfigure(), a monitored configuration file, or a
 * management endpoint). The configuration is substituted again at that point.
 */
public final class VictimReload {

    public static void main(final String[] args) {
        final Logger log = LogManager.getLogger("victim"); // configuration loaded here
        final String userInput = args.length > 0 ? args[0] : "hello";

        ThreadContext.put("ua", userInput);

        // reconfigure: the configuration (and its patterns) are substituted again
        try {
            org.apache.logging.log4j.core.config.Configurator.reconfigure();
        } catch (final Throwable t) {
            System.out.println("reconfigure failed: " + t);
        }

        log.info("request handled");
        ThreadContext.clearMap();
        System.out.println("VICTIM: logged ctx ua=" + userInput);
    }

    private VictimReload() {}
}
