package lab;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

/**
 * Same as VictimCtx, but the LoggerContext (and therefore the configuration) is created
 * BEFORE the Thread Context Map is populated. This separates "the configuration was
 * substituted while untrusted data was already in the MDC" from "the MDC value is
 * evaluated per event".
 */
public final class VictimCtx2 {

    public static void main(final String[] args) {
        final Logger log = LogManager.getLogger("victim"); // configuration is loaded here
        final String userInput = args.length > 0 ? args[0] : "hello";
        ThreadContext.put("ua", userInput);
        log.info("request handled");
        ThreadContext.clearMap();
        System.out.println("VICTIM: logged ctx ua=" + userInput);
    }
}
