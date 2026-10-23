package lab;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

/**
 * Second victim shape: the attacker value arrives through the Thread Context Map (MDC),
 * e.g. a servlet putting the User-Agent header into the MDC. The pattern layout resolves
 * ${ctx:ua}, and the returned value is substituted again - that is the vector that
 * log4j-core 2.15.0 did not close.
 */
public final class VictimCtx {

    public static void main(final String[] args) {
        final String userInput = args.length > 0 ? args[0] : "hello";
        ThreadContext.put("ua", userInput);
        final Logger log = LogManager.getLogger("victim");
        log.info("request handled");
        ThreadContext.clearMap();
        System.out.println("VICTIM: logged ctx ua=" + userInput);
    }
}
