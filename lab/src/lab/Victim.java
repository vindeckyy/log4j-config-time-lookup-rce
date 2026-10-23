package lab;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Victim application: logs attacker-controlled input, exactly like a web app logging
 * a request header, user agent, or query parameter.
 */
public final class Victim {

    public static void main(final String[] args) throws Exception {
        final Logger log = LogManager.getLogger("victim");
        final String userInput = args.length > 0 ? args[0] : System.getProperty("lab.input", "hello");

        // This is the sink: the attacker string reaches the log message.
        log.info("request received, user-agent: {}", userInput);

        System.out.println("VICTIM: logged user-agent=" + userInput);
    }
}
