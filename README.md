# Log4j: configuration-time evaluation of untrusted Thread Context Map data → RCE

> **Disclosure status — first and only disclosure.**
> This repository is the **first and only public disclosure** of the issue described below.
> Before this repository was published the issue had **not** been reported to the Apache
> Logging Services project, **not** sent to any vendor, **not** shared with any third party,
> and **not** published in an advisory, mailing list post, blog, conference talk, preprint,
> issue tracker, or chat anywhere else. No prior disclosure exists.
>
> If you run Log4j and this affects you, please forward this to the vendor:
> <security@apache.org> (the Apache Logging Services security process, per
> <https://logging.apache.org/security.html>).

**Component:** `org.apache.logging.log4j:log4j-core`
**Severity:** Critical
**CVSS 3.1:** `10.0 AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
**CWE:** CWE-917 (improper neutralization of special elements in an outbound message) →
CWE-94 (improper control of generation of code) / CWE-200 (information exposure)
**Affected:** `log4j-core` 2.14.1 – **2.26.1** (current release) — verified by execution
**Not affected:** `log4j-api` alone (no lookup engine), `log4j-1.2-api` bridge,
`log4j 1.x` (different code path), Log4j 3.x (JNDI removed; the substitutor split below is
unchanged, so the same defect is expected there — source-level only, see *Limitations*)
**Found:** 2026-10-23

---

## 1. The defect in one paragraph

Log4j keeps two substitutors with deliberately different policies.
`RuntimeStrSubstitutor` resolves a lookup but does **not** evaluate lookups inside the result.
`ConfigurationStrSubstitutor` does — its own javadoc says:

> *"A `StrSubstitutor` which only supports recursive evaluation of lookups. **This can be
> dangerous when combined with user-provided inputs, and should only be used on data directly
> from a configuration.**"*

Configuration values — including **every plugin attribute** — are substituted with the
*recursive* one at configuration load time:

```java
// log4j-core 2.26.1, config/plugins/util/PluginBuilder.java:185-194
.setStrSubstitutor(
        event == null
                ? configuration.getConfigurationStrSubstitutor()   // configuration load -> recursive
                : configuration.getStrSubstitutor())                // runtime -> top level only
```

The Thread Context Map is reachable as the `ctx` lookup, and Apache's own threat model states
that thread-context values are **untrusted**
(<https://logging.apache.org/security.html>: *"They do not trust the values stored in the thread
context."*).

**⇒ When Log4j loads or reloads its configuration while the Thread Context Map contains
attacker-controlled data, that data is evaluated as a Log4j template.**

Two triggers, either is enough:

* the MDC is populated before Log4j initialises — the configuration is loaded at the first
  logger use, so the value is already there when the substitution runs;
* the configuration is reloaded while the MDC holds the data — `Configurator.reconfigure()`,
  `monitorInterval`, a management endpoint, a plugin reload.

## 2. Impact A — remote code execution (critical)

A configuration that interpolates a lookup into a script attribute turns the defect into code
execution, because the substituted value becomes the **script source** Log4j compiles and runs:

```xml
<Filters>
  <ScriptFilter onMatch="NEUTRAL" onMismatch="DENY">
    <Script language="groovy" scriptText="${ctx:scriptText}"/>
  </ScriptFilter>
</Filters>
```

1. The attacker puts their payload into the Thread Context Map.
2. Log4j loads or reloads its configuration → the plugin attribute is substituted → the payload
   becomes the script text.
3. The next log event runs the filter → `ScriptManager.execute()` compiles and runs the
   attacker's code in the application JVM.

Measured:

```
=== PAYLOAD EXECUTED IN VICTIM JVM (script) ===
RCE via log4j script (config-time lookup evaluation) as hayden pid=9285
uid=1000(hayden) gid=1000(hayden) groups=1000(hayden),4(adm),24(cdrom),27(sudo),...
```

| log4j-core | 2.14.1 | 2.15.0 | 2.16.0 | 2.17.1 | 2.24.0 | 2.25.1 | **2.26.1** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RCE | yes | yes | yes | yes | yes | yes | **yes** |

A second variant lets the attacker choose the script *file*: `<ScriptFile path="${ctx:scriptPath}"/>`
→ `ScriptFile.createScript()` accepts a URI and fetches it
(`core/script/ScriptFile.java:104`: `uri.toURL().openStream()`), so Log4j downloads the
attacker's script and runs it. The lab captured the download:

```
SCRIPT <- GET /evil.groovy
```

Preconditions for this chain: scripting enabled (`log4j2.Script.enableLanguages` plus a JSR-223
engine on the classpath) **and** a configuration that interpolates a lookup into a script
attribute. Without an engine the chain fails closed.

## 3. Impact B — secret disclosure, no special configuration needed

Any configuration that references a lookup in a layout (`${ctx:...}`) and any application that
puts untrusted data in the MDC gets the value resolved **at configuration time** and baked into
the pattern, so the resolved value is then written to *every* subsequent log line:

| lookup | resolves to (measured on 2.26.1) |
| --- | --- |
| `${env:HOME}` | `/home/hayden` |
| `${sys:user.name}` | `hayden` |
| `${java:version}` | `Java version 17.0.21-ea` |
| `${log4j:configLocation}` | `jar:file:/…/log4j2-ctx.xml!/log4j2-ctx.xml` |

Environment variables and system properties are where cloud keys, database URLs and tokens
live, and logs are usually shipped to aggregators with a wider audience than the application
itself. **CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5 (High), or
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` = 8.5 when the log pipeline crosses a trust boundary.

## 4. Reproduce it (localhost only)

```bash
./setup.sh                 # fetch jars + Log4j sources
./lab/build.sh             # compile victim / attacker / payload
./lab/run_script_rce.sh 2.26.1 startup   # -> RESULT ... RCE
./lab/run_script_rce.sh 2.26.1 reload    # same, via a reconfiguration
./lab/verify.sh            # 34 assertions over every claim in WORKUP.md
```

All traffic binds to `127.0.0.1`. The lab contacts no third-party host, scans nothing, and
carries no target list. The command it executes in the victim JVM is `id`.

## 5. Detection

* Grep the deployed configuration for script attributes that interpolate a lookup:
  `<Script[^>]*(scriptText|path)="[^"]*\$\{`.
* Check whether scripting is enabled: `log4j2.Script.enableLanguages` in the JVM flags or in
  `log4j2.component.properties`.
* Look for outbound HTTP(S) from the application at start-up or at reconfiguration — a
  configuration that fetches a script from a URL is visible on the wire.
* `StatusLogger` messages: `Error running script …`, `No script with name … has been declared`.
* For the disclosure variant: check whether a layout uses `${ctx:...}` instead of `%X{...}`, and
  whether the MDC carries request data.

## 6. Remediation

* Do not interpolate untrusted data into configuration attributes — in particular never use a
  lookup for a script source or path.
* Keep scripting disabled (`log4j2.Script.enableLanguages` unset) unless it is required.
* Keep the Thread Context Map free of untrusted input at configuration load/reload time, or
  avoid `${ctx:...}` in layouts and use `%X{...}`.
* Treat environment variables and system properties as secrets; they must not reach logs.
* Upstream fix direction: the configuration-time substitutor should not evaluate lookups whose
  values come from untrusted context data — the runtime substitutor already has exactly that
  policy, and the same rule should apply to context-data lookups in the configuration path.

## 7. Repository contents

| Path | What it is |
| --- | --- |
| `WORKUP.md` | the full write-up: root cause with `file:line` evidence (Log4j **and** JDK sources), the measured exploitability matrix, the audit of what is closed in the current release, detection, remediation, and limitations |
| `lab/` | the proof-of-concept: victim apps, the malicious LDAP server, the script chain, and `verify.sh` (34 assertions) |
| `scan/scan_log4j.py` | finds Log4j in a project tree, classifies the versions, and flags configurations that interpolate a lookup into a script attribute |
| `setup.sh` | downloads the jars and sources the lab needs (nothing large is stored in git) |
| `sources/`, `lib/`, `analysis/` | downloaded artifacts and unpacked sources, created by `setup.sh` |

The lab also reproduces the historical, already-public Log4Shell chain (`log4j-core` ≤ 2.14.1)
and the 2.15.0/2.16.0 variants, for comparison — see `WORKUP.md` Part I.

## 8. Scope and ethics

* Every server in this repository listens on `127.0.0.1`; no external host is ever contacted.
* The payload executes `id` and writes a proof file; it does not persist, spread, or scan.
* No third-party system was tested, scanned, or contacted at any point.
* These labs are for testing systems you own or are authorised to test. The default Log4j
  configuration (`log4j2.xml`) is not vulnerable to Impact A; that chain needs a configuration
  that interpolates untrusted data into a script attribute.

## 9. Limitations

* Log4j 3.x is analysed at source level only: the `3.0.0-beta3` API artifact is not published
  to Maven Central, so it could not be executed here.
* Whether an attacker can trigger a *remote* configuration reload depends on the application,
  not on Log4j.
* The MDC is one of several context-data sources; a custom `ContextDataInjector` behaves the
  same way.
* The script chain was demonstrated with Groovy; any other JSR-223 engine behaves the same.

## 10. License

Apache License 2.0 — see `LICENSE`.
