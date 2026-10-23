# Disclosure status

One disclosure record for both findings from this audit. **Both repositories carry an identical
copy of this file.** Update both whenever anything changes.

## Findings covered

| id | finding | repository | canonical write-up |
| --- | --- | --- | --- |
| **B** | Configuration-time evaluation of untrusted Thread Context Map data → RCE (script source) and secret disclosure | <https://github.com/vindeckyy/log4j-config-time-lookup-rce> | `README.md` and `WORKUP.md` in that repository |
| **C** | Log4j silently applies two fixed-name classpath resources (`log4j2.system.properties`, `log4j2.component.properties`) → RCE (configuration hijack) and JVM-wide reconfiguration | <https://github.com/vindeckyy/log4j-classpath-plant-rce> | `README.md` and `WORKUP.md` in that repository |

Both were found in the same audit, on the same day, and are reported together through one
channel.

## Timeline

| date | event |
| --- | --- |
| 2026-10-23 | Both findings identified and reproduced end to end (`lab/verify.sh` in each repository: 34 and 15 assertions, all passing). |
| 2026-10-23 | Finding B's repository published. |
| 2026-10-23 | Finding C's repository published, later the same day. The second repository appeared after the first: the two findings were written up separately during the audit, and finding C's material was then moved out of finding B's repository so that each repository documents exactly one finding. |
| **pending** | Report sent to the Apache Logging Services security team — **one report covering both findings**. The text is in the *Report text* section below. |
| pending | Apache's response. |
| pending | Planned publication date. |

**Planned publication date:** to be recorded. If the report is sent on *D*, the target is *D + 90
days*, following the project's published process
(<https://logging.apache.org/security.html>).

**Advisory:** none yet. When one is published, link it here in place of this line:
<https://logging.apache.org/log4j/2.x/security.html> (project advisory page — to be replaced by
the specific advisory).

**Contact:** the reporter of this audit. Nothing in either repository is intended for use
against systems their owner has not authorised.

## Report text

This is the single report that will go to `security@apache.org`, covering both findings.

---

**To:** security@apache.org
**Subject:** Apache Log4j — two findings, reported together for coordinated disclosure

Hello,

I am reporting two independent defects in Apache Log4j. They came out of the same audit, they
are unrelated to each other, and I am sending them in one message so they can be handled on one
timeline. Both are reproduced end to end; the proof-of-concept code and the full analysis are
public in the repositories linked at the end.

**Finding 1 — configuration-time evaluation of untrusted Thread Context Map data**

`log4j-core` substitutes configuration values (including every plugin attribute) with
`ConfigurationStrSubstitutor`, which evaluates lookups inside lookup results, while the runtime
path (`RuntimeStrSubstitutor`) deliberately does not. The Thread Context Map is reachable
through the `ctx` lookup, and Apache's own threat model states that thread-context values are
untrusted. Consequently, when Log4j loads or reloads its configuration while the Thread Context
Map holds attacker-controlled data, that data is evaluated as a Log4j template.

* In a configuration that interpolates a lookup into a script attribute
  (`<Script scriptText="${ctx:…}"/>`), the attacker's value becomes the script source and is
  compiled and executed in the application JVM. Verified on `log4j-core` 2.14.1, 2.15.0, 2.16.0,
  2.17.1, 2.24.0, 2.25.1 and 2.26.1 — the current release.
* Without any special configuration, a layout that references a lookup (`${ctx:…}`) resolves the
  MDC value at configuration time and bakes the result into the pattern, so the resolved value
  is written to every subsequent log line. Environment variables and system properties are
  reachable this way.

Triggers are the first log statement after the MDC is populated, and any reconfiguration
(`Configurator.reconfigure()`, `monitorInterval`, a management endpoint, a plugin reload).

**Finding 2 — two fixed-name classpath resources are applied silently**

`log4j-api` reads two resources by fixed name from the classpath during its own initialization:
`log4j2.system.properties`, whose keys are copied into the **JVM system properties**, and
`log4j2.component.properties`, which supplies Log4j's own properties — including
`log4j.configurationFile` and `log4j2.Script.enableLanguages`. Neither file has to be requested
or enabled, and neither produces a warning.

* A single file on the classpath therefore reconfigures the JVM: pointing `log4j.configurationFile`
  at a configuration the attacker also ships (it may be a resource inside the same jar) and
  enabling scripting in the same file yields code execution in the application before its first
  log statement is rendered. Verified on `log4j-core` 2.14.1, 2.17.1, 2.24.0, 2.25.1 and 2.26.1.
* The system-property half works with `log4j-api` alone — no `log4j-core`, no appender, no
  configuration — so the exposed population is every application that has Log4j on its classpath.
* The same file also redirects the application's outbound traffic (`http.proxyHost`,
  `http.proxyPort`), which is measured in the repository.

The access condition is the one the score reflects: the attacker must be able to place a file on
the victim's classpath — write access to a classpath directory, or control of an artifact in the
dependency chain. That is a local write primitive, and the base vector is scored accordingly
(`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 7.8); delivery through dependency resolution raises the
environmental vector to `AV:N/PR:N`.

I am reporting this because the outcome is code execution and the file is applied silently and by
default, not because a setting can be changed by a file. Apache's documentation describes the
`log4j2.system.properties` file as a property source
(<https://logging.apache.org/log4j/2.x/manual/systemproperties.html>); it does not state that the
classpath is a trust boundary, does not mention that the file is applied to the JVM's global
namespace, and does not mention the configuration-hijack and scripting consequences. Whether the
classpath is an accepted trust boundary is a question for the project; if it is, that assumption
belongs in the documentation, and the behaviour should at least warn when it acts.

I am happy to test any fix, and I am happy to be acknowledged. I would like the two findings to
be handled on one timeline, and I will keep both repositories up to date until an advisory
exists. Unless you tell me otherwise, I plan to publish no further material before 90 days after
this report.

Full analysis, evidence and reproduction:

* Finding 1 — <https://github.com/vindeckyy/log4j-config-time-lookup-rce>
* Finding 2 — <https://github.com/vindeckyy/log4j-classpath-plant-rce>

Thank you,
