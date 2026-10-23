#!/usr/bin/env python3
"""Find Apache Log4j artifacts in a project tree and classify them by exploitability.

The verdicts are the ones this repo verified empirically (see WORKUP.md and lab/verify.sh),
not a copy of a CVE list.

Usage:
    scan_log4j.py <path> [--json]
"""

import argparse
import json
import os
import re
import sys
import zipfile

# ---- verdicts -----------------------------------------------------------------
# log4j-core: JNDI message lookup -> attacker LDAP -> RCE.
VULN_CORE = ("2.0-beta9", "2.14.1")  # inclusive range
COND_CORE = ("2.15.0", "2.16.0")  # inclusive range
SAFE_FROM = "2.17.1"

LOG4J1_VULN = ("1.0", "1.2.17")  # log4j 1.x: EOL, JNDIAppender/JMSAppender RCE

ARTIFACTS = ("log4j-core", "log4j-api", "log4j-1.2-api", "log4j", "log4j-slf4j-impl")

POM_DEP = re.compile(
    r"<groupId>\s*(org\.apache\.logging\.log4j|log4j)\s*</groupId>\s*"
    r"<artifactId>\s*([\w.\-]+)\s*</artifactId>\s*"
    r"(?:<version>\s*([\w.\-+]+)\s*</version>)?",
    re.S,
)
GRADLE_DEP = re.compile(
    r"(?:group|groupId)\s*[:=]\s*['\"](org\.apache\.logging\.log4j|log4j)['\"]\s*[,)]?\s*"
    r"[\s\S]{0,80}?name\s*[:=]\s*['\"]([\w.\-]+)['\"]\s*[,)]?\s*"
    r"(?:version\s*[:=]\s*['\"]([\w.\-+]+)['\"])?"
)
GRADLE_SHORT = re.compile(
    r"['\"](org\.apache\.logging\.log4j|log4j):([\w.\-]+):([\w.\-+]+)['\"]"
)
JAR_VERSION = re.compile(r"([\w.\-]+)-(\d[\w.\-+]*)\.jar$")


def parse_version(v):
    """(major, minor, patch) plus a pre-release marker so betas sort before releases."""
    if not v:
        return None
    v = v.strip()
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?(.*)$", v)
    if not m:
        return None
    major, minor, patch, rest = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0), m.group(4)
    pre = 0 if re.search(r"(alpha|beta|rc)", rest) else 1
    return (major, minor, patch, pre)


def in_range(v, lo, hi):
    pv = parse_version(v)
    return pv is not None and parse_version(lo) <= pv <= parse_version(hi)


def classify(artifact, version):
    """-> (severity, title, detail)"""
    if artifact == "log4j" or (artifact == "log4j-core" and version.startswith("1.")):
        if in_range(version, *LOG4J1_VULN):
            return (
                "CRITICAL",
                "log4j 1.x end-of-life: JNDIAppender/JMSAppender RCE",
                "log4j 1.x is unmaintained since 2015 and its JNDI/JMS appenders are RCE-prone. "
                "Replace with log4j 2.x (>= 2.17.1) or the log4j-1.2-api bridge.",
            )
        return ("INFO", "log4j 1.x", "Unmaintained branch; check the config for JNDI/JMS appenders.")
    if artifact == "log4j-1.2-api":
        return (
            "INFO",
            "log4j 1.2 compatibility bridge",
            "The bridge ships no JNDIAppender/JMSAppender/SocketServer, so JNDI RCE is not reachable "
            "through it. It still bridges unmaintained 1.x behaviour.",
        )
    if artifact == "log4j-api":
        return (
            "INFO",
            "log4j-api only",
            "log4j-api alone has no lookup engine, only log4j-core is exploitable. Still track its "
            "version: CVE-2026-49844 affects log4j-api < 2.25.5 and 2.26.0.",
        )
    # log4j-core
    if in_range(version, *VULN_CORE):
        return (
            "CRITICAL",
            "JNDI lookup RCE via log content",
            "log4j-core resolves ${jndi:...} inside log messages. Any user-controlled value that "
            "reaches a log message gives remote code execution through an attacker LDAP server.",
        )
    if in_range(version, *COND_CORE):
        return (
            "HIGH",
            "JNDI RCE through the Thread Context Map path",
            "The message path is closed by default, but MDC/ThreadContext values are still "
            "substituted and still reach JNDI; a layout using %msg{lookups} re-enables the message "
            "path, which makes this version Critical (RCE straight from a log message) rather than "
            "High. 2.15.0/2.16.0 also allowlist the *advertised* javaClassName instead of the class "
            "actually in the deserialization stream, and the attacker controls that attribute.",
        )
    if parse_version(version) and parse_version(version) >= parse_version(SAFE_FROM):
        return (
            "OK",
            "JNDI message lookups are closed",
            "JndiManager.lookup() accepts only scheme-less and java: names, so ldap:// and rmi:// "
            "cannot be reached from log content. Keep it patched anyway.",
        )
    return ("UNKNOWN", "unclassified version", "Check the release notes for this version.")


def scan_pom(path, findings):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return
    for m in POM_DEP.finditer(text):
        group, artifact, version = m.group(1), m.group(2), m.group(3)
        if artifact not in ARTIFACTS:
            continue
        line = text.count("\n", 0, m.start()) + 1
        findings.append(
            {
                "artifact": "%s:%s" % (group, artifact),
                "version": version or "(managed elsewhere)",
                "location": "%s:%d" % (path, line),
                "kind": "pom",
            }
        )


def scan_gradle(path, findings):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return
    for m in GRADLE_DEP.finditer(text):
        group, artifact, version = m.group(1), m.group(2), m.group(3)
        if artifact not in ARTIFACTS:
            continue
        line = text.count("\n", 0, m.start()) + 1
        findings.append(
            {
                "artifact": "%s:%s" % (group, artifact),
                "version": version or "(managed elsewhere)",
                "location": "%s:%d" % (path, line),
                "kind": "gradle",
            }
        )
    # shorthand notation: implementation "org.apache.logging.log4j:log4j-core:2.14.1"
    for m in GRADLE_SHORT.finditer(text):
        group, artifact, version = m.group(1), m.group(2), m.group(3)
        if artifact not in ARTIFACTS:
            continue
        line = text.count("\n", 0, m.start()) + 1
        findings.append(
            {
                "artifact": "%s:%s" % (group, artifact),
                "version": version,
                "location": "%s:%d" % (path, line),
                "kind": "gradle",
            }
        )


def scan_jar(path, findings):
    m = JAR_VERSION.search(os.path.basename(path))
    if not m:
        return
    name, version = m.group(1), m.group(2)
    if name not in ARTIFACTS:
        return
    # prefer the version recorded inside the jar
    try:
        with zipfile.ZipFile(path) as zf:
            for entry in zf.namelist():
                if entry.endswith("pom.properties"):
                    props = zf.read(entry).decode("utf-8", "replace")
                    vm = re.search(r"^version=(.+)$", props, re.M)
                    if vm:
                        version = vm.group(1).strip()
                    break
    except (OSError, zipfile.BadZipFile):
        pass
    findings.append(
        {
            "artifact": name,
            "version": version,
            "location": path,
            "kind": "jar",
        }
    )


SCRIPT_ELEM = re.compile(
    r"<(Script|ScriptFile)\b[^>]*\b(scriptText|path)\s*=\s*\"([^\"]*\$\{[^\"]*)\"",
    re.S,
)


def scan_config(path, findings):
    """A configuration that interpolates a lookup into a script attribute is the trigger of
    the configuration-time evaluation finding (RCE via the script source)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return
    for m in SCRIPT_ELEM.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        findings.append(
            {
                "artifact": "log4j configuration",
                "version": m.group(3),
                "location": "%s:%d" % (path, line),
                "kind": "config",
            }
        )


def walk(root):
    skip = {".git", "node_modules", "build", "target", ".venv", "__pycache__", ".m2"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            yield os.path.join(dirpath, name)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    findings = []
    for f in walk(args.path):
        base = os.path.basename(f)
        if base == "pom.xml":
            scan_pom(f, findings)
        elif base in ("build.gradle", "build.gradle.kts"):
            scan_gradle(f, findings)
        elif base.endswith(".jar"):
            scan_jar(f, findings)
        elif base.endswith(".xml") and "log4j" in base.lower():
            scan_config(f, findings)

    order = {"CRITICAL": 0, "HIGH": 1, "UNKNOWN": 2, "INFO": 3, "OK": 4}
    rows = []
    for item in findings:
        artifact = item["artifact"].split(":")[-1]
        if item["kind"] == "config":
            sev, title, detail = (
                "CRITICAL",
                "configuration interpolates a lookup into a script attribute",
                "Plugin attributes are substituted with the recursive ConfigurationStrSubstitutor at "
                "configuration load time. If the Thread Context Map holds attacker-controlled data at that "
                "moment, it becomes the script source Log4j compiles and runs (RCE). Verified on "
                "log4j-core 2.14.1 - 2.26.1.",
            )
        else:
            sev, title, detail = classify(artifact, item["version"])
        rows.append(dict(item, severity=sev, title=title, detail=detail))
    rows.sort(key=lambda r: (order.get(r["severity"], 9), r["artifact"], r["version"]))

    if args.json:
        print(json.dumps(rows, indent=2))
        return 0

    if not rows:
        print("no log4j artifacts found under %s" % args.path)
        return 0
    for r in rows:
        print("%-8s %-28s %-12s %s" % (r["severity"], r["artifact"], r["version"], r["location"]))
        print("         %s" % r["title"])
        if r["severity"] in ("CRITICAL", "HIGH"):
            print("         %s" % r["detail"])
    worst = min((order.get(r["severity"], 9) for r in rows), default=9)
    print()
    names = ["CRITICAL", "HIGH", "UNKNOWN", "INFO", "OK"]
    print("worst severity: %s" % (names[worst] if worst < len(names) else "OK"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
