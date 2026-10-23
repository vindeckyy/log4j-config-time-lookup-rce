#!/usr/bin/env bash
# Verifies the claims in WORKUP.md by running the attack and checking the outcome.
# Exit code 0 = every expectation held.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

[ -d lab/build ] || ./lab/build.sh >/dev/null

fail=0
check() { # description expected(RCE|blocked) version mode victim [props]
    local desc="$1" expect="$2" ver="$3" mode="$4" victim="$5" props="${6:-}"
    local out got
    out=$(./lab/run.sh "$ver" "$mode" "$victim" "$props" | head -1)
    case "$out" in
        *": RCE") got=RCE ;;
        *) got=blocked ;;
    esac
    if [ "$got" = "$expect" ]; then
        printf 'PASS  %-58s expected=%-7s got=%s\n' "$desc" "$expect" "$got"
    else
        printf 'FAIL  %-58s expected=%-7s got=%s\n' "$desc" "$expect" "$got"
        fail=1
    fi
}

echo "== F1: log4j-core 2.14.1, JNDI in log content"
check "2.14.1 message path, factory class from attacker server" RCE 2.14.1 codebase log
check "2.14.1 message path, factory class on victim classpath"   RCE 2.14.1 classpath log

echo "== F2: 2.15.0 / 2.16.0, Thread Context Map path"
check "2.15.0 MDC path, javaSerializedData response"             RCE 2.15.0 serialized ctx
check "2.16.0 MDC path, javaSerializedData response"             RCE 2.16.0 serialized ctx "-Dlog4j2.enableJndi=true"
check "2.16.0 MDC path without enableJndi"                      blocked 2.16.0 serialized ctx

echo "== F2b: layouts that opted back into message lookups (%msg{lookups})"
check "2.15.0 message path, lookups option"                     RCE 2.15.0 serialized lookups
check "2.15.0 message path, lookups option, reference answer"   blocked 2.15.0 codebase lookups
check "2.16.0 message path, lookups option"                     blocked 2.16.0 serialized lookups "-Dlog4j2.enableJndi=true"
check "2.17.1 message path, lookups option"                     blocked 2.17.1 serialized lookups "-Dlog4j2.enableJndi=true -Dlog4j2.enableJndiLookup=true"

echo "== F3: configuration-time evaluation of untrusted Thread Context Map data"
check_script() { # description expected version order
    local desc="$1" expect="$2" ver="$3" order="$4"
    local out got
    out=$(./lab/run_script_rce.sh "$ver" "$order" | head -1)
    case "$out" in
        *": RCE") got=RCE ;;
        *) got=blocked ;;
    esac
    if [ "$got" = "$expect" ]; then
        printf 'PASS  %-58s expected=%-7s got=%s\n' "$desc" "$expect" "$got"
    else
        printf 'FAIL  %-58s expected=%-7s got=%s\n' "$desc" "$expect" "$got"
        fail=1
    fi
}
check_script "2.26.1 script source from MDC (startup order)"  RCE 2.26.1 startup
check_script "2.26.1 script source from MDC (reconfigure)"    RCE 2.26.1 reload
check_script "2.17.1 script source from MDC (startup order)"  RCE 2.17.1 startup
check_script "2.15.0 script source from MDC (startup order)"  RCE 2.15.0 startup
check_script "2.14.1 script source from MDC (startup order)"  RCE 2.14.1 startup
check_script "2.26.1 without script engine (must be blocked)" blocked 2.26.1 startup-nogroovy

echo "== F3b: JNDI through the same configuration-time path (older releases)"
check "2.15.0 reconfigure + javaSerializedData"               RCE 2.15.0 serialized reload
check "2.16.0 reconfigure + javaSerializedData + enableJndi" RCE 2.16.0 serialized reload "-Dlog4j2.enableJndi=true"
check "2.26.1 reconfigure + javaSerializedData"               blocked 2.26.1 serialized reload "-Dlog4j2.enableJndi=true -Dlog4j2.enableJndiLookup=true"

echo "== F4: the JNDI content path is closed in the current releases"
for v in 2.17.1 2.24.0 2.25.1 2.26.1; do
    check "$v message path"                                     blocked "$v" codebase log
    check "$v message path, class on classpath"                  blocked "$v" classpath log
    check "$v MDC path"                                         blocked "$v" serialized ctx
    check "$v MDC path, enableJndi turned on"                    blocked "$v" serialized ctx "-Dlog4j2.enableJndi=true -Dlog4j2.enableJndiLookup=true"
done

echo
if [ "$fail" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "SOME CHECKS FAILED"
fi
exit "$fail"
