#!/usr/bin/env bash
# Fetches everything the lab needs. Nothing large is stored in git.
#
#   ./setup.sh                 jars + Log4j sources
#   ./setup.sh --with-jdk-sources   also unpack the JDK naming sources (for the citations)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
M=https://repo1.maven.org/maven2

LOG4J_VERSIONS="2.14.1 2.15.0 2.16.0 2.17.1 2.24.0 2.25.1 2.26.1"

mkdir -p "$ROOT/lib" "$ROOT/sources"

echo "== log4j jars"
for v in $LOG4J_VERSIONS; do
    for a in log4j-api log4j-core; do
        f="$a-$v.jar"
        [ -f "$ROOT/lib/$f" ] || curl -sS -m 120 -o "$ROOT/lib/$f" "$M/org/apache/logging/log4j/$a/$v/$f"
    done
done

echo "== lab dependencies"
curl -sS -m 120 -o "$ROOT/lib/unboundid-ldapsdk-6.0.11.jar" \
    "$M/com/unboundid/unboundid-ldapsdk/6.0.11/unboundid-ldapsdk-6.0.11.jar"
curl -sS -m 120 -o "$ROOT/lib/slf4j-api-1.7.36.jar" "$M/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar"
curl -sS -m 120 -o "$ROOT/lib/slf4j-nop-1.7.36.jar" "$M/org/slf4j/slf4j-nop/1.7.36/slf4j-nop-1.7.36.jar"
curl -sS -m 180 -o "$ROOT/lib/groovy-4.0.24.jar" "$M/org/apache/groovy/groovy/4.0.24/groovy-4.0.24.jar"
curl -sS -m 120 -o "$ROOT/lib/groovy-jsr223-4.0.24.jar" \
    "$M/org/apache/groovy/groovy-jsr223/4.0.24/groovy-jsr223-4.0.24.jar"

echo "== Log4j sources (for the file:line citations)"
for v in $LOG4J_VERSIONS; do
    f="log4j-core-$v-sources.jar"
    [ -f "$ROOT/sources/$f" ] || curl -sS -m 120 -o "$ROOT/sources/$f" \
        "$M/org/apache/logging/log4j/log4j-core/$v/$f"
    mkdir -p "$ROOT/sources/$v"
    (cd "$ROOT/sources/$v" && unzip -oq "../$f")
done
curl -sS -m 120 -o "$ROOT/sources/log4j-api-2.26.1-sources.jar" \
    "$M/org/apache/logging/log4j/log4j-api/2.26.1/log4j-api-2.26.1-sources.jar"
mkdir -p "$ROOT/sources/api-2.26.1"
(cd "$ROOT/sources/api-2.26.1" && unzip -oq "../log4j-api-2.26.1-sources.jar")

if [ "${1:-}" = "--with-jdk-sources" ]; then
    echo "== JDK naming sources (for the analysis citations)"
    mkdir -p "$ROOT/analysis/jdksrc/jdk8full" "$ROOT/analysis/jdksrc/jdk17full"
    J8="${JAVA8_HOME:-/usr/lib/jvm/java-8-openjdk-amd64}"
    J17="${JAVA17_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
    [ -f "$J8/src.zip" ] && unzip -oq "$J8/src.zip" 'com/sun/*' 'javax/naming/*' -d "$ROOT/analysis/jdksrc/jdk8full" || true
    [ -f "$J17/lib/src.zip" ] && unzip -oq "$J17/lib/src.zip" 'java.naming/*' -d "$ROOT/analysis/jdksrc/jdk17full" || true
fi

echo "done. now: ./lab/build.sh && ./lab/verify.sh"
