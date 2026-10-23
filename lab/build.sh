#!/usr/bin/env bash
# Builds the jars used by the lab. Java 8 bytecode so the victim can run on JDK 8 and 17.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/lib"
OUT="$ROOT/lab/build"
JAVAC="${JAVAC:-/usr/lib/jvm/java-8-openjdk-amd64/bin/javac}"
JAR="${JAR:-/usr/lib/jvm/java-8-openjdk-amd64/bin/jar}"

rm -rf "$OUT"
mkdir -p "$OUT/payload" "$OUT/victim" "$OUT/attacker"

"$JAVAC" -d "$OUT/payload" "$ROOT/lab/src/lab/Payload.java" "$ROOT/lab/src/lab/Serial.java"
"$JAVAC" -d "$OUT/victim" -cp "$LIB/log4j-api-2.26.1.jar:$LIB/log4j-core-2.26.1.jar" \
    "$ROOT/lab/src/lab/Victim.java" "$ROOT/lab/src/lab/VictimCtx.java" "$ROOT/lab/src/lab/VictimCtx2.java" \
    "$ROOT/lab/src/lab/VictimReload.java" "$ROOT/lab/src/lab/VictimScript.java" \
    "$ROOT/lab/src/lab/VictimScript2.java"
"$JAVAC" -d "$OUT/attacker" -cp "$LIB/unboundid-ldapsdk-6.0.11.jar" \
    "$ROOT/lab/src/lab/Attacker.java" "$ROOT/lab/src/lab/Payload.java" "$ROOT/lab/src/lab/Serial.java" \
    "$ROOT/lab/src/lab/ScriptServer.java"

cp "$ROOT/lab/conf/log4j2.xml" "$OUT/victim/log4j2.xml"
cp "$ROOT/lab/conf/log4j2-ctx.xml" "$OUT/victim/log4j2-ctx.xml"
cp "$ROOT/lab/conf/log4j2-lookups.xml" "$OUT/victim/log4j2-lookups.xml"
cp "$ROOT/lab/conf/log4j2-script.xml" "$OUT/victim/log4j2-script.xml"
cp "$ROOT/lab/conf/log4j2-script-text.xml" "$OUT/victim/log4j2-script-text.xml"
cp "$ROOT/lab/conf/log4j2-script-url.xml" "$OUT/victim/log4j2-script-url.xml"

"$JAR" cf "$OUT/payload.jar" -C "$OUT/payload" .
"$JAR" cf "$OUT/victim.jar" -C "$OUT/victim" .
"$JAR" cf "$OUT/attacker.jar" -C "$OUT/attacker" .

echo "built -> $OUT"
