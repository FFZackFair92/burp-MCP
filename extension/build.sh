#!/usr/bin/env bash
# Build senza Gradle (Linux/macOS): serve solo un JDK 17+ nel PATH.
set -euo pipefail
cd "$(dirname "$0")"

MONTOYA_VER="2026.4"
MONTOYA_JAR="lib/montoya-api-${MONTOYA_VER}.jar"
MONTOYA_URL="https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/${MONTOYA_VER}/montoya-api-${MONTOYA_VER}.jar"

command -v javac >/dev/null || { echo "[ERRORE] javac non trovato. Installa un JDK 17+."; exit 1; }

mkdir -p lib
if [ ! -f "$MONTOYA_JAR" ]; then
  echo "Scarico Montoya API ${MONTOYA_VER}..."
  curl -fSL "$MONTOYA_URL" -o "$MONTOYA_JAR"
fi

rm -rf build && mkdir -p build/classes build/libs
echo "Compilo..."
find src/main/java -name '*.java' > build/sources.txt
javac -cp "$MONTOYA_JAR" -d build/classes @build/sources.txt

echo "Creo il JAR..."
jar cf build/libs/burp-mcp-bridge-0.1.0.jar -C build/classes burpmcp
echo "OK -> extension/build/libs/burp-mcp-bridge-0.1.0.jar"
