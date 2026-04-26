#!/bin/bash
# MAADIF Run Script - Execute the APK analyzer

set -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 <apk-file> [output-dir]"
    echo
    echo "Arguments:"
    echo "  apk-file    Path to the APK file to analyze"
    echo "  output-dir  Output directory (default: ./analysis_output/<apk-name>)"
    exit 1
fi

APK_FILE="$1"
OUTPUT_DIR="${2:-}"

if [ ! -f "$APK_FILE" ]; then
    echo "Error: APK file not found: $APK_FILE"
    exit 1
fi

# Build classpath
JADX_CP="/opt/jadx/lib/jadx-1.5.1-all.jar"

GHIDRA_HOME=${GHIDRA_HOME:-/opt/ghidra}
GHIDRA_CP=""
for dir in Framework Features Processors; do
    for jar in $(find "$GHIDRA_HOME/Ghidra/$dir" -name "*.jar" -path "*/lib/*" 2>/dev/null); do
        GHIDRA_CP="$GHIDRA_CP:$jar"
    done
done

CLASSPATH="target/maadif-analyzer-1.0.0.jar:$JADX_CP$GHIDRA_CP"

# Set memory options (increase for large APKs)
JAVA_OPTS="-Xmx8g -Xms2g"

# Run analyzer
if [ -n "$OUTPUT_DIR" ]; then
    java $JAVA_OPTS -cp "$CLASSPATH" io.maadif.analyzer.ApkAnalyzer "$APK_FILE" "$OUTPUT_DIR"
else
    java $JAVA_OPTS -cp "$CLASSPATH" io.maadif.analyzer.ApkAnalyzer "$APK_FILE"
fi
