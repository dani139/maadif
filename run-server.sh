#!/bin/bash
# MAADIF API Server Startup Script

set -e

PORT=${MAADIF_PORT:-8080}
APKS_DIR=${MAADIF_APKS_DIR:-/workspace/apks}
OUTPUT_DIR=${MAADIF_OUTPUT_DIR:-/workspace/output}
DATA_DIR=${MAADIF_DATA_DIR:-/workspace/data}

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                    MAADIF API Server Startup                                 ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo

# Create directories
mkdir -p "$APKS_DIR" "$OUTPUT_DIR" "$DATA_DIR"

# Check if we need to build
if [ ! -f "target/maadif-analyzer-1.0.0.jar" ]; then
    echo "[Server] Building analyzer..."
    bash build.sh
fi

# Build classpath
JADX_CP="/opt/jadx/lib/jadx-1.5.1-all.jar"
SQLITE_CP="/opt/sqlite-jdbc.jar"

GHIDRA_HOME=${GHIDRA_HOME:-/opt/ghidra}
GHIDRA_CP=""
for jar in $(find $GHIDRA_HOME/Ghidra -name "*.jar" -path "*/lib/*" 2>/dev/null); do
    if [ -n "$GHIDRA_CP" ]; then
        GHIDRA_CP="$GHIDRA_CP:$jar"
    else
        GHIDRA_CP="$jar"
    fi
done

CLASSPATH="target/maadif-analyzer-1.0.0.jar:$JADX_CP:$GHIDRA_CP:$SQLITE_CP"

# Java options - 16GB heap for large native library analysis
JAVA_OPTS="-Xmx16g -Xms4g -XX:+UseG1GC -XX:MaxGCPauseMillis=200"

echo "[Server] Starting API server on port $PORT..."
echo

# Export environment variables
export MAADIF_APKS_DIR="$APKS_DIR"
export MAADIF_OUTPUT_DIR="$OUTPUT_DIR"
export MAADIF_DATA_DIR="$DATA_DIR"

# Start server
exec java $JAVA_OPTS -cp "$CLASSPATH" io.maadif.server.ApiServer $PORT
