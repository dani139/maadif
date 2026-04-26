#!/bin/bash
# MAADIF API Server runner

set -e

# Build first if needed
if [ ! -f "target/maadif-analyzer-1.0.0.jar" ]; then
    echo "[*] Building project first..."
    bash build.sh
fi

# Java options for large APK analysis
JAVA_OPTS="${JAVA_OPTS:--Xmx16g -Xms4g -XX:+UseG1GC -XX:MaxGCPauseMillis=200}"

# Build classpath
GHIDRA_HOME="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
CLASSPATH="target/maadif-analyzer-1.0.0.jar"
CLASSPATH="$CLASSPATH:/opt/jadx/lib/*"
CLASSPATH="$CLASSPATH:$GHIDRA_HOME/Ghidra/Framework/Generic/lib/*"
CLASSPATH="$CLASSPATH:$GHIDRA_HOME/Ghidra/Framework/Utility/lib/*"
CLASSPATH="$CLASSPATH:$GHIDRA_HOME/Ghidra/Framework/Project/lib/*"
CLASSPATH="$CLASSPATH:$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/*"
CLASSPATH="$CLASSPATH:$GHIDRA_HOME/Ghidra/Framework/Docking/lib/*"
CLASSPATH="$CLASSPATH:$GHIDRA_HOME/Ghidra/Framework/FileSystem/lib/*"
CLASSPATH="$CLASSPATH:$GHIDRA_HOME/Ghidra/Framework/Graph/lib/*"
CLASSPATH="$CLASSPATH:$GHIDRA_HOME/Ghidra/Framework/DB/lib/*"
CLASSPATH="$CLASSPATH:$GHIDRA_HOME/Ghidra/Features/Base/lib/*"
CLASSPATH="$CLASSPATH:$GHIDRA_HOME/Ghidra/Features/Decompiler/lib/*"
CLASSPATH="$CLASSPATH:$GHIDRA_HOME/Ghidra/Processors/*/lib/*"
CLASSPATH="$CLASSPATH:/opt/sqlite-jdbc.jar"

# Port
PORT="${1:-8080}"

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                    Starting MAADIF API Server                                ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo
echo "Port: $PORT"
echo "JVM Options: $JAVA_OPTS"
echo

exec java $JAVA_OPTS -cp "$CLASSPATH" io.maadif.server.ApiServer "$PORT"
