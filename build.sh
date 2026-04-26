#!/bin/bash
# MAADIF Build Script - Compiles against local JADX and Ghidra installations

set -e

SRC_DIR="src/main/java"
OUT_DIR="target/classes"
JAR_DIR="target"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    MAADIF Build Script                                       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
echo

# Build classpath from JADX
JADX_CP="/opt/jadx/lib/jadx-1.5.1-all.jar"

# Build classpath from Ghidra
GHIDRA_HOME=${GHIDRA_HOME:-/opt/ghidra}
GHIDRA_CP=""
for jar in $(find $GHIDRA_HOME/Ghidra -name "*.jar" -path "*/lib/*" 2>/dev/null); do
    if [ -n "$GHIDRA_CP" ]; then
        GHIDRA_CP="$GHIDRA_CP:$jar"
    else
        GHIDRA_CP="$jar"
    fi
done

# Combined classpath
CLASSPATH="$JADX_CP:$GHIDRA_CP"

echo -e "${YELLOW}[Build]${NC} Creating output directories..."
mkdir -p "$OUT_DIR"
mkdir -p "$JAR_DIR"

echo -e "${YELLOW}[Build]${NC} Compiling Java sources..."

# Find Java files - io.maadif.analyzer and io.maadif.server
JAVA_FILES=$(find "$SRC_DIR" -path "*/io/maadif/*.java" -o -path "*/io/maadif/**/*.java" | sort -u)

if [ -z "$JAVA_FILES" ]; then
    echo -e "${RED}[Error]${NC} No Java files found in $SRC_DIR/io/maadif"
    exit 1
fi

echo "  Found Java files:"
for f in $JAVA_FILES; do
    echo "    - $f"
done

# Compile
javac -d "$OUT_DIR" -cp "$CLASSPATH" -Xlint:unchecked $JAVA_FILES

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[Build]${NC} Compilation successful!"
else
    echo -e "${RED}[Build]${NC} Compilation failed!"
    exit 1
fi

# Create manifest
echo -e "${YELLOW}[Build]${NC} Creating JAR manifest..."
cat > "$JAR_DIR/MANIFEST.MF" << EOF
Manifest-Version: 1.0
Main-Class: io.maadif.analyzer.ApkAnalyzer
Class-Path: /opt/jadx/lib/jadx-1.5.1-all.jar
EOF

# Create JAR
echo -e "${YELLOW}[Build]${NC} Creating JAR file..."
cd "$OUT_DIR"
jar cfm "../maadif-analyzer-1.0.0.jar" "../MANIFEST.MF" io/
cd - > /dev/null

echo
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                         Build Complete!                                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "JAR file: ${GREEN}target/maadif-analyzer-1.0.0.jar${NC}"
echo
echo "Run with:"
echo "  java -cp 'target/maadif-analyzer-1.0.0.jar:/opt/jadx/lib/*:/opt/ghidra/Ghidra/Framework/*/lib/*:/opt/ghidra/Ghidra/Features/*/lib/*' io.maadif.analyzer.ApkAnalyzer <apk>"
