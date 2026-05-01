#!/bin/bash
# Export all device_sos libraries to SQLite using the maadif API server
#
# Usage: ./export_device_sos.sh [output_dir]
#
# This script:
# 1. Starts the maadif server in Docker
# 2. Calls /ghidra/batch to analyze all .so files
# 3. Monitors the job until completion

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

DEVICE_SOS_DIR="$PROJECT_ROOT/device_sos"
OUTPUT_DIR="${1:-$PROJECT_ROOT/output/device_analysis/sqlite_export}"
SERVER_PORT=8080

echo "================================================================================"
echo "  Device SOS -> SQLite Full Export"
echo "================================================================================"
echo ""
echo "Source:  $DEVICE_SOS_DIR"
echo "Output:  $OUTPUT_DIR"
echo ""

# Count .so files
SO_COUNT=$(ls -1 "$DEVICE_SOS_DIR"/*.so 2>/dev/null | wc -l)
echo "Found $SO_COUNT .so files to export"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if server is already running
if curl -s "http://localhost:$SERVER_PORT/health" > /dev/null 2>&1; then
    echo "Server already running on port $SERVER_PORT"
else
    echo "Starting maadif server..."
    docker run -d --rm \
        --name maadif-export \
        -p $SERVER_PORT:8080 \
        -v "$PROJECT_ROOT:/workspace" \
        maadif \
        java -cp "/workspace/target/classes:/opt/ghidra/Ghidra/Framework/Generic/lib/*:/opt/ghidra/Ghidra/Framework/SoftwareModeling/lib/*:/opt/ghidra/Ghidra/Features/Base/lib/*:/opt/ghidra/Ghidra/Features/Decompiler/lib/*:/opt/ghidra/Ghidra/Framework/Project/lib/*:/opt/ghidra/Ghidra/Framework/Utility/lib/*:/opt/ghidra/Ghidra/Framework/Docking/lib/*:/opt/ghidra/Ghidra/Framework/Gui/lib/*:/opt/ghidra/Ghidra/Framework/FileSystem/lib/*:/opt/ghidra/Ghidra/Framework/DB/lib/*:/opt/ghidra/Ghidra/Framework/Graph/lib/*:/opt/ghidra/Ghidra/Processors/AARCH64/lib/*:/opt/ghidra/Ghidra/Processors/ARM/lib/*:/opt/sqlite-jdbc.jar" \
        io.maadif.server.ApiServer

    echo "Waiting for server to start..."
    for i in {1..30}; do
        if curl -s "http://localhost:$SERVER_PORT/health" > /dev/null 2>&1; then
            echo "Server is ready!"
            break
        fi
        sleep 1
    done

    if ! curl -s "http://localhost:$SERVER_PORT/health" > /dev/null 2>&1; then
        echo "Error: Server failed to start"
        docker logs maadif-export 2>&1 | tail -20
        exit 1
    fi
fi

echo ""
echo "Starting batch export..."

# Call batch endpoint
RESPONSE=$(curl -s -X POST "http://localhost:$SERVER_PORT/ghidra/batch" \
    -H "Content-Type: application/json" \
    -d "{\"directory\": \"/workspace/device_sos\", \"output\": \"/workspace/output/device_analysis/sqlite_export\"}")

JOB_ID=$(echo "$RESPONSE" | jq -r '.id')

if [ "$JOB_ID" == "null" ] || [ -z "$JOB_ID" ]; then
    echo "Error: Failed to start batch job"
    echo "$RESPONSE"
    exit 1
fi

echo "Job ID: $JOB_ID"
echo ""

# Monitor job
while true; do
    STATUS=$(curl -s "http://localhost:$SERVER_PORT/status/$JOB_ID")
    JOB_STATUS=$(echo "$STATUS" | jq -r '.status')
    PROGRESS=$(echo "$STATUS" | jq -r '.progress')
    MESSAGE=$(echo "$STATUS" | jq -r '.message')

    echo -ne "\r[$PROGRESS%] $MESSAGE                    "

    if [ "$JOB_STATUS" == "completed" ] || [ "$JOB_STATUS" == "failed" ]; then
        echo ""
        echo ""
        echo "Final status: $JOB_STATUS"
        echo "Message: $MESSAGE"
        break
    fi

    sleep 5
done

echo ""
echo "================================================================================"
echo "  Summary"
echo "================================================================================"
echo ""

# Show output databases
if ls "$OUTPUT_DIR"/*.db 1>/dev/null 2>&1; then
    echo "SQLite databases:"
    TOTAL_SIZE=0
    for db in "$OUTPUT_DIR"/*.db; do
        size=$(stat -c%s "$db" 2>/dev/null || stat -f%z "$db" 2>/dev/null || echo "0")
        TOTAL_SIZE=$((TOTAL_SIZE + size))
        printf "  %-50s %s\n" "$(basename $db)" "$(numfmt --to=iec $size 2>/dev/null || echo $size)"
    done
    echo ""
    echo "Total size: $(numfmt --to=iec $TOTAL_SIZE 2>/dev/null || echo $TOTAL_SIZE)"
fi

echo ""
echo "Output directory: $OUTPUT_DIR"
