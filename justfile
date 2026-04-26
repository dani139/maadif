# MAADIF - Mobile & Application Analysis Docker Image Framework
# Justfile for common operations

# Default recipe - show help
default:
    @just --list

# Docker image name
image := "maadif"

# Build the Docker image
build-docker:
    docker build -t {{image}} .

# Build the Docker image with no cache
build-docker-fresh:
    docker build --no-cache -t {{image}} .

# Start interactive shell in container with workspace mounted
shell:
    docker run -it --rm \
        -v "$(pwd):/workspace" \
        -w /workspace \
        {{image}} \
        /bin/bash

# Build the Java analyzer using local JARs
build:
    docker run --rm \
        -v "$(pwd):/workspace" \
        -w /workspace \
        {{image}} \
        bash build.sh

# Analyze an APK file (full analysis with JADX + Ghidra)
analyze apk output="/workspace/output":
    docker run --rm \
        -v "$(pwd):/workspace" \
        -w /workspace \
        {{image}} \
        bash run.sh "{{apk}}" "{{output}}"

# Run JADX decompilation only
jadx apk output="/workspace/output/jadx":
    docker run --rm \
        -v "$(pwd):/workspace" \
        -w /workspace \
        {{image}} \
        jadx -d "{{output}}" "{{apk}}"

# Run JADX GUI (requires X11 forwarding)
jadx-gui apk:
    docker run --rm \
        -v "$(pwd):/workspace" \
        -v /tmp/.X11-unix:/tmp/.X11-unix \
        -e DISPLAY=$DISPLAY \
        -w /workspace \
        {{image}} \
        jadx-gui "{{apk}}"

# Run Ghidra headless analysis on a file
ghidra file output="/workspace/output/ghidra":
    docker run --rm \
        -v "$(pwd):/workspace" \
        -w /workspace \
        {{image}} \
        bash -c "mkdir -p '{{output}}' && analyzeHeadless '{{output}}' analysis -import '{{file}}' -postScript /dev/null"

# Run apktool decode
apktool-decode apk output="/workspace/output/apktool":
    docker run --rm \
        -v "$(pwd):/workspace" \
        -w /workspace \
        {{image}} \
        apktool d -f -o "{{output}}" "{{apk}}"

# Run dex2jar conversion
dex2jar apk:
    docker run --rm \
        -v "$(pwd):/workspace" \
        -w /workspace \
        {{image}} \
        d2j-dex2jar "{{apk}}"

# Run baksmali to disassemble DEX
baksmali dex output="/workspace/output/smali":
    docker run --rm \
        -v "$(pwd):/workspace" \
        -w /workspace \
        {{image}} \
        baksmali d -o "{{output}}" "{{dex}}"

# Quick test - build and analyze sample APK if present
test:
    #!/usr/bin/env bash
    just build
    if [ -d "apks" ]; then
        APK=$(find apks -name "*.apk" -type f | head -1)
        if [ -n "$APK" ]; then
            echo "Testing with: $APK"
            just analyze "$APK"
        else
            echo "No APK files found in apks/ directory"
        fi
    else
        echo "apks/ directory not found"
    fi

# Clean build artifacts
clean:
    rm -rf target/
    rm -rf output/

# Clean Docker images
clean-docker:
    docker rmi {{image}} || true

# View analysis output
view-report output="/workspace/output":
    @cat "{{output}}/full_analysis_report.txt" 2>/dev/null || echo "No report found"

# List available APKs
list-apks:
    @find apks -name "*.apk" -type f 2>/dev/null || echo "No APKs found"

# Run frida-tools inside container
frida *args:
    docker run -it --rm \
        --privileged \
        -v "$(pwd):/workspace" \
        -w /workspace \
        {{image}} \
        frida {{args}}

# Run radare2 on a file
r2 file:
    docker run -it --rm \
        -v "$(pwd):/workspace" \
        -w /workspace \
        {{image}} \
        r2 "{{file}}"

# Check if all tools are available
check-tools:
    docker run --rm {{image}} bash -c '\
        echo "=== Tool Check ===" && \
        echo -n "Java: " && java --version | head -1 && \
        echo -n "Ghidra: " && ls /opt/ghidra/ghidraRun && \
        echo -n "JADX: " && jadx --version && \
        echo -n "apktool: " && apktool --version && \
        echo -n "radare2: " && r2 -v | head -1 && \
        echo -n "baksmali: " && baksmali --version && \
        echo "=== All tools OK ===" \
    '

# Show Docker image info
info:
    @echo "Image: {{image}}"
    @docker images {{image}} --format "Size: {{{{.Size}}}}\nCreated: {{{{.CreatedAt}}}}"
