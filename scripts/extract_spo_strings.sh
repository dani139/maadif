#!/bin/bash
# =============================================================================
# SPO String Extractor - Uses minimal Android x86_64 emulator
# =============================================================================
# Extracts decompressed strings from WhatsApp's .spo files by running
# the APK in a headless emulator and pulling the decompressed files.
#
# Options (fastest to slowest):
#   1. reDroid (Docker) - ~30 sec startup, needs binder module
#   2. Google Emulator headless - ~60 sec startup, most compatible
#   3. Cuttlefish - ~45 sec startup, needs setup
# =============================================================================

set -e

APK_PATH="${1:-}"
OUTPUT_DIR="${2:-./extracted_strings}"
METHOD="${3:-auto}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[-]${NC} $1"; }

usage() {
    echo "Usage: $0 <apk_path> [output_dir] [method]"
    echo ""
    echo "Methods:"
    echo "  auto     - Auto-detect fastest available method"
    echo "  redroid  - Use reDroid Docker container"
    echo "  emulator - Use Google Android emulator (headless)"
    echo ""
    echo "Example:"
    echo "  $0 ./whatsapp.apk ./strings redroid"
    exit 1
}

check_kvm() {
    if [ ! -e /dev/kvm ]; then
        err "KVM not available. Hardware virtualization required."
        return 1
    fi
    return 0
}

check_binder() {
    if ! lsmod | grep -q binder_linux; then
        warn "binder_linux module not loaded. Trying to load..."
        sudo modprobe binder_linux devices="binder,hwbinder,vndbinder" 2>/dev/null || return 1
        sudo modprobe ashmem_linux 2>/dev/null || true
    fi
    return 0
}

# =============================================================================
# Method 1: reDroid (fastest if binder available)
# =============================================================================
extract_with_redroid() {
    log "Starting reDroid container..."

    CONTAINER_NAME="spo_extractor_$$"

    # Start reDroid
    docker run -d --rm --privileged \
        --name "$CONTAINER_NAME" \
        -v /dev/kvm:/dev/kvm \
        -p 5555:5555 \
        redroid/redroid:11.0.0-latest \
        androidboot.redroid_gpu_mode=guest 2>/dev/null

    # Wait for boot
    log "Waiting for Android to boot (30-60 sec)..."
    sleep 10

    for i in {1..30}; do
        if adb connect localhost:5555 2>/dev/null | grep -q "connected"; then
            break
        fi
        sleep 2
    done

    # Wait for boot complete
    adb -s localhost:5555 wait-for-device
    while [ "$(adb -s localhost:5555 shell getprop sys.boot_completed 2>/dev/null)" != "1" ]; do
        sleep 2
    done

    log "Android booted. Installing APK..."
    adb -s localhost:5555 install -g "$APK_PATH"

    # Get package name
    PKG_NAME=$(aapt dump badging "$APK_PATH" 2>/dev/null | grep "package:" | sed "s/.*name='//" | sed "s/'.*//")
    log "Package: $PKG_NAME"

    # Launch app briefly to trigger decompression
    MAIN_ACTIVITY=$(aapt dump badging "$APK_PATH" 2>/dev/null | grep "launchable-activity" | sed "s/.*name='//" | sed "s/'.*//")
    log "Starting app: $MAIN_ACTIVITY"
    adb -s localhost:5555 shell am start -n "$PKG_NAME/$MAIN_ACTIVITY" 2>/dev/null || true

    sleep 10  # Wait for decompression

    # Extract decompressed strings
    log "Extracting decompressed strings..."
    mkdir -p "$OUTPUT_DIR"
    adb -s localhost:5555 pull "/data/data/$PKG_NAME/files/decompressed/" "$OUTPUT_DIR/" 2>/dev/null || \
    adb -s localhost:5555 shell "run-as $PKG_NAME cat files/decompressed/strings/*" > "$OUTPUT_DIR/strings_dump.txt" 2>/dev/null || \
    warn "Could not extract strings directly"

    # Cleanup
    log "Cleaning up..."
    docker stop "$CONTAINER_NAME" 2>/dev/null || true

    log "Done! Output in: $OUTPUT_DIR"
}

# =============================================================================
# Method 2: Google Emulator (headless)
# =============================================================================
extract_with_emulator() {
    log "Using Google Android Emulator (headless)..."

    # Check for emulator
    if ! command -v emulator &>/dev/null; then
        err "Android emulator not found. Install Android SDK."
        err "Or run: sdkmanager 'emulator' 'system-images;android-30;google_apis;x86_64'"
        return 1
    fi

    # Check for AVD
    AVD_NAME="spo_extractor"
    if ! emulator -list-avds | grep -q "$AVD_NAME"; then
        log "Creating AVD..."
        echo "no" | avdmanager create avd -n "$AVD_NAME" -k "system-images;android-30;google_apis;x86_64" --force
    fi

    # Start emulator headless
    log "Starting emulator (headless)..."
    emulator -avd "$AVD_NAME" -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect &
    EMU_PID=$!

    # Wait for boot
    log "Waiting for emulator boot..."
    adb wait-for-device
    while [ "$(adb shell getprop sys.boot_completed 2>/dev/null)" != "1" ]; do
        sleep 2
    done

    log "Emulator ready. Installing APK..."
    adb install -g "$APK_PATH"

    PKG_NAME=$(aapt dump badging "$APK_PATH" 2>/dev/null | grep "package:" | sed "s/.*name='//" | sed "s/'.*//")
    MAIN_ACTIVITY=$(aapt dump badging "$APK_PATH" 2>/dev/null | grep "launchable-activity" | sed "s/.*name='//" | sed "s/'.*//")

    log "Starting app..."
    adb shell am start -n "$PKG_NAME/$MAIN_ACTIVITY"
    sleep 10

    log "Extracting strings..."
    mkdir -p "$OUTPUT_DIR"
    adb pull "/data/data/$PKG_NAME/files/decompressed/" "$OUTPUT_DIR/" 2>/dev/null || warn "Direct pull failed"

    # Cleanup
    kill $EMU_PID 2>/dev/null

    log "Done!"
}

# =============================================================================
# Auto-detect best method
# =============================================================================
auto_detect() {
    check_kvm || { err "No KVM"; exit 1; }

    if check_binder 2>/dev/null && command -v docker &>/dev/null; then
        log "Using reDroid (fastest)"
        extract_with_redroid
    elif command -v emulator &>/dev/null; then
        log "Using Google Emulator"
        extract_with_emulator
    else
        err "No suitable method found."
        err "Install either:"
        err "  - Docker + load binder module for reDroid"
        err "  - Android SDK emulator"
        exit 1
    fi
}

# =============================================================================
# Main
# =============================================================================
[ -z "$APK_PATH" ] && usage
[ ! -f "$APK_PATH" ] && { err "APK not found: $APK_PATH"; exit 1; }

case "$METHOD" in
    auto)     auto_detect ;;
    redroid)  check_binder && extract_with_redroid ;;
    emulator) extract_with_emulator ;;
    *)        usage ;;
esac
