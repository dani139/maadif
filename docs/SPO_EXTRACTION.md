# SPO String Extraction Guide

WhatsApp stores localized strings in `.spo` (SuperPack Object) files which are compressed
with Facebook's proprietary SuperPack algorithm. This requires running the APK to trigger
decompression.

## Quick Summary

| Method | Speed | Requirements | Reliability |
|--------|-------|--------------|-------------|
| reDroid | ~30s startup | Docker + binder module | Best |
| Standard Emulator | ~60s startup | Android SDK | Good |
| Physical Device | Instant | Rooted Android phone | Best |

## Method 1: reDroid (Recommended)

reDroid runs Android natively in Docker. It's the fastest headless option.

### Prerequisites

```bash
# 1. Install Docker (if not already)
sudo apt install docker.io
sudo usermod -aG docker $USER

# 2. Install kernel module package
sudo apt install linux-modules-extra-$(uname -r)

# 3. Load required modules
sudo modprobe binder_linux devices="binder,hwbinder,vndbinder"
sudo modprobe ashmem_linux  # May not exist on newer kernels, OK to skip

# 4. Verify KVM
ls -la /dev/kvm
```

### Run Extraction

```bash
# Start reDroid container
mkdir -p /tmp/android-data
docker run -itd --rm --privileged \
    --pull always \
    -v /tmp/android-data:/data \
    -p 5555:5555 \
    redroid/redroid:12.0.0-latest

# Connect ADB
adb connect localhost:5555
adb -s localhost:5555 wait-for-device

# Wait for boot
while [ "$(adb -s localhost:5555 shell getprop sys.boot_completed 2>/dev/null)" != "1" ]; do
    sleep 2
done
echo "Android ready!"

# Install APK (use x86_64 version!)
adb -s localhost:5555 install --abi x86_64 whatsapp.apk

# Start app to trigger decompression
adb -s localhost:5555 shell am start -n com.whatsapp/com.whatsapp.Main
sleep 15

# Extract decompressed strings
adb -s localhost:5555 pull /data/data/com.whatsapp/files/decompressed/strings/ ./strings/

# Cleanup
docker stop $(docker ps -q --filter ancestor=redroid/redroid)
```

### What You Get

After extraction, the `strings/` directory contains:
```
strings/
├── strings_en.txt     # English strings (plain text!)
├── strings_es.txt     # Spanish
├── strings_ar.txt     # Arabic
└── ... (50+ languages)
```

## Method 2: Google Emulator (No special modules needed)

If you can't load binder module, use the standard Android emulator.

### Prerequisites

```bash
# Install Android SDK command-line tools
wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
unzip commandlinetools-linux-*.zip -d ~/android-sdk/cmdline-tools/latest
export ANDROID_HOME=~/android-sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin

# Accept licenses and install emulator
yes | sdkmanager --licenses
sdkmanager "emulator" "platform-tools" "system-images;android-30;google_apis;x86_64"

# Create AVD
avdmanager create avd -n spo_extractor -k "system-images;android-30;google_apis;x86_64" --force
```

### Run Extraction

```bash
# Start emulator headless
emulator -avd spo_extractor -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect &

# Wait for boot
adb wait-for-device
adb shell 'while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done'

# Install and run
adb install whatsapp.apk
adb shell am start -n com.whatsapp/com.whatsapp.Main
sleep 15

# Extract
adb pull /data/data/com.whatsapp/files/decompressed/strings/ ./strings/

# Stop emulator
adb emu kill
```

## Method 3: GitHub Actions (Zero local setup)

Fork [clearbluejar/apk-install-extract](https://github.com/clearbluejar/apk-install-extract)
and run it with your APK:

1. Fork the repo
2. Upload your APK to a release or public URL
3. Go to Actions → Install Extract APK → Run workflow
4. Enter APK URL and run
5. Download extracted artifacts

## Why This is Necessary

The `.spo` format wraps WhatsApp's StringPacks (`.pack`) format with SuperPack compression:

```
.pack (WhatsApp StringPacks) ──[SuperPack]──> .spo

StringPacks library: https://github.com/WhatsApp/StringPacks
```

- StringPacks `.pack` can be read with official library
- SuperPack compression requires `libsuperpack.so` native code
- Only way to decompress is to run the APK on Android

## Troubleshooting

### "binder_linux module not found"

```bash
# Install the modules package
sudo apt install linux-modules-extra-$(uname -r)
sudo modprobe binder_linux devices="binder,hwbinder,vndbinder"
```

### Emulator too slow

- Enable KVM: `ls /dev/kvm` should exist
- Use x86_64 images, not ARM
- Use `-gpu swiftshader_indirect` or `-gpu host` if supported

### ADB connection refused

```bash
adb kill-server
adb start-server
adb connect localhost:5555
```

## Native Libraries are NOT Superpacked

Important: In current WhatsApp APKs, the native `.so` libraries are **NOT** superpacked.
They are standard ELF files that can be analyzed directly:

```
lib/arm64-v8a/libs.so    ← Regular ELF, analyze with Ghidra
lib/arm64-v8a/libsuperpack.so  ← The decompressor itself
```

Only the localized strings use SuperPack compression.
