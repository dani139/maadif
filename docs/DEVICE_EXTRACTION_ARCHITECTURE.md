# Device-Based SPO Extraction Architecture

## Overview

WhatsApp APKs contain SuperPack-compressed files that cannot be decompressed statically.
This document describes a systematic approach to extract these files using a rooted ARM64 device.

## WhatsApp Data Layout on Device

After installing and launching WhatsApp, the following directories are created:

```
/data/data/com.whatsapp/
├── files/
│   ├── decompressed/                    # <-- SuperPack decompressed files
│   │   ├── libs.spo/                    # Decompressed native libraries
│   │   │   ├── libwhatsapp.so          # Main native code (13 MB)
│   │   │   ├── libwhatsappmerged.so    # Merged library (6 MB)
│   │   │   ├── libpytorch.so           # ML library
│   │   │   ├── libexecutorch.so        # Execution engine
│   │   │   ├── libar-bundle*.so        # AR features
│   │   │   └── ... (73 total .so files)
│   │   │
│   │   └── strings_{locale}.spo/        # Decompressed strings (per locale)
│   │       ├── strings_{locale}.pack   # StringPacks format (parseable)
│   │       └── .superpack_version      # Version marker
│   │
│   ├── cldr_strings_*.pack              # CLDR locale data (not superpacked)
│   └── downloadable/                    # Wallpapers, stickers
│
├── shared_prefs/                        # App preferences
├── databases/                           # SQLite databases (messages, etc.)
├── cache/                               # Temporary files
└── app_webview/                         # WebView data
```

## What Gets Decompressed

| Content | APK Location | Device Location | Trigger |
|---------|-------------|-----------------|---------|
| Native libs | `lib/{arch}/libs.so` (packed) | `files/decompressed/libs.spo/*.so` | App launch |
| Strings | `assets/compressed/strings/strings_{locale}.spo` | `files/decompressed/strings_{locale}.spo/` | Locale usage |
| CLDR | `assets/cldr_strings.pack` | `files/cldr_strings_*.pack` | App launch |

## Extraction Pipeline

### Phase 1: Device Preparation

```
┌─────────────────────────────────────────────────────────────────┐
│                     Device Requirements                          │
├─────────────────────────────────────────────────────────────────┤
│ • Rooted ARM64 device (Magisk recommended)                      │
│ • ADB connection (USB or WiFi)                                  │
│ • Sufficient storage (~500 MB for full extraction)              │
│ • Target WhatsApp APK (matching version to analyze)             │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 2: APK Installation & Launch

```bash
# Install specific version
adb install /path/to/whatsapp-{version}.apk

# Launch to trigger libs decompression
adb shell am start -n com.whatsapp/com.whatsapp.Main

# Wait for decompression (5-10 seconds)
sleep 10
```

### Phase 3: Library Extraction

```bash
# Copy to accessible location (needs root)
adb shell "su -c 'cp -r /data/data/com.whatsapp/files/decompressed/libs.spo /data/local/tmp/'"
adb shell "su -c 'chmod -R 755 /data/local/tmp/libs.spo'"

# Pull to local machine
adb pull /data/local/tmp/libs.spo/ ./extracted/arm64/libs/
```

### Phase 4: String Extraction (All Locales)

```
┌─────────────────────────────────────────────────────────────────┐
│                    Locale Extraction Flow                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  For each locale in [en, ar, es, ru, zh, de, fr, ...]:          │
│    1. Change WhatsApp app language                              │
│    2. Force stop and restart app                                │
│    3. Wait for string decompression                             │
│    4. Pull decompressed strings_{locale}.spo/                   │
│    5. Parse .pack file with StringPacks library                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Integration with MAADIF System

### New Database Tables

```sql
-- Add to Database.java

-- Extracted native libraries (from device)
CREATE TABLE device_extracted_libs (
    id INTEGER PRIMARY KEY,
    version TEXT NOT NULL,
    lib_name TEXT NOT NULL,
    arch TEXT DEFAULT 'arm64-v8a',
    size INTEGER,
    sha256 TEXT,
    extracted_at TEXT,
    local_path TEXT,
    analyzed INTEGER DEFAULT 0
);

-- Extracted strings
CREATE TABLE extracted_strings (
    id INTEGER PRIMARY KEY,
    version TEXT NOT NULL,
    locale TEXT NOT NULL,
    string_id INTEGER,
    string_key TEXT,
    string_value TEXT,
    is_plural INTEGER DEFAULT 0,
    extracted_at TEXT
);

-- Extraction jobs
CREATE TABLE device_extraction_jobs (
    id INTEGER PRIMARY KEY,
    version TEXT NOT NULL,
    device_serial TEXT,
    status TEXT DEFAULT 'pending',
    libs_extracted INTEGER DEFAULT 0,
    strings_extracted INTEGER DEFAULT 0,
    started_at TEXT,
    completed_at TEXT
);
```

### New API Endpoints

```
POST /extract/device
  Body: { "version": "2.26.16.73", "device": "59221XEBF5OB69" }
  Returns: { "jobId": "...", "status": "started" }

GET /extract/status/{jobId}
  Returns: { "status": "running", "libs": 73, "locales": 5 }

GET /extract/libs/{version}
  Returns: List of extracted libraries with metadata

GET /extract/strings/{version}/{locale}
  Returns: All strings for given locale
```

### Directory Structure

```
maadif/
├── extracted/
│   └── {package}/
│       └── {version}/
│           ├── arm64/
│           │   ├── libs/              # Decompressed .so files
│           │   │   ├── libwhatsapp.so
│           │   │   └── ...
│           │   └── strings/           # Parsed string files
│           │       ├── strings_en.json
│           │       ├── strings_ar.json
│           │       └── ...
│           └── extraction.db          # Extraction metadata
```

## Extraction Script: `scripts/device_extract.py`

```python
#!/usr/bin/env python3
"""
Device-based SuperPack extraction for WhatsApp.

Usage:
    python device_extract.py --version 2.26.16.73 --device 59221XEBF5OB69
    python device_extract.py --version 2.26.16.73 --device 59221XEBF5OB69 --locales en,ar,es
"""

import subprocess
import json
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime

# Locales to extract (WhatsApp supports 60+)
ALL_LOCALES = [
    'en', 'ar', 'es', 'pt', 'ru', 'zh', 'de', 'fr', 'it', 'ja', 'ko',
    'hi', 'tr', 'pl', 'nl', 'id', 'vi', 'th', 'ms', 'uk', 'cs', 'ro',
    'hu', 'el', 'sv', 'da', 'fi', 'nb', 'he', 'sk', 'bg', 'hr', 'sr',
    'sl', 'lt', 'lv', 'et', 'fa', 'sw', 'af', 'zu', 'am', 'bn', 'gu',
    'kn', 'ml', 'mr', 'pa', 'ta', 'te', 'ur', 'az', 'kk', 'uz', 'km',
    'lo', 'my', 'si', 'fil', 'ca', 'eu', 'gl'
]

class DeviceExtractor:
    def __init__(self, device_serial: str, version: str, output_dir: Path):
        self.device = device_serial
        self.version = version
        self.output_dir = output_dir
        self.adb = f"adb -s {device_serial}"

    def shell(self, cmd: str, root: bool = False) -> str:
        """Execute shell command on device."""
        if root:
            cmd = f"su -c '{cmd}'"
        result = subprocess.run(
            f"{self.adb} shell \"{cmd}\"",
            shell=True, capture_output=True, text=True
        )
        return result.stdout.strip()

    def pull(self, remote: str, local: Path) -> bool:
        """Pull file/directory from device."""
        local.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            f"{self.adb} pull {remote} {local}",
            shell=True, capture_output=True
        )
        return result.returncode == 0

    def is_whatsapp_installed(self) -> bool:
        """Check if WhatsApp is installed."""
        result = self.shell("pm list packages | grep com.whatsapp")
        return "com.whatsapp" in result

    def get_whatsapp_version(self) -> str:
        """Get installed WhatsApp version."""
        result = self.shell("dumpsys package com.whatsapp | grep versionName")
        if "versionName=" in result:
            return result.split("versionName=")[1].split()[0]
        return ""

    def extract_libs(self) -> list:
        """Extract decompressed native libraries."""
        libs_dir = self.output_dir / "arm64" / "libs"
        libs_dir.mkdir(parents=True, exist_ok=True)

        # Copy to temp location with root
        self.shell("cp -r /data/data/com.whatsapp/files/decompressed/libs.spo /data/local/tmp/", root=True)
        self.shell("chmod -R 755 /data/local/tmp/libs.spo", root=True)

        # Pull to local
        self.pull("/data/local/tmp/libs.spo/", libs_dir)

        # Cleanup
        self.shell("rm -rf /data/local/tmp/libs.spo", root=True)

        # Get list of extracted libs
        extracted = []
        for so_file in libs_dir.glob("**/*.so"):
            extracted.append({
                "name": so_file.name,
                "size": so_file.stat().st_size,
                "sha256": hashlib.sha256(so_file.read_bytes()).hexdigest(),
                "path": str(so_file)
            })

        return extracted

    def extract_strings(self, locales: list = None) -> dict:
        """Extract strings for specified locales."""
        if locales is None:
            locales = ['en']  # Default to English only

        strings_dir = self.output_dir / "arm64" / "strings"
        strings_dir.mkdir(parents=True, exist_ok=True)

        results = {}

        for locale in locales:
            print(f"Extracting strings for locale: {locale}")

            # Change WhatsApp language (via shared prefs manipulation)
            # This requires app restart to take effect
            self.shell("am force-stop com.whatsapp")

            # Set locale preference
            prefs_file = "/data/data/com.whatsapp/shared_prefs/com.whatsapp_preferences.xml"
            # Note: Actual implementation would modify the XML

            # Restart app
            self.shell("am start -n com.whatsapp/com.whatsapp.Main")

            # Wait for decompression
            import time
            time.sleep(5)

            # Check if strings were decompressed
            check = self.shell(f"ls /data/data/com.whatsapp/files/decompressed/strings_{locale}.spo/", root=True)

            if "No such file" not in check:
                # Copy and pull
                self.shell(f"cp -r /data/data/com.whatsapp/files/decompressed/strings_{locale}.spo /data/local/tmp/", root=True)
                self.shell(f"chmod -R 755 /data/local/tmp/strings_{locale}.spo", root=True)

                locale_dir = strings_dir / f"strings_{locale}.spo"
                self.pull(f"/data/local/tmp/strings_{locale}.spo/", locale_dir)

                # Parse .pack file
                pack_file = locale_dir / f"strings_{locale}.pack"
                if pack_file.exists():
                    results[locale] = self.parse_pack_file(pack_file)

                # Cleanup
                self.shell(f"rm -rf /data/local/tmp/strings_{locale}.spo", root=True)

        return results

    def parse_pack_file(self, pack_file: Path) -> dict:
        """Parse StringPacks .pack file format."""
        # Use StringPacks library
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "external" / "StringPacks" / "library" / "scripts"))
        from string_pack import StringPack

        return StringPack.from_file(str(pack_file))

    def run(self, extract_libs: bool = True, locales: list = None) -> dict:
        """Run full extraction."""
        result = {
            "version": self.version,
            "device": self.device,
            "started_at": datetime.now().isoformat(),
            "libs": [],
            "strings": {}
        }

        # Check WhatsApp installation
        if not self.is_whatsapp_installed():
            raise RuntimeError("WhatsApp not installed on device")

        installed_version = self.get_whatsapp_version()
        if installed_version != self.version:
            print(f"Warning: Installed version {installed_version} != requested {self.version}")

        # Extract libs
        if extract_libs:
            print("Extracting native libraries...")
            result["libs"] = self.extract_libs()
            print(f"Extracted {len(result['libs'])} libraries")

        # Extract strings
        if locales:
            print(f"Extracting strings for {len(locales)} locales...")
            result["strings"] = self.extract_strings(locales)
            print(f"Extracted strings for {len(result['strings'])} locales")

        result["completed_at"] = datetime.now().isoformat()

        # Save results
        with open(self.output_dir / "extraction_result.json", "w") as f:
            json.dump(result, f, indent=2)

        return result
```

## Workflow Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        Device Extraction Workflow                         │
└──────────────────────────────────────────────────────────────────────────┘

     ┌─────────┐     ┌─────────┐     ┌─────────────┐     ┌──────────────┐
     │  APK    │────▶│ Install │────▶│   Launch    │────▶│ Decompression│
     │ Storage │     │ on Device│    │  WhatsApp   │     │  Triggered   │
     └─────────┘     └─────────┘     └─────────────┘     └──────────────┘
                                                                  │
                                                                  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                           Device Storage                                  │
│                                                                           │
│  /data/data/com.whatsapp/files/decompressed/                             │
│  ├── libs.spo/          ◀──────────────────┐                             │
│  │   └── *.so (73 files)                   │                             │
│  └── strings_*.spo/     ◀────────┐         │                             │
│      └── *.pack                  │         │                             │
└──────────────────────────────────┼─────────┼─────────────────────────────┘
                                   │         │
                    ┌──────────────┘         └──────────────┐
                    │                                        │
                    ▼                                        ▼
          ┌─────────────────┐                      ┌─────────────────┐
          │  String Parser  │                      │   ADB Pull      │
          │  (StringPacks)  │                      │   (root)        │
          └─────────────────┘                      └─────────────────┘
                    │                                        │
                    ▼                                        ▼
          ┌─────────────────┐                      ┌─────────────────┐
          │  JSON Output    │                      │  .so Files      │
          │  per Locale     │                      │  (ARM64)        │
          └─────────────────┘                      └─────────────────┘
                    │                                        │
                    └────────────────┬───────────────────────┘
                                     │
                                     ▼
                           ┌─────────────────┐
                           │   MAADIF DB     │
                           │   Integration   │
                           └─────────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
                    ▼                ▼                ▼
          ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
          │   Ghidra    │   │   String    │   │   Binary    │
          │  Analysis   │   │   Search    │   │   Diffing   │
          └─────────────┘   └─────────────┘   └─────────────┘
```

## Integration Steps

### 1. Create extraction script
```bash
# scripts/device_extract.py (see above)
```

### 2. Add database tables
```java
// In Database.java - add device extraction tables
```

### 3. Add API endpoints
```java
// In ApiServer.java - add /extract/* endpoints
```

### 4. Update analysis pipeline
```java
// In ApkAnalyzer.java - use extracted ARM64 libs instead of x86
```

### 5. Run extraction
```bash
# One-time extraction
python scripts/device_extract.py \
    --version 2.26.16.73 \
    --device 59221XEBF5OB69 \
    --locales en,ar,es,ru,zh

# Or via API
curl -X POST http://localhost:8080/extract/device \
    -H "Content-Type: application/json" \
    -d '{"version": "2.26.16.73", "device": "59221XEBF5OB69", "locales": ["en"]}'
```

## Benefits

1. **Real ARM64 binaries** - Same architecture as production devices
2. **All native libraries** - 73 .so files vs 3 packed files in APK
3. **Localized strings** - Parseable StringPacks format
4. **Version-matched** - Exact version correlation
5. **Automated pipeline** - Integrate with existing MAADIF workflow

## Limitations

1. Requires rooted device
2. One locale at a time (app restart needed)
3. Device must be connected during extraction
4. Storage requirements (~500 MB per version)
