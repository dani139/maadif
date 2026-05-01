# Device SOS Batch Export Status

**Date:** 2026-05-02
**Status:** IN PROGRESS (container `maadif-batch` running)

## Summary

Exporting all 73 WhatsApp native libraries (.so files) from `device_sos/` to SQLite databases with full Ghidra decompilation.

## Output Directory

```
/home/danil/Projects/maadif/output/device_sos_sqlite/
```

## Progress

- **Completed:** 5 / 73 databases
- **Remaining:** 68 files

### Completed Files

| Library | Size |
|---------|------|
| libandroidx.graphics.path.db | 92K |
| libaom.db | 14M |
| libar-bundle2.db | 20M |
| libar-bundle3.db | 17M |
| libar-bundle4.db | 11M |

### Remaining Files

```
libar-bundle5
libarcore_sdk_c
libc++_shared
libcurve25519
libdav1d
libessential
libexecutorch
libfb
libfbjni
libfbjni_kt
libfbsocketthreadlocalscope
libfbsofterror
libfb_sqlite_3500300
libfbunwindstack
libffsingletonmerged
libflexlayout
libfortify
libggml_core_ops_enhanced
libggml_core_ops_universal
libgifimage
libglog
libgraphicsengine-arengineservices-whatsappservicehost-native
libgraphstorecerealutil
libgraphutil
libhiddenapis2
libminscompiler-jni
libmobileconfig-jni
libnative-filters
libnativeutil-jni
libnative_utils
libohai
libpando-client-runtimedefaults-jni
libprofilo
libprofilo_atrace
libprofilo_counters
libprofilo_logger
libprofilo_mmapbuf
libprofilo_mmapbuf_buffer
libprofilo_mmapbuf_buffer_jni
libprofilo_multi_buffer_logger
libprofilo_stacktrace
libprofilo_systemcounters
libprofilo_threadmetadata
libpsi
libpyspeech
libpytorch
librtvip
libsimplejni
libsmartglasses-bundle
libsodium
libsqlitejni
libsqlitevec
libstatic-webp
libtorch-code-gen
libtransparency
libunityjni
libvlc
libwa_log
libwasafe
libwasafedeps
libwebpencoder-native
libwhatsapp
libwhatsappmerged
libwzav1
libwzav1_v2
libxplat_psi
libxplat_third-party_zstd__zstd
libyoga
```

## To Continue Export

### Option 1: Check if container still running
```bash
docker ps | grep maadif-batch
docker logs -f maadif-batch  # Follow logs
```

### Option 2: Restart batch export (skips already done)
```bash
docker run -d --name maadif-batch -v "/home/danil/Projects/maadif:/workspace" -w /workspace maadif bash -c '
OUTPUT_DIR=/workspace/output/device_sos_sqlite
mkdir -p $OUTPUT_DIR /tmp/ghidra_projects

cd /workspace/device_sos
for SO_FILE in *.so; do
    LIB_NAME="${SO_FILE%.so}"
    DB_FILE="$OUTPUT_DIR/${LIB_NAME}.db"

    # Skip if already done
    if [ -f "$DB_FILE" ] && [ $(stat -c%s "$DB_FILE") -gt 10000 ]; then
        echo "[Skip] $LIB_NAME"
        continue
    fi

    echo "[Analyzing] $SO_FILE"
    /opt/ghidra/support/analyzeHeadless /tmp/ghidra_projects ${LIB_NAME}_proj \
        -import /workspace/device_sos/$SO_FILE \
        -postScript ExportToJson.java $OUTPUT_DIR \
        -scriptPath /workspace/scripts/ghidra \
        -deleteProject 2>&1 | grep -E "\[Export\]|ERROR"

    if [ -f "$OUTPUT_DIR/${LIB_NAME}.json" ]; then
        python3 /workspace/scripts/json_to_sqlite.py "$OUTPUT_DIR/${LIB_NAME}.json" "$DB_FILE"
        rm -f "$OUTPUT_DIR/${LIB_NAME}.json"
    fi
done
echo "Complete!"
'
```

### Option 3: Export single file
```bash
docker run --rm -v "/home/danil/Projects/maadif:/workspace" maadif bash -c '
/opt/ghidra/support/analyzeHeadless /tmp/proj libwhatsapp_proj \
    -import /workspace/device_sos/libwhatsapp.so \
    -postScript ExportToJson.java /workspace/output/device_sos_sqlite \
    -scriptPath /workspace/scripts/ghidra \
    -deleteProject

python3 /workspace/scripts/json_to_sqlite.py \
    /workspace/output/device_sos_sqlite/libwhatsapp.json \
    /workspace/output/device_sos_sqlite/libwhatsapp.db
'
```

## Pipeline Components

1. **ExportToJson.java** (`scripts/ghidra/`) - Ghidra script that decompiles all functions and exports to JSON
2. **json_to_sqlite.py** (`scripts/`) - Converts JSON to SQLite with full schema
3. **ApiServer.java** - `/ghidra/export` and `/ghidra/batch` endpoints

## Database Schema

Each SQLite database contains:

- `library_info` - Library metadata (architecture, compiler, etc.)
- `functions` - All functions with decompiled C code, signatures, hashes
- `strings` - Extracted strings with addresses
- `imports` - Imported symbols and libraries
- `exports` - Exported symbols
- `memory_sections` - Memory layout

## Notes

- `ExportToSqlite.java` renamed to `.bak` due to OSGi classloader conflicts
- Large files (libwhatsapp.so ~100MB) may take 30+ minutes each
- JSON files are deleted after conversion to save space
