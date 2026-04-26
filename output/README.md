# WhatsApp APK Decompilation Output

## Structure

```
output/
├── jadx/                          # JADX decompiled Java source
│   ├── whatsapp-2.26.14.75/
│   │   ├── sources/              # Decompiled Java source files
│   │   └── resources/            # Extracted resources (layouts, drawables, etc.)
│   ├── whatsapp-2.26.15.70/
│   │   ├── sources/
│   │   └── resources/
│   └── whatsapp-2.26.16.73/
│       ├── sources/
│       └── resources/
└── ghidra/                        # Ghidra decompiled native code
    └── whatsapp-2.26.16.73/
        ├── arm64-v8a/            # ARM64 native libraries
        │   ├── libs_decompiled.c
        │   ├── libsuperpack_decompiled.c
        │   └── libunwindstack_binary_decompiled.c
        └── x86_64/               # x86_64 native libraries
            ├── libs_decompiled.c
            ├── libsuperpack_decompiled.c
            └── libunwindstack_binary_decompiled.c
```

## Tools Used
- **JADX 1.5.1**: Java decompilation (DEX to Java source)
- **Ghidra 11.3.1**: Native library decompilation (ELF .so to C pseudocode)

## Key Packages (JADX)
- `com/whatsapp/` - Main WhatsApp code
- `com/facebook/` - Facebook SDK integration
- `com/google/` - Google services
- `androidx/` - AndroidX libraries
- Native code in `lib/` directories

## Notes
- JADX had ~216-219 decompilation errors per APK (normal for obfuscated apps)
- Ghidra exported up to 500 functions per native library
- Some code may be obfuscated or use anti-reverse engineering techniques
