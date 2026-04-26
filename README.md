- how to download them new ones
- start analysis, with configs all natives, or only 1 for testing.


# MAADIF - Mobile & Application Analysis Docker Image Framework

A comprehensive APK analysis framework that combines Ghidra and JADX APIs for deep binary and source code analysis.

## Features

- **JADX Decompilation**: Full Java source code decompilation from APK/DEX files
- **Ghidra Analysis**: Binary analysis of DEX files and native libraries (.so)
- **Security Analysis**: Automated detection of security issues, permissions, and potential secrets
- **Resource Extraction**: Parse and analyze AndroidManifest.xml and other resources
- **Report Generation**: Comprehensive text and JSON reports

## Quick Start

```bash
# Build the Docker image
just build-docker

# Run analysis on an APK
just analyze apks/com.whatsapp/WhatsApp.apk

# Interactive shell in container
just shell
```

## Directory Structure

```
maadif/
├── apks/                    # Place APK files here
├── output/                  # Analysis output
├── src/
│   └── main/java/io/maadif/analyzer/
│       ├── ApkAnalyzer.java      # Main entry point
│       ├── JadxAnalyzer.java     # JADX API integration
│       └── GhidraAnalyzer.java   # Ghidra API integration
├── Dockerfile               # Multi-stage build with all tools
├── pom.xml                  # Maven build configuration
├── justfile                 # Task runner commands
└── README.md
```

## Requirements

- Docker
- just (command runner) - `cargo install just` or `brew install just`

## Usage

### Building

```bash
# Build Docker image with all tools
just build-docker

# Build Java analyzer inside container
just build
```

### Running Analysis

```bash
# Analyze a single APK
just analyze path/to/app.apk

# Analyze with custom output directory
just analyze path/to/app.apk /workspace/output/myanalysis

# Run only JADX decompilation
just jadx path/to/app.apk

# Run only Ghidra analysis on a DEX file
just ghidra path/to/classes.dex
```

### Interactive Mode

```bash
# Start interactive shell in container
just shell

# Inside container:
java -jar target/maadif-analyzer-1.0.0.jar /workspace/apks/app.apk
```

## Analysis Output

The analyzer produces several output files:

- `full_analysis_report.txt` - Comprehensive human-readable report
- `analysis_result.json` - Machine-readable JSON output
- `jadx_analysis_report.txt` - JADX-specific decompilation report
- `ghidra_*_report.txt` - Ghidra analysis for each binary
- `jadx_output/` - Decompiled Java source code
  - `sources/` - Java source files
  - `resources/` - Extracted resources

## What Gets Analyzed

### JADX Analysis
- Full Java source code decompilation
- Class, method, and field enumeration
- AndroidManifest.xml parsing
- Permission extraction
- Security configuration checks
- URL and endpoint discovery
- Hardcoded secret detection
- Activity/Service/Receiver/Provider identification

### Ghidra Analysis
- Function enumeration and signatures
- Cross-references (callers/callees)
- String extraction
- Import/export analysis
- Memory section mapping
- Data structure identification

### Security Checks
- Debuggable flag detection
- Backup configuration
- Cleartext traffic settings
- Exported component analysis
- Dangerous permission usage
- Potential hardcoded secrets
- Crypto-related code identification
- Network communication patterns

## Tools Included in Docker Image

- **Ghidra 12.0.4** - NSA reverse engineering framework
- **JADX 1.5.1** - DEX to Java decompiler
- **apktool** - APK resource decoder
- **dex2jar** - DEX to JAR converter
- **smali/baksmali** - DEX assembler/disassembler
- **radare2** - Reverse engineering framework
- **Cutter** - GUI for radare2
- **androguard** - Python Android analysis
- **frida-tools** - Dynamic instrumentation
- **objection** - Runtime mobile exploration

## API Usage

You can use the analyzers programmatically:

```java
import io.maadif.analyzer.*;

// Full analysis
File apk = new File("/path/to/app.apk");
File output = new File("/path/to/output");
ApkAnalyzer analyzer = new ApkAnalyzer(apk, output);
ApkAnalyzer.FullAnalysisResult result = analyzer.analyze();

// JADX only
JadxAnalyzer jadx = new JadxAnalyzer(output);
JadxAnalyzer.DecompilationResult jadxResult = jadx.analyzeApk(apk);

// Ghidra only
GhidraAnalyzer ghidra = new GhidraAnalyzer(output);
GhidraAnalyzer.AnalysisResult ghidraResult = ghidra.analyzeDexFile(dexFile);
```

## License

MIT
