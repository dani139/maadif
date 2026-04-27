# Package Version Diff API Implementation Plan

## Overview
Add a REST API endpoint to diff two versions of the same package, comparing both **Java/DEX methods** and **native library functions** across APK versions. The diff leverages obfuscation-resistant features documented in `DB_STRUCTURES_FOR_DIFFING.md`.

This implementation is split into two phases:
1. **Phase A**: Enhance analysis with diffing features (hashing, instruction counting, etc.)
2. **Phase B**: Add diff API endpoint with matching algorithm

---

## Phase A: Enhance Analysis with Diffing Features

**Goal:** During APK analysis, extract and store additional features needed for version diffing. This is a prerequisite before any diffing can happen.

### A1. Extend Database Schema for Java Methods

**File:** `src/main/java/io/maadif/server/Database.java`

Add diffing columns to `methods` table:

```sql
-- New columns for diffing
ALTER TABLE methods ADD COLUMN instruction_count INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN basic_block_count INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN return_type TEXT;
ALTER TABLE methods ADD COLUMN param_types TEXT;           -- JSON array
ALTER TABLE methods ADD COLUMN param_count INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN is_static INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN is_native INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN callee_count INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN api_calls TEXT;             -- JSON array of android/java.* calls
ALTER TABLE methods ADD COLUMN api_call_hash TEXT;         -- SHA256 of sorted api_calls
ALTER TABLE methods ADD COLUMN string_literals TEXT;       -- JSON array
ALTER TABLE methods ADD COLUMN string_hash TEXT;
ALTER TABLE methods ADD COLUMN opcode_histogram TEXT;      -- JSON {"invoke-virtual": 5, ...}
ALTER TABLE methods ADD COLUMN normalized_hash TEXT;       -- bytecode hash with registers normalized

-- Indexes for efficient diffing queries
CREATE INDEX idx_methods_api_hash ON methods(api_call_hash);
CREATE INDEX idx_methods_normalized ON methods(normalized_hash);
CREATE INDEX idx_methods_signature ON methods(return_type, param_count);
CREATE INDEX idx_methods_name ON methods(name);
```

### A2. Extend Native Function Schema

Add diffing columns to native `functions` table (in *.so.db files):

```sql
ALTER TABLE functions ADD COLUMN instruction_count INTEGER DEFAULT 0;
ALTER TABLE functions ADD COLUMN basic_block_count INTEGER DEFAULT 0;
ALTER TABLE functions ADD COLUMN callee_count INTEGER DEFAULT 0;
ALTER TABLE functions ADD COLUMN import_calls TEXT;        -- JSON array of imported functions called
ALTER TABLE functions ADD COLUMN import_call_hash TEXT;    -- SHA256 of sorted imports
ALTER TABLE functions ADD COLUMN string_refs TEXT;         -- JSON array of referenced strings
ALTER TABLE functions ADD COLUMN string_hash TEXT;
ALTER TABLE functions ADD COLUMN mnemonic_hash TEXT;       -- hash of instruction mnemonic sequence
ALTER TABLE functions ADD COLUMN cfg_hash TEXT;            -- hash of CFG topology

-- Indexes
CREATE INDEX idx_functions_cfg ON functions(cfg_hash);
CREATE INDEX idx_functions_mnemonic ON functions(mnemonic_hash);
CREATE INDEX idx_functions_import ON functions(import_call_hash);
```

### A3. Extend MethodInfo Class in JadxAnalyzer

**File:** `src/main/java/io/maadif/analyzer/JadxAnalyzer.java`

```java
public static class MethodInfo {
    // Existing fields
    public String name;
    public String signature;
    public int accessFlags;
    public int codeLines;
    public boolean decompileFailed = false;
    public String errorMessage;

    // New diffing fields
    public int instructionCount;
    public int basicBlockCount;
    public String returnType;
    public List<String> paramTypes = new ArrayList<>();
    public int paramCount;
    public boolean isStatic;
    public boolean isNative;
    public int calleeCount;
    public List<String> apiCalls = new ArrayList<>();      // Only android.* and java.* calls
    public String apiCallHash;
    public List<String> stringLiterals = new ArrayList<>();
    public String stringHash;
    public Map<String, Integer> opcodeHistogram = new HashMap<>();
    public String normalizedHash;
}
```

### A4. Add Feature Extraction Method

**File:** `src/main/java/io/maadif/analyzer/JadxAnalyzer.java`

Add new method `extractDiffingFeatures()`:

```java
/**
 * Extract diffing-relevant features from a method's bytecode.
 * Call this after getting MethodNode from JavaMethod.
 */
private void extractDiffingFeatures(MethodNode methodNode, MethodInfo info) {
    if (methodNode == null || methodNode.isNoCode()) {
        return;
    }

    try {
        methodNode.load();
    } catch (Exception e) {
        return;
    }

    InsnNode[] instructions = methodNode.getInstructions();
    if (instructions == null) {
        return;
    }

    // 1. Count instructions
    info.instructionCount = instructions.length;

    // 2. Extract method signature info
    MethodInfo mthInfo = methodNode.getMethodInfo();
    info.returnType = mthInfo.getReturnType().toString();
    for (ArgType arg : mthInfo.getArgumentsTypes()) {
        info.paramTypes.add(arg.toString());
    }
    info.paramCount = info.paramTypes.size();
    info.isStatic = methodNode.getAccessFlags().isStatic();
    info.isNative = methodNode.getAccessFlags().isNative();

    // 3. Build opcode histogram and extract features
    StringBuilder normalizedBytecode = new StringBuilder();
    Map<Integer, Integer> registerMap = new HashMap<>();
    int regCounter = 0;

    for (InsnNode insn : instructions) {
        if (insn == null) continue;

        // Opcode histogram
        String opcode = insn.getType().toString();
        info.opcodeHistogram.merge(opcode, 1, Integer::sum);

        // Build normalized bytecode
        normalizedBytecode.append(opcode).append(";");

        // Normalize registers
        for (InsnArg arg : insn.getArguments()) {
            if (arg.isRegister()) {
                int regNum = ((RegisterArg) arg).getRegNum();
                if (!registerMap.containsKey(regNum)) {
                    registerMap.put(regNum, regCounter++);
                }
                normalizedBytecode.append("R").append(registerMap.get(regNum)).append(",");
            }
        }

        // Extract API calls from invoke instructions
        if (insn instanceof InvokeNode) {
            InvokeNode invoke = (InvokeNode) insn;
            jadx.core.dex.info.MethodInfo callMth = invoke.getCallMth();
            if (callMth != null) {
                String calleeClass = callMth.getDeclClass().getFullName();
                String apiCall = calleeClass + "->" + callMth.getName();

                // Filter for stable API calls only
                if (isStableApi(calleeClass)) {
                    info.apiCalls.add(apiCall);
                }

                // Full signature for normalized hash
                normalizedBytecode.append("CALL:").append(callMth.getShortId()).append(";");
                info.calleeCount++;
            }
        }

        // Extract string constants
        if (insn instanceof ConstStringNode) {
            String str = ((ConstStringNode) insn).getString();
            if (str != null && !str.isEmpty()) {
                info.stringLiterals.add(str);
                normalizedBytecode.append("STR:").append(hashString(str)).append(";");
            }
        }
    }

    // 4. Compute hashes
    info.normalizedHash = sha256(normalizedBytecode.toString());

    Collections.sort(info.apiCalls);
    info.apiCallHash = sha256(String.join(",", info.apiCalls));

    Collections.sort(info.stringLiterals);
    info.stringHash = sha256(String.join(",", info.stringLiterals));
}

private boolean isStableApi(String className) {
    return className.startsWith("android.") ||
           className.startsWith("java.") ||
           className.startsWith("javax.") ||
           className.startsWith("kotlin.") ||
           className.startsWith("com.google.android.");
}

private String sha256(String input) {
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte b : hash) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    } catch (Exception e) {
        return "";
    }
}

private String hashString(String s) {
    // Simple hash for strings in normalized bytecode
    return Integer.toHexString(s.hashCode());
}
```

### A5. Update extractMetadataOnly() to Call Feature Extraction

Modify the existing method extraction loop to call `extractDiffingFeatures()`:

```java
// In extractMetadataOnly()
for (JavaMethod method : cls.getMethods()) {
    MethodInfo methodInfo = new MethodInfo();
    methodInfo.name = method.getName();
    // ... existing code ...

    // NEW: Extract diffing features
    try {
        MethodNode methodNode = method.getMethodNode();
        extractDiffingFeatures(methodNode, methodInfo);
    } catch (Exception e) {
        // Skip if features can't be extracted
    }

    classInfo.methods.add(methodInfo);
}
```

### A6. Update Database Save Methods

**File:** `src/main/java/io/maadif/server/Database.java`

Update method saving to include new columns:

```java
public void saveMethod(int classId, JadxAnalyzer.MethodInfo method) throws SQLException {
    String sql = """
        INSERT INTO methods (class_id, name, signature, decompile_failed, error_message,
                           instruction_count, basic_block_count, return_type, param_types,
                           param_count, is_static, is_native, callee_count,
                           api_calls, api_call_hash, string_literals, string_hash,
                           opcode_histogram, normalized_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """;
    try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
        ps.setInt(1, classId);
        ps.setString(2, method.name);
        ps.setString(3, method.signature);
        ps.setInt(4, method.decompileFailed ? 1 : 0);
        ps.setString(5, method.errorMessage);
        ps.setInt(6, method.instructionCount);
        ps.setInt(7, method.basicBlockCount);
        ps.setString(8, method.returnType);
        ps.setString(9, toJson(method.paramTypes));
        ps.setInt(10, method.paramCount);
        ps.setInt(11, method.isStatic ? 1 : 0);
        ps.setInt(12, method.isNative ? 1 : 0);
        ps.setInt(13, method.calleeCount);
        ps.setString(14, toJson(method.apiCalls));
        ps.setString(15, method.apiCallHash);
        ps.setString(16, toJson(method.stringLiterals));
        ps.setString(17, method.stringHash);
        ps.setString(18, toJson(method.opcodeHistogram));
        ps.setString(19, method.normalizedHash);
        ps.executeUpdate();
    }
}
```

### A7. (Optional) Enhance Native Analysis

Similar enhancements to `GhidraAnalyzer.java` if Ghidra scripts support:
- instruction_count
- basic_block_count
- import_calls (PLT calls)
- string_refs
- mnemonic_hash
- cfg_hash

---

## Phase B: Diff API Endpoint

**Prerequisite:** Both package versions must be analyzed first. The diff endpoint validates this.

### B1. API Design

**Endpoint:**
```
POST /diff
Content-Type: application/json

{
  "package": "com.whatsapp",
  "version1": "2.24.1.6",
  "version2": "2.24.2.7"
}
```

**Response (Full Details):**
```json
{
  "package": "com.whatsapp",
  "version1": "2.24.1.6",
  "version2": "2.24.2.7",
  "java": {
    "summary": {
      "methods_added": 1234,
      "methods_removed": 567,
      "methods_modified": 890,
      "methods_unchanged": 45000,
      "classes_added": 100,
      "classes_removed": 50
    },
    "added_methods": [
      {"class": "com.whatsapp.NewClass", "method": "newMethod(I)V"}
    ],
    "removed_methods": [
      {"class": "com.whatsapp.OldClass", "method": "oldMethod()V"}
    ],
    "modified_methods": [
      {
        "v1_class": "com.whatsapp.a.b",
        "v1_method": "a(I)V",
        "v2_class": "com.whatsapp.a.c",
        "v2_method": "b(I)V",
        "similarity": 0.92,
        "match_type": "api_call_hash"
      }
    ],
    "unchanged_methods": [...]
  },
  "native": {
    "summary": {...},
    "libraries": {
      "libwhatsapp.so": {...}
    }
  }
}
```

**Error Response (packages not analyzed):**
```json
{
  "error": "Package com.whatsapp version 2.24.1.6 has not been analyzed. Please analyze it first using POST /analyze"
}
```

### B2. Implement Diff Endpoint Handler

**File:** `src/main/java/io/maadif/server/ApiServer.java`

```java
// Register endpoint
server.createContext("/diff", this::handleDiff);

private void handleDiff(HttpExchange exchange) throws IOException {
    if (!exchange.getRequestMethod().equals("POST")) {
        sendError(exchange, 405, "Method not allowed");
        return;
    }

    // Parse request
    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    // Parse JSON to get package, version1, version2

    String packageName = ...;
    String version1 = ...;
    String version2 = ...;

    // Check both versions are analyzed
    File db1Path = new File(DATA_DIR + "/" + packageName + "/" + version1 + "/analysis.db");
    File db2Path = new File(DATA_DIR + "/" + packageName + "/" + version2 + "/analysis.db");

    if (!db1Path.exists()) {
        sendError(exchange, 400, "Package " + packageName + " version " + version1 +
                  " has not been analyzed. Please analyze it first using POST /analyze");
        return;
    }
    if (!db2Path.exists()) {
        sendError(exchange, 400, "Package " + packageName + " version " + version2 +
                  " has not been analyzed. Please analyze it first using POST /analyze");
        return;
    }

    // Run diff
    Database db1 = new Database(db1Path.getPath());
    Database db2 = new Database(db2Path.getPath());

    DiffEngine diffEngine = new DiffEngine();
    DiffResult result = diffEngine.diff(db1, db2);

    // Also diff native libraries if present
    // ...

    sendJson(exchange, 200, result.toJson());
}
```

### B3. Implement DiffEngine

**New File:** `src/main/java/io/maadif/server/DiffEngine.java`

```java
package io.maadif.server;

import java.util.*;

public class DiffEngine {

    public DiffResult diff(Database db1, Database db2) {
        DiffResult result = new DiffResult();

        // Load all methods from both databases
        List<MethodData> methods1 = db1.getAllMethodsWithFeatures();
        List<MethodData> methods2 = db2.getAllMethodsWithFeatures();

        Map<Integer, MatchResult> matches = new HashMap<>();
        Set<Integer> unmatched1 = new HashSet<>();
        Set<Integer> unmatched2 = new HashSet<>();

        for (MethodData m : methods1) unmatched1.add(m.id);
        for (MethodData m : methods2) unmatched2.add(m.id);

        // Build indexes for efficient matching
        Map<String, List<MethodData>> byName1 = indexByFullName(methods1);
        Map<String, List<MethodData>> byName2 = indexByFullName(methods2);
        Map<String, List<MethodData>> byNormHash1 = indexByNormalizedHash(methods1);
        Map<String, List<MethodData>> byNormHash2 = indexByNormalizedHash(methods2);
        Map<String, List<MethodData>> byApiHash1 = indexByApiCallHash(methods1);
        Map<String, List<MethodData>> byApiHash2 = indexByApiCallHash(methods2);

        // Pass 0: Exact name match (class + method + signature)
        matchByExactName(byName1, byName2, matches, unmatched1, unmatched2);

        // Pass 1: Same normalized_hash
        matchByHash(byNormHash1, byNormHash2, "normalized_hash", matches, unmatched1, unmatched2);

        // Pass 2: Same api_call_hash + same signature shape
        matchByApiAndSignature(byApiHash1, methods2, matches, unmatched1, unmatched2);

        // Pass 3: Call graph propagation
        // (requires loading method_calls table)

        // Pass 4: Fuzzy matching for remaining
        matchByFuzzyFeatures(methods1, methods2, matches, unmatched1, unmatched2);

        // Build result
        result.buildFromMatches(matches, unmatched1, unmatched2, methods1, methods2);
        return result;
    }

    private void matchByExactName(...) {
        // Match methods with identical class.method(signature)
    }

    private void matchByHash(...) {
        // Match methods with same normalized_hash (unique matches only)
    }

    private void matchByApiAndSignature(...) {
        // Match methods with same api_call_hash AND same return_type AND same param_count
    }

    private void matchByFuzzyFeatures(...) {
        // For remaining unmatched, compute similarity score:
        // - instruction_count within 20%
        // - api_calls Jaccard > 0.7
        // - string_literals overlap
    }
}

public class MatchResult {
    public int id1;
    public int id2;
    public String matchType;    // "exact_name", "normalized_hash", "api_call", "callgraph", "fuzzy"
    public double similarity;
    public boolean isModified;  // true if matched but normalized_hash differs
}

public class DiffResult {
    public int methodsAdded;
    public int methodsRemoved;
    public int methodsModified;
    public int methodsUnchanged;

    public List<MethodData> addedMethods = new ArrayList<>();
    public List<MethodData> removedMethods = new ArrayList<>();
    public List<ModifiedMethod> modifiedMethods = new ArrayList<>();
    public List<MethodData> unchangedMethods = new ArrayList<>();

    public String toJson() { ... }
}
```

---

## Files to Modify/Create

### Phase A (Analysis Enhancement)
| File | Changes |
|------|---------|
| `Database.java` | Add diffing columns to methods table schema, update save methods |
| `JadxAnalyzer.java` | Add MethodInfo fields, add `extractDiffingFeatures()` method |

### Phase B (Diff API)
| File | Changes |
|------|---------|
| `ApiServer.java` | Add `/diff` endpoint handler |
| `DiffEngine.java` (new) | Multi-pass matching algorithm |

---

## Testing Plan

### Phase A Testing
```bash
# Analyze an APK
curl -X POST http://localhost:8080/analyze -d '{"apk":"com.example/v1.apk"}'

# Query the database to verify new columns are populated
sqlite3 /workspace/data/com.example/1.0/analysis.db \
  "SELECT name, instruction_count, api_call_hash, normalized_hash FROM methods LIMIT 5"
```

### Phase B Testing
```bash
# Analyze two versions
curl -X POST http://localhost:8080/analyze -d '{"apk":"com.example/v1.apk"}'
curl -X POST http://localhost:8080/analyze -d '{"apk":"com.example/v2.apk"}'

# Try diff without analysis (should fail)
curl -X POST http://localhost:8080/diff -d '{
  "package": "com.notanalyzed",
  "version1": "1.0",
  "version2": "2.0"
}'
# Expected: {"error": "Package com.notanalyzed version 1.0 has not been analyzed..."}

# Run diff
curl -X POST http://localhost:8080/diff -d '{
  "package": "com.example",
  "version1": "1.0",
  "version2": "2.0"
}'
```

---

## Key Implementation Details

### Normalized Hash Computation
From `DB_STRUCTURES_FOR_DIFFING.md`:
- Normalize register numbers (v0, v1 -> R0, R1 sequentially by first use)
- Keep opcodes
- Keep type information
- Keep API calls fully qualified
- Keep constants (strings, numbers)
- Hash the normalized bytecode string with SHA256

### Matching Priority (Name First)
1. **Exact name match** - Same class + method + signature
2. **Normalized hash match** - Identical bytecode (possibly renamed)
3. **API call hash match** - Same SDK/library calls + same signature shape
4. **Call graph propagation** - If caller matched, match callees
5. **Fuzzy matching** - Similar features for remaining unmatched

### API Call Filtering
Only include calls to stable packages:
- `android.*`, `java.*`, `javax.*`, `kotlin.*`, `com.google.android.*`

### Full Results
Return **all** methods categorized as:
- `added` - exists only in v2
- `removed` - exists only in v1
- `modified` - matched but bytecode differs
- `unchanged` - matched and identical
