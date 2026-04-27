# Hashing Implementation Plan for Diffing

## Overview

This document details how to implement method/function hashing during analysis for both **Java/DEX** (via JADX) and **Native binaries** (via Ghidra). These hashes enable efficient matching across package versions.

Based on analysis of: BinDiff, Diaphora, ApkDiff, Ghidriff, SimiDroid

---

## Part 1: Java/DEX Hashing (JADX)

### 1.1 Hashes to Compute

| Hash | Purpose | How Tools Do It | Priority |
|------|---------|-----------------|----------|
| `normalized_hash` | Match renamed/obfuscated methods | Normalize registers, keep opcodes+types+constants | HIGH |
| `api_call_hash` | Match by SDK usage pattern | SHA256 of sorted android/java.* calls | HIGH |
| `string_hash` | Match by string constants | SHA256 of sorted string literals | MEDIUM |
| `opcode_hash` | Match by instruction composition | SHA256 of opcode sequence | MEDIUM |
| `signature_shape` | Quick filter | "(II)V" format (types only, no names) | HIGH |

### 1.2 Data to Extract Per Method

```java
public static class MethodDiffFeatures {
    // Basic counts
    public int instructionCount;
    public int registerCount;

    // Signature parts (stable across obfuscation)
    public String returnType;           // "V", "I", "Ljava/lang/String;"
    public List<String> paramTypes;     // ["I", "Ljava/lang/String;"]
    public int paramCount;
    public String signatureShape;       // "(ILjava/lang/String;)V"

    // Flags
    public boolean isStatic;
    public boolean isNative;
    public boolean isAbstract;
    public boolean isSynthetic;

    // API calls (VERY STABLE - SDK names don't change)
    public List<String> apiCalls;       // ["android.util.Log->d", "java.lang.String->length"]
    public String apiCallHash;          // SHA256(sorted(apiCalls))

    // String constants
    public List<String> stringLiterals;
    public String stringHash;

    // Opcode features
    public List<String> opcodeSequence; // ["INVOKE_VIRTUAL", "MOVE_RESULT", ...]
    public String opcodeHash;           // SHA256(opcodeSequence.join(";"))
    public Map<String, Integer> opcodeHistogram; // {"INVOKE_VIRTUAL": 5, ...}

    // The main matching hash
    public String normalizedHash;       // SHA256 of normalized bytecode

    // Call graph stats
    public int calleeCount;             // Methods this calls
}
```

### 1.3 Normalized Hash Algorithm (Java/DEX)

Based on `DB_STRUCTURES_FOR_DIFFING.md` and how Diaphora/ApkDiff do it:

```java
/**
 * Compute normalized hash for obfuscation-resistant matching.
 *
 * KEEPS: opcodes, types, constants, external API calls
 * NORMALIZES: register numbers (first-use sequential), internal references
 */
public String computeNormalizedHash(MethodNode methodNode) {
    StringBuilder sb = new StringBuilder();
    Map<Integer, Integer> registerMap = new HashMap<>();
    int regCounter = 0;

    InsnNode[] instructions = methodNode.getInstructions();
    if (instructions == null) return null;

    for (InsnNode insn : instructions) {
        if (insn == null) continue;

        // 1. OPCODE (always keep)
        sb.append(insn.getType().toString()).append(";");

        // 2. NORMALIZE REGISTERS (v0,v1 -> R0,R1 by first use)
        for (InsnArg arg : insn.getArguments()) {
            if (arg.isRegister()) {
                int regNum = ((RegisterArg) arg).getRegNum();
                if (!registerMap.containsKey(regNum)) {
                    registerMap.put(regNum, regCounter++);
                }
                sb.append("R").append(registerMap.get(regNum)).append(",");
            }
        }

        // 3. KEEP TYPE INFORMATION
        if (insn.getResult() != null) {
            sb.append("T:").append(insn.getResult().getType()).append(";");
        }

        // 4. HANDLE METHOD CALLS
        if (insn instanceof InvokeNode) {
            InvokeNode invoke = (InvokeNode) insn;
            MethodInfo callMth = invoke.getCallMth();
            if (callMth != null) {
                String calleeClass = callMth.getDeclClass().getFullName();

                if (isExternalApi(calleeClass)) {
                    // KEEP full signature for external APIs (stable)
                    sb.append("API:").append(callMth.getFullId()).append(";");
                } else {
                    // For internal calls, keep only signature SHAPE (not name)
                    sb.append("CALL:")
                      .append(callMth.getReturnType()).append("(")
                      .append(callMth.getArgumentsTypes().stream()
                          .map(Object::toString)
                          .collect(Collectors.joining(",")))
                      .append(");");
                }
            }
        }

        // 5. KEEP CONSTANTS
        if (insn instanceof ConstStringNode) {
            String str = ((ConstStringNode) insn).getString();
            // Hash strings to avoid length issues
            sb.append("STR:").append(Integer.toHexString(str.hashCode())).append(";");
        }
        if (insn instanceof LiteralArg) {
            sb.append("NUM:").append(((LiteralArg) insn).getLiteral()).append(";");
        }

        // 6. KEEP FIELD ACCESS TYPES (not names for internal)
        if (insn instanceof IndexInsnNode && insn.getType() == InsnType.IGET ||
            insn.getType() == InsnType.SGET) {
            FieldInfo field = (FieldInfo) ((IndexInsnNode) insn).getIndex();
            if (isExternalApi(field.getDeclClass().getFullName())) {
                sb.append("FAPI:").append(field.getFullId()).append(";");
            } else {
                sb.append("FIELD:").append(field.getType()).append(";");
            }
        }
    }

    return sha256(sb.toString());
}

private boolean isExternalApi(String className) {
    return className.startsWith("android.") ||
           className.startsWith("java.") ||
           className.startsWith("javax.") ||
           className.startsWith("kotlin.") ||
           className.startsWith("com.google.android.") ||
           className.startsWith("androidx.");
}
```

### 1.4 API Call Hash Algorithm

```java
/**
 * Extract and hash API calls (most stable feature for obfuscated code).
 */
public void extractApiCalls(MethodNode methodNode, MethodDiffFeatures features) {
    Set<String> apiCalls = new TreeSet<>(); // TreeSet for sorted order

    InsnNode[] instructions = methodNode.getInstructions();
    if (instructions == null) return;

    for (InsnNode insn : instructions) {
        if (insn instanceof InvokeNode) {
            InvokeNode invoke = (InvokeNode) insn;
            MethodInfo callMth = invoke.getCallMth();
            if (callMth != null) {
                String calleeClass = callMth.getDeclClass().getFullName();

                if (isExternalApi(calleeClass)) {
                    // Format: "android.util.Log->d" or "java.lang.String->length"
                    String apiCall = calleeClass + "->" + callMth.getName();
                    apiCalls.add(apiCall);
                    features.calleeCount++;
                }
            }
        }
    }

    features.apiCalls = new ArrayList<>(apiCalls);
    features.apiCallHash = sha256(String.join(",", apiCalls));
}
```

### 1.5 Signature Shape

```java
/**
 * Extract signature shape (types only, no names).
 * e.g., "(ILjava/lang/String;)V"
 */
public void extractSignatureShape(MethodNode methodNode, MethodDiffFeatures features) {
    MethodInfo mthInfo = methodNode.getMethodInfo();

    features.returnType = mthInfo.getReturnType().toString();
    features.paramTypes = mthInfo.getArgumentsTypes().stream()
        .map(Object::toString)
        .collect(Collectors.toList());
    features.paramCount = features.paramTypes.size();

    // Shape: "(param1,param2,...)returnType"
    features.signatureShape = "(" +
        String.join(",", features.paramTypes) + ")" +
        features.returnType;
}
```

---

## Part 2: Native Code Hashing (Ghidra)

### 2.1 Hashes to Compute

| Hash | Purpose | How BinDiff/Diaphora Do It | Priority |
|------|---------|---------------------------|----------|
| `mnemonic_hash` | Match by instruction sequence | SHA256 of mnemonic sequence | HIGH |
| `cfg_hash` | Match by control flow structure | Hash of (block_count, edges, topology) | HIGH |
| `prime_product` | Order-independent structure match | Product of primes per mnemonic | HIGH |
| `import_call_hash` | Match by library usage | SHA256 of sorted import calls | HIGH |
| `string_refs_hash` | Match by string references | SHA256 of sorted referenced strings | MEDIUM |
| `kgh_hash` | Multi-feature graph hash (Diaphora) | Prime product of graph features | MEDIUM |

### 2.2 Data to Extract Per Function

```java
public static class FunctionDiffFeatures {
    // Basic counts
    public int instructionCount;
    public int basicBlockCount;
    public int edgeCount;
    public int bodySize;                // bytes

    // CFG metrics
    public int cyclomaticComplexity;    // edges - nodes + 2
    public int loopCount;
    public int maxNestingDepth;

    // Call graph
    public int calleeCount;
    public int callerCount;
    public List<String> importCalls;    // ["malloc", "free", "memcpy"]
    public String importCallHash;

    // String references
    public List<String> stringRefs;
    public String stringRefsHash;

    // Instruction features
    public List<String> mnemonics;      // ["mov", "bl", "add", ...]
    public String mnemonicHash;         // SHA256(mnemonics.join(";"))
    public Map<String, Integer> mnemonicHistogram;

    // Structural hashes
    public String cfgHash;              // Graph structure hash
    public String primeProduct;         // BinDiff-style prime product
    public String kghHash;              // Diaphora KOKA hash

    // Function flags
    public boolean isThunk;
    public boolean isExternal;
    public boolean isExport;
    public boolean hasNoReturn;
}
```

### 2.3 Mnemonic Hash Algorithm

```python
# In Ghidra Python script (or via Ghidra API in Java)

def compute_mnemonic_hash(function, program):
    """
    Hash of instruction mnemonics in order.
    Ignores operand values, keeps instruction types.
    """
    listing = program.getListing()
    mnemonics = []

    for insn in listing.getInstructions(function.getBody(), True):
        mnemonics.append(insn.getMnemonicString())

    # Join with semicolon and hash
    mnemonic_str = ";".join(mnemonics)
    return hashlib.sha256(mnemonic_str.encode()).hexdigest()
```

### 2.4 CFG Hash Algorithm

Based on Ghidriff's approach:

```python
def compute_cfg_hash(function, program):
    """
    Hash of control flow graph structure.
    DFS order: for each block, record (insn_count, successor_indices).
    """
    from ghidra.program.model.block import BasicBlockModel

    block_model = BasicBlockModel(program)
    blocks = list(block_model.getCodeBlocksContaining(function.getBody(), monitor))

    if not blocks:
        return None

    # Find entry block and do DFS
    entry_block = blocks[0]  # Usually first block
    visited = set()
    ordered_blocks = []

    def dfs(block):
        if block in visited:
            return
        visited.add(block)
        ordered_blocks.append(block)
        for dest in block.getDestinations(monitor):
            dest_block = dest.getDestinationBlock()
            if dest_block:
                dfs(dest_block)

    dfs(entry_block)

    # Build hash string
    parts = []
    for i, block in enumerate(ordered_blocks):
        insn_count = count_instructions(block, listing)
        successors = []
        for dest in block.getDestinations(monitor):
            dest_block = dest.getDestinationBlock()
            if dest_block and dest_block in ordered_blocks:
                successors.append(ordered_blocks.index(dest_block))

        parts.append(f"{insn_count}:{','.join(map(str, sorted(successors)))}")

    return hashlib.sha256(";".join(parts).encode()).hexdigest()
```

### 2.5 Prime Product Algorithm (BinDiff Style)

```python
# First 200 primes (enough for most mnemonics)
PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
          73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
          157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, ...]

# Mnemonic to prime mapping (built on first encounter)
MNEMONIC_PRIMES = {}
_next_prime_idx = 0

def get_mnemonic_prime(mnemonic):
    global _next_prime_idx
    if mnemonic not in MNEMONIC_PRIMES:
        MNEMONIC_PRIMES[mnemonic] = PRIMES[_next_prime_idx % len(PRIMES)]
        _next_prime_idx += 1
    return MNEMONIC_PRIMES[mnemonic]

def compute_prime_product(function, program):
    """
    BinDiff-style prime product.
    Order-independent fingerprint of instruction composition.
    """
    listing = program.getListing()
    product = 1

    for insn in listing.getInstructions(function.getBody(), True):
        mnemonic = insn.getMnemonicString()
        product *= get_mnemonic_prime(mnemonic)

    # Return as string (can be very large number)
    return str(product)
```

### 2.6 KOKA/KGH Hash (Diaphora Style)

```python
# Feature primes from Diaphora
KGH_PRIMES = {
    'NODE_ENTRY': 2,
    'NODE_EXIT': 3,
    'NODE_NORMAL': 5,
    'EDGE_CONDITIONAL': 7,
    'EDGE_UNCONDITIONAL': 11,
    'FEATURE_LOOP': 13,
    'FEATURE_CALL': 17,
    'FEATURE_DATA_REF': 19,
    'FEATURE_STRING_REF': 23,
    'FEATURE_IMPORT_CALL': 29,
}

def compute_kgh_hash(function, program):
    """
    Koret-Karamitas Graph Hash.
    Multiplies primes based on structural/semantic features.
    """
    block_model = BasicBlockModel(program)
    blocks = list(block_model.getCodeBlocksContaining(function.getBody(), monitor))

    product = 1

    for block in blocks:
        # Node type
        in_degree = block.getNumSources(monitor)
        out_degree = block.getNumDestinations(monitor)

        if in_degree == 0:
            product *= KGH_PRIMES['NODE_ENTRY']
        elif out_degree == 0:
            product *= KGH_PRIMES['NODE_EXIT']
        else:
            product *= KGH_PRIMES['NODE_NORMAL']

        # Edge features
        if out_degree > 1:
            product *= KGH_PRIMES['EDGE_CONDITIONAL'] ** out_degree
        elif out_degree == 1:
            product *= KGH_PRIMES['EDGE_UNCONDITIONAL']

        # Instruction features in block
        for insn in listing.getInstructions(block, True):
            mnemonic = insn.getMnemonicString().lower()

            if mnemonic.startswith('bl') or mnemonic == 'call':
                product *= KGH_PRIMES['FEATURE_CALL']

            # Check for string/data references
            for ref in insn.getReferencesFrom():
                ref_type = ref.getReferenceType()
                if ref_type.isData():
                    product *= KGH_PRIMES['FEATURE_DATA_REF']

    return str(product)
```

### 2.7 Import Call Hash

```python
def compute_import_call_hash(function, program):
    """
    Hash of imported functions called by this function.
    """
    import_calls = set()

    for callee in function.getCalledFunctions(monitor):
        if callee.isExternal() or callee.isThunk():
            import_calls.add(callee.getName())

    # Sort for deterministic hash
    sorted_imports = sorted(import_calls)
    return hashlib.sha256(",".join(sorted_imports).encode()).hexdigest()
```

---

## Part 3: Database Schema Updates

### 3.1 Java Methods Table Extension

```sql
-- Add to methods table in analysis.db
ALTER TABLE methods ADD COLUMN instruction_count INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN register_count INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN return_type TEXT;
ALTER TABLE methods ADD COLUMN param_types TEXT;         -- JSON array
ALTER TABLE methods ADD COLUMN param_count INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN signature_shape TEXT;     -- "(II)V" format
ALTER TABLE methods ADD COLUMN is_static INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN is_native INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN is_abstract INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN is_synthetic INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN callee_count INTEGER DEFAULT 0;
ALTER TABLE methods ADD COLUMN api_calls TEXT;           -- JSON array
ALTER TABLE methods ADD COLUMN api_call_hash TEXT;
ALTER TABLE methods ADD COLUMN string_literals TEXT;     -- JSON array
ALTER TABLE methods ADD COLUMN string_hash TEXT;
ALTER TABLE methods ADD COLUMN opcode_sequence TEXT;     -- JSON array
ALTER TABLE methods ADD COLUMN opcode_hash TEXT;
ALTER TABLE methods ADD COLUMN opcode_histogram TEXT;    -- JSON object
ALTER TABLE methods ADD COLUMN normalized_hash TEXT;

-- Indexes for efficient matching
CREATE INDEX idx_methods_normalized ON methods(normalized_hash);
CREATE INDEX idx_methods_api_hash ON methods(api_call_hash);
CREATE INDEX idx_methods_signature ON methods(signature_shape);
CREATE INDEX idx_methods_opcode ON methods(opcode_hash);
```

### 3.2 Native Functions Table Extension

```sql
-- Add to functions table in *.so.db files
ALTER TABLE functions ADD COLUMN instruction_count INTEGER DEFAULT 0;
ALTER TABLE functions ADD COLUMN basic_block_count INTEGER DEFAULT 0;
ALTER TABLE functions ADD COLUMN edge_count INTEGER DEFAULT 0;
ALTER TABLE functions ADD COLUMN cyclomatic_complexity INTEGER DEFAULT 0;
ALTER TABLE functions ADD COLUMN callee_count INTEGER DEFAULT 0;
ALTER TABLE functions ADD COLUMN caller_count INTEGER DEFAULT 0;
ALTER TABLE functions ADD COLUMN import_calls TEXT;       -- JSON array
ALTER TABLE functions ADD COLUMN import_call_hash TEXT;
ALTER TABLE functions ADD COLUMN string_refs TEXT;        -- JSON array
ALTER TABLE functions ADD COLUMN string_refs_hash TEXT;
ALTER TABLE functions ADD COLUMN mnemonics TEXT;          -- JSON array (optional, large)
ALTER TABLE functions ADD COLUMN mnemonic_hash TEXT;
ALTER TABLE functions ADD COLUMN mnemonic_histogram TEXT; -- JSON object
ALTER TABLE functions ADD COLUMN cfg_hash TEXT;
ALTER TABLE functions ADD COLUMN prime_product TEXT;
ALTER TABLE functions ADD COLUMN kgh_hash TEXT;

-- Indexes
CREATE INDEX idx_functions_mnemonic ON functions(mnemonic_hash);
CREATE INDEX idx_functions_cfg ON functions(cfg_hash);
CREATE INDEX idx_functions_prime ON functions(prime_product);
CREATE INDEX idx_functions_import ON functions(import_call_hash);
```

---

## Part 4: Implementation Order

### Step 1: Java/DEX Hashing (JadxAnalyzer.java)
1. Extend `MethodInfo` class with new fields
2. Add `extractDiffingFeatures()` method
3. Call it during `extractMetadataOnly()` loop
4. Update Database.java to save new columns
5. Test: Analyze APK, query DB for hashes

### Step 2: Native Hashing (GhidraAnalyzer.java or Ghidra script)
1. Extend `FunctionInfo` class with new fields
2. Add hash computation methods (mnemonic, CFG, prime, KGH)
3. Extract and store during native analysis
4. Update Database.java native schema
5. Test: Analyze .so, query DB for hashes

### Step 3: Diff API
1. Implement DiffEngine with multi-pass matching
2. Add `/diff` endpoint
3. Validate packages analyzed before diffing
4. Return full results

---

## Part 5: Matching Priority (How to Use Hashes)

### Java Method Matching
| Pass | Match By | Confidence |
|------|----------|------------|
| 0 | Exact name (class.method.signature) | 100% |
| 1 | `normalized_hash` | 100% |
| 2 | `api_call_hash` + `signature_shape` | 95% |
| 3 | Call graph propagation | 85% |
| 4 | `opcode_hash` + similar `instruction_count` | 75% |
| 5 | Fuzzy: Jaccard(apiCalls) > 0.7 | 60% |

### Native Function Matching
| Pass | Match By | Confidence |
|------|----------|------------|
| 0 | Exact name (symbol) | 100% |
| 1 | `cfg_hash` | 95% |
| 2 | `mnemonic_hash` | 95% |
| 3 | `prime_product` | 90% |
| 4 | `import_call_hash` + similar size | 85% |
| 5 | `kgh_hash` | 80% |
| 6 | Call graph propagation | 75% |
