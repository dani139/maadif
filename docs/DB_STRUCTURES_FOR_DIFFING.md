# Database Structures for APK/Binary Diffing

This document describes database schemas for storing analysis data that enables effective diffing between versions of Android APKs (Java/DEX) and native binaries (ARM/x86).

---

## Table of Contents

1. [Java/DEX Code Schema](#1-javadex-code-schema)
2. [Native Code Schema](#2-native-code-schema)
3. [Diffing Algorithms](#3-diffing-algorithms)
4. [Notable Projects](#4-notable-projects)
5. [Implementation Notes](#5-implementation-notes)
6. [Advanced Techniques from BinDiff & Diaphora](#6-advanced-techniques-from-bindiff--diaphora)
7. [Advanced Java/DEX Diffing Techniques](#7-advanced-javadex-diffing-techniques)

---

## 1. Java/DEX Code Schema

### 1.1 Core Tables

```sql
-- ============================================
-- APK METADATA
-- ============================================
CREATE TABLE apks (
    id              INTEGER PRIMARY KEY,
    file_path       TEXT,
    package_name    TEXT,
    version_code    INTEGER,
    version_name    TEXT,
    min_sdk         INTEGER,
    target_sdk      INTEGER,
    sha256          TEXT UNIQUE,
    dex_count       INTEGER,
    analyzed_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- CLASSES
-- ============================================
CREATE TABLE classes (
    id              INTEGER PRIMARY KEY,
    apk_id          INTEGER REFERENCES apks(id),
    dex_index       INTEGER,              -- which DEX file (0, 1, 2...)

    -- Identity
    name            TEXT,                 -- e.g., "Lcom/example/MainActivity;"
    simple_name     TEXT,                 -- e.g., "MainActivity"
    package_name    TEXT,                 -- e.g., "com.example"

    -- Hierarchy
    superclass      TEXT,
    interfaces      TEXT,                 -- JSON array

    -- Flags
    access_flags    INTEGER,
    is_interface    BOOLEAN,
    is_abstract     BOOLEAN,
    is_enum         BOOLEAN,
    is_annotation   BOOLEAN,

    -- Obfuscation detection
    is_obfuscated   BOOLEAN,              -- heuristic: name entropy, length
    name_entropy    REAL,                 -- Shannon entropy of class name

    -- Debug info
    source_file     TEXT,                 -- from SourceFile attribute

    -- Structure metrics
    method_count    INTEGER,
    field_count     INTEGER,
    inner_class_count INTEGER,

    UNIQUE(apk_id, name)
);

CREATE INDEX idx_classes_package ON classes(apk_id, package_name);
CREATE INDEX idx_classes_super ON classes(apk_id, superclass);

-- ============================================
-- METHODS (Primary matching unit)
-- ============================================
CREATE TABLE methods (
    id              INTEGER PRIMARY KEY,
    class_id        INTEGER REFERENCES classes(id),

    -- Identity
    name            TEXT,
    full_signature  TEXT,                 -- "methodName(ILjava/lang/String;)V"

    -- Signature features (STABLE - types don't get obfuscated)
    return_type     TEXT,                 -- "V", "I", "Ljava/lang/String;"
    param_types     TEXT,                 -- JSON: ["I", "Ljava/lang/String;"]
    param_count     INTEGER,

    -- Access flags
    access_flags    INTEGER,
    is_static       BOOLEAN,
    is_native       BOOLEAN,
    is_abstract     BOOLEAN,
    is_constructor  BOOLEAN,              -- <init> or <clinit>
    is_synthetic    BOOLEAN,
    is_bridge       BOOLEAN,

    -- ================================================
    -- CODE STRUCTURE FEATURES (obfuscation-resistant)
    -- ================================================
    instruction_count   INTEGER,
    register_count      INTEGER,
    basic_block_count   INTEGER,

    -- Control flow metrics
    cyclomatic_complexity INTEGER,        -- edges - nodes + 2
    loop_count          INTEGER,
    branch_count        INTEGER,          -- if/switch statements
    try_block_count     INTEGER,

    -- ================================================
    -- BYTECODE HASHES
    -- ================================================
    bytecode_hash       TEXT,             -- SHA256 of raw bytecode
    normalized_hash     TEXT,             -- hash with registers normalized
    structure_hash      TEXT,             -- hash of CFG structure only

    -- ================================================
    -- CALL GRAPH FEATURES (KEY for matching)
    -- ================================================
    callee_count        INTEGER,          -- methods this calls (out-degree)
    caller_count        INTEGER,          -- methods calling this (in-degree)

    -- ================================================
    -- API FINGERPRINT (VERY STABLE - SDK names don't change)
    -- ================================================
    api_calls           TEXT,             -- JSON: ["Landroid/util/Log;->d", ...]
    api_call_count      INTEGER,
    api_call_hash       TEXT,             -- hash of sorted unique api_calls

    -- Categorized API usage
    android_api_calls   TEXT,             -- android.* calls only
    java_api_calls      TEXT,             -- java.* calls only

    -- ================================================
    -- CONSTANTS (usually not obfuscated)
    -- ================================================
    string_literals     TEXT,             -- JSON array
    string_count        INTEGER,
    string_hash         TEXT,             -- hash of sorted strings

    numeric_constants   TEXT,             -- JSON array
    numeric_hash        TEXT,

    -- ================================================
    -- INSTRUCTION HISTOGRAM (opcode distribution)
    -- ================================================
    opcode_histogram    TEXT,             -- JSON: {"invoke-virtual": 5, ...}
    opcode_hash         TEXT,             -- hash of histogram

    -- Instruction categories
    invoke_count        INTEGER,          -- all invoke-* instructions
    field_access_count  INTEGER,          -- iget/iput/sget/sput
    arithmetic_count    INTEGER,          -- add/sub/mul/div/rem
    comparison_count    INTEGER,          -- if-* instructions

    UNIQUE(class_id, name, param_types)
);

CREATE INDEX idx_methods_class ON methods(class_id);
CREATE INDEX idx_methods_signature ON methods(return_type, param_types);
CREATE INDEX idx_methods_api_hash ON methods(api_call_hash);
CREATE INDEX idx_methods_normalized ON methods(normalized_hash);
CREATE INDEX idx_methods_structure ON methods(structure_hash);

-- ============================================
-- FIELDS
-- ============================================
CREATE TABLE fields (
    id              INTEGER PRIMARY KEY,
    class_id        INTEGER REFERENCES classes(id),
    name            TEXT,
    type            TEXT,
    access_flags    INTEGER,
    is_static       BOOLEAN,
    is_final        BOOLEAN,
    initial_value   TEXT,                 -- for static final fields

    UNIQUE(class_id, name, type)
);

-- ============================================
-- CALL GRAPH EDGES
-- ============================================
CREATE TABLE callgraph (
    id              INTEGER PRIMARY KEY,
    caller_id       INTEGER REFERENCES methods(id),
    callee_id       INTEGER REFERENCES methods(id),

    -- For external calls (SDK/library)
    callee_external TEXT,                 -- "Landroid/util/Log;->d" if not in APK

    call_count      INTEGER,              -- how many call sites
    call_type       TEXT,                 -- "virtual", "static", "direct", "super", "interface"

    UNIQUE(caller_id, callee_id, callee_external)
);

CREATE INDEX idx_callgraph_caller ON callgraph(caller_id);
CREATE INDEX idx_callgraph_callee ON callgraph(callee_id);

-- ============================================
-- FIELD ACCESS EDGES
-- ============================================
CREATE TABLE field_accesses (
    id              INTEGER PRIMARY KEY,
    method_id       INTEGER REFERENCES methods(id),
    field_id        INTEGER REFERENCES fields(id),

    -- For external fields
    field_external  TEXT,                 -- "Landroid/os/Build;->MODEL" if not in APK

    access_type     TEXT,                 -- "read" or "write"
    is_static       BOOLEAN,
    count           INTEGER,

    UNIQUE(method_id, field_id, field_external, access_type)
);

-- ============================================
-- TYPE REFERENCES (class dependencies)
-- ============================================
CREATE TABLE type_references (
    id              INTEGER PRIMARY KEY,
    class_id        INTEGER REFERENCES classes(id),
    referenced_type TEXT,
    reference_kind  TEXT,                 -- "extends", "implements", "field", "method_param", "local", "annotation"
    count           INTEGER
);

-- ============================================
-- EXCEPTION HANDLERS
-- ============================================
CREATE TABLE exception_handlers (
    id              INTEGER PRIMARY KEY,
    method_id       INTEGER REFERENCES methods(id),
    try_start       INTEGER,              -- instruction offset
    try_end         INTEGER,
    handler_offset  INTEGER,
    catch_type      TEXT,                 -- "Ljava/io/IOException;" or null for catch-all
    handler_index   INTEGER               -- order of handler
);

-- ============================================
-- ANNOTATIONS
-- ============================================
CREATE TABLE annotations (
    id              INTEGER PRIMARY KEY,
    target_type     TEXT,                 -- "class", "method", "field", "param"
    target_id       INTEGER,
    annotation_type TEXT,                 -- e.g., "Ljava/lang/Override;"
    visibility      TEXT,                 -- "build", "runtime", "system"
    values          TEXT                  -- JSON of annotation values
);
```

### 1.2 Normalized Hash Computation

```java
/**
 * Compute normalized hash for obfuscation-resistant matching.
 * Normalizes: register numbers, label offsets, local variable names
 * Preserves: opcodes, types, constants, API calls
 */
public String computeNormalizedHash(Method method) {
    StringBuilder sb = new StringBuilder();
    Map<Integer, Integer> registerMap = new HashMap<>();
    int regCounter = 0;

    for (Instruction insn : method.getInstructions()) {
        // 1. Opcode (always keep)
        sb.append(insn.getOpcode().name()).append(";");

        // 2. Normalize registers to sequential numbers
        for (int reg : insn.getRegisters()) {
            if (!registerMap.containsKey(reg)) {
                registerMap.put(reg, regCounter++);
            }
            sb.append("R").append(registerMap.get(reg)).append(",");
        }

        // 3. Keep type information
        if (insn.hasType()) {
            sb.append("T:").append(insn.getType()).append(";");
        }

        // 4. Handle method calls
        if (insn.isInvoke()) {
            MethodReference ref = insn.getMethodReference();
            // Keep full signature for external APIs
            if (isExternalApi(ref)) {
                sb.append("API:").append(ref.getFullSignature()).append(";");
            } else {
                // For internal methods, keep only signature shape
                sb.append("CALL:")
                  .append(ref.getReturnType()).append("(")
                  .append(String.join(",", ref.getParamTypes()))
                  .append(");");
            }
        }

        // 5. Keep constants
        if (insn.hasConstant()) {
            Object c = insn.getConstant();
            if (c instanceof String) {
                sb.append("STR:").append(hashString((String)c)).append(";");
            } else if (c instanceof Number) {
                sb.append("NUM:").append(c).append(";");
            }
        }

        // 6. Keep field types (not names for internal fields)
        if (insn.isFieldAccess()) {
            FieldReference ref = insn.getFieldReference();
            if (isExternalApi(ref)) {
                sb.append("FAPI:").append(ref.getFullSignature()).append(";");
            } else {
                sb.append("FIELD:").append(ref.getType()).append(";");
            }
        }
    }

    return sha256(sb.toString());
}
```

### 1.3 Structure Hash (CFG-based)

```java
/**
 * Hash based on control flow graph structure only.
 * Useful for matching when code has minor modifications.
 */
public String computeStructureHash(Method method) {
    // Build CFG
    List<BasicBlock> blocks = buildCFG(method);

    StringBuilder sb = new StringBuilder();
    for (BasicBlock bb : blocks) {
        // Block type: entry, exit, normal, loop_header, switch
        sb.append(bb.getType()).append(":");

        // Instruction count in block
        sb.append(bb.getInstructionCount()).append(":");

        // Successor count and types
        sb.append(bb.getSuccessors().size()).append(":");
        for (Edge edge : bb.getOutEdges()) {
            sb.append(edge.getType()).append(","); // fall-through, branch, exception
        }
        sb.append(";");
    }

    return sha256(sb.toString());
}
```

---

## 2. Native Code Schema

### 2.1 Core Tables

```sql
-- ============================================
-- BINARY METADATA
-- ============================================
CREATE TABLE binaries (
    id              INTEGER PRIMARY KEY,
    file_path       TEXT,
    file_name       TEXT,

    -- Identity
    sha256          TEXT UNIQUE,
    file_size       INTEGER,

    -- ELF info
    architecture    TEXT,                 -- "arm64", "arm", "x86", "x86_64"
    endianness      TEXT,                 -- "little", "big"
    elf_type        TEXT,                 -- "executable", "shared_object"

    -- Sections summary
    text_size       INTEGER,
    data_size       INTEGER,
    rodata_size     INTEGER,

    -- Symbols
    has_symbols     BOOLEAN,
    has_dwarf       BOOLEAN,
    symbol_count    INTEGER,

    -- APK relation (for .so files from APK)
    apk_id          INTEGER REFERENCES apks(id),
    lib_name        TEXT,                 -- "libnative.so"
    abi             TEXT,                 -- "arm64-v8a", "armeabi-v7a"

    analyzed_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- FUNCTIONS (Primary matching unit)
-- ============================================
CREATE TABLE functions (
    id              INTEGER PRIMARY KEY,
    binary_id       INTEGER REFERENCES binaries(id),

    -- Identity
    address         INTEGER,              -- start address
    name            TEXT,                 -- symbol name or auto-generated
    demangled_name  TEXT,                 -- C++ demangled

    -- Size
    size            INTEGER,
    end_address     INTEGER,

    -- ================================================
    -- STRUCTURE FEATURES (critical for matching)
    -- ================================================
    instruction_count   INTEGER,
    basic_block_count   INTEGER,
    edge_count          INTEGER,

    -- Control flow metrics
    cyclomatic_complexity INTEGER,
    loop_count          INTEGER,

    -- ================================================
    -- CALL GRAPH FEATURES
    -- ================================================
    callee_count        INTEGER,          -- functions this calls
    caller_count        INTEGER,          -- functions calling this

    -- ================================================
    -- HASHES (multiple for different matching strategies)
    -- ================================================

    -- Exact match
    bytes_hash          TEXT,             -- SHA256 of raw bytes

    -- Instruction-level (ignores operand values)
    mnemonic_hash       TEXT,             -- hash of mnemonic sequence

    -- Structural
    cfg_hash            TEXT,             -- hash of CFG topology
    prime_product       TEXT,             -- BinDiff-style prime product

    -- Fuzzy
    minhash_signature   TEXT,             -- MinHash for fuzzy matching
    simhash             TEXT,             -- SimHash for similarity

    -- ================================================
    -- INSTRUCTION HISTOGRAM
    -- ================================================
    instruction_histogram TEXT,           -- JSON: {"mov": 15, "bl": 8, ...}
    instruction_categories TEXT,          -- JSON: {"arithmetic": 20, "memory": 15, ...}

    -- ================================================
    -- CONSTANTS & STRINGS
    -- ================================================
    string_refs         TEXT,             -- JSON array of referenced strings
    string_ref_count    INTEGER,
    numeric_constants   TEXT,             -- JSON array of immediate values

    -- ================================================
    -- API CALLS (imports/PLT)
    -- ================================================
    import_calls        TEXT,             -- JSON: ["malloc", "free", "memcpy", ...]
    import_call_hash    TEXT,

    -- ================================================
    -- STACK FRAME
    -- ================================================
    stack_frame_size    INTEGER,
    local_var_count     INTEGER,
    param_count         INTEGER,          -- if recoverable

    -- ================================================
    -- MATCHING METADATA
    -- ================================================
    is_thunk            BOOLEAN,          -- simple jump wrapper
    is_library          BOOLEAN,          -- matches known library function
    library_name        TEXT,             -- e.g., "libc:strlen"

    UNIQUE(binary_id, address)
);

CREATE INDEX idx_functions_binary ON functions(binary_id);
CREATE INDEX idx_functions_name ON functions(binary_id, name);
CREATE INDEX idx_functions_cfg ON functions(cfg_hash);
CREATE INDEX idx_functions_prime ON functions(prime_product);
CREATE INDEX idx_functions_minhash ON functions(minhash_signature);

-- ============================================
-- BASIC BLOCKS
-- ============================================
CREATE TABLE basic_blocks (
    id              INTEGER PRIMARY KEY,
    function_id     INTEGER REFERENCES functions(id),

    address         INTEGER,
    size            INTEGER,
    instruction_count INTEGER,

    -- Block characteristics
    block_type      TEXT,                 -- "entry", "exit", "normal", "loop_header"

    -- Hashes for block-level matching
    bytes_hash      TEXT,
    mnemonic_hash   TEXT,

    -- Prime for prime product algorithm
    prime           INTEGER,              -- unique prime based on block characteristics

    UNIQUE(function_id, address)
);

CREATE INDEX idx_blocks_function ON basic_blocks(function_id);

-- ============================================
-- CFG EDGES
-- ============================================
CREATE TABLE cfg_edges (
    id              INTEGER PRIMARY KEY,
    function_id     INTEGER REFERENCES functions(id),
    source_block_id INTEGER REFERENCES basic_blocks(id),
    target_block_id INTEGER REFERENCES basic_blocks(id),

    edge_type       TEXT,                 -- "fall_through", "jump", "branch_true", "branch_false", "switch", "call", "exception"

    UNIQUE(source_block_id, target_block_id, edge_type)
);

-- ============================================
-- CALL GRAPH
-- ============================================
CREATE TABLE native_callgraph (
    id              INTEGER PRIMARY KEY,
    caller_id       INTEGER REFERENCES functions(id),
    callee_id       INTEGER REFERENCES functions(id),

    -- For external/imported calls
    callee_external TEXT,                 -- "malloc@plt" if not in binary

    call_site_addr  INTEGER,
    call_type       TEXT,                 -- "direct", "indirect", "tail"

    UNIQUE(caller_id, call_site_addr)
);

CREATE INDEX idx_native_cg_caller ON native_callgraph(caller_id);
CREATE INDEX idx_native_cg_callee ON native_callgraph(callee_id);

-- ============================================
-- DATA REFERENCES
-- ============================================
CREATE TABLE data_references (
    id              INTEGER PRIMARY KEY,
    function_id     INTEGER REFERENCES functions(id),

    address         INTEGER,              -- address of data being referenced
    ref_type        TEXT,                 -- "string", "jump_table", "vtable", "global_var"
    data_value      TEXT,                 -- actual string or description
    access_type     TEXT,                 -- "read", "write", "lea"

    instruction_addr INTEGER              -- where the reference is made from
);

-- ============================================
-- STRINGS
-- ============================================
CREATE TABLE strings (
    id              INTEGER PRIMARY KEY,
    binary_id       INTEGER REFERENCES binaries(id),

    address         INTEGER,
    value           TEXT,
    length          INTEGER,
    encoding        TEXT,                 -- "ascii", "utf8", "utf16"
    section         TEXT,                 -- ".rodata", ".data"

    UNIQUE(binary_id, address)
);

CREATE INDEX idx_strings_value ON strings(binary_id, value);

-- ============================================
-- IMPORTS/EXPORTS
-- ============================================
CREATE TABLE imports (
    id              INTEGER PRIMARY KEY,
    binary_id       INTEGER REFERENCES binaries(id),

    name            TEXT,
    library         TEXT,                 -- source library
    address         INTEGER,              -- PLT/GOT address

    UNIQUE(binary_id, name, library)
);

CREATE TABLE exports (
    id              INTEGER PRIMARY KEY,
    binary_id       INTEGER REFERENCES binaries(id),

    name            TEXT,
    address         INTEGER,
    size            INTEGER,
    type            TEXT,                 -- "function", "object"

    UNIQUE(binary_id, name)
);
```

### 2.2 Hash Computation Methods

```python
# ============================================
# MNEMONIC HASH (ignores operand values)
# ============================================
def compute_mnemonic_hash(function):
    """Hash of instruction mnemonics only, ignoring operands."""
    mnemonics = []
    for insn in function.instructions:
        mnemonics.append(insn.mnemonic)
    return sha256(';'.join(mnemonics))


# ============================================
# CFG HASH (topology only)
# ============================================
def compute_cfg_hash(function):
    """Hash based on CFG structure."""
    blocks = function.basic_blocks

    # Normalize block order by DFS from entry
    ordered_blocks = dfs_order(blocks, function.entry_block)

    parts = []
    for i, block in enumerate(ordered_blocks):
        # Block: (instruction_count, successor_indices)
        successors = sorted([ordered_blocks.index(s) for s in block.successors])
        parts.append(f"{block.instruction_count}:{','.join(map(str, successors))}")

    return sha256(';'.join(parts))


# ============================================
# PRIME PRODUCT (BinDiff algorithm)
# ============================================
PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, ...]  # enough primes

def compute_prime_product(function):
    """
    BinDiff-style prime product.
    Each basic block gets a prime based on:
    - number of instructions
    - in-degree
    - out-degree
    """
    product = 1
    for block in function.basic_blocks:
        # Compute block characteristic tuple
        char = (
            block.instruction_count,
            len(block.predecessors),
            len(block.successors)
        )
        # Map to prime (use hash to index into prime table)
        prime_idx = hash(char) % len(PRIMES)
        product *= PRIMES[prime_idx]

    return str(product)


# ============================================
# MINHASH SIGNATURE (fuzzy matching)
# ============================================
def compute_minhash(function, num_hashes=128):
    """
    MinHash signature for fuzzy similarity.
    Uses instruction n-grams as features.
    """
    # Extract features (instruction trigrams)
    features = set()
    mnemonics = [insn.mnemonic for insn in function.instructions]
    for i in range(len(mnemonics) - 2):
        trigram = f"{mnemonics[i]}_{mnemonics[i+1]}_{mnemonics[i+2]}"
        features.add(trigram)

    # Compute MinHash
    signature = []
    for seed in range(num_hashes):
        min_hash = float('inf')
        for feature in features:
            h = murmurhash(feature, seed)
            min_hash = min(min_hash, h)
        signature.append(min_hash)

    return ','.join(map(str, signature))


def minhash_similarity(sig1, sig2):
    """Jaccard similarity estimate from MinHash signatures."""
    s1 = list(map(int, sig1.split(',')))
    s2 = list(map(int, sig2.split(',')))
    matches = sum(1 for a, b in zip(s1, s2) if a == b)
    return matches / len(s1)
```

---

## 3. Diffing Algorithms

### 3.1 Multi-Pass Matching Strategy

Most tools use a **multi-pass approach**, matching easy cases first, then using those matches to inform harder cases:

```
PASS 1: Exact Matches (high confidence)
├── Same name (if not obfuscated)
├── Same bytes/bytecode hash
└── Same normalized hash

PASS 2: Signature-Based (medium-high confidence)
├── Same API call hash + same param types
├── Same structure hash + same size (±10%)
└── Same prime product + same callee count

PASS 3: Call Graph Propagation (medium confidence)
├── If caller matched, try to match callees by position
├── If callee matched, try to match callers by call pattern
└── Unique call relationships (only one caller/callee candidate)

PASS 4: Fuzzy Matching (lower confidence)
├── MinHash similarity > 0.8
├── Instruction histogram similarity > 0.9
└── String/constant overlap > 0.7

PASS 5: Structural Matching (lowest confidence)
├── Same position in class hierarchy
├── Same field access patterns
└── Machine learning classifier
```

### 3.2 BinDiff Algorithm (Simplified)

```python
def bindiff_match(funcs1, funcs2):
    """
    Simplified BinDiff matching algorithm.
    """
    matches = {}
    unmatched1 = set(funcs1)
    unmatched2 = set(funcs2)

    # Pass 1: Hash-based exact matching
    for hash_type in ['bytes_hash', 'cfg_hash', 'prime_product']:
        hash_to_func1 = defaultdict(list)
        hash_to_func2 = defaultdict(list)

        for f in unmatched1:
            hash_to_func1[getattr(f, hash_type)].append(f)
        for f in unmatched2:
            hash_to_func2[getattr(f, hash_type)].append(f)

        for h, fs1 in hash_to_func1.items():
            fs2 = hash_to_func2.get(h, [])
            if len(fs1) == 1 and len(fs2) == 1:
                # Unique match
                matches[fs1[0]] = fs2[0]
                unmatched1.remove(fs1[0])
                unmatched2.remove(fs2[0])

    # Pass 2: Call graph propagation
    changed = True
    while changed:
        changed = False
        for f1 in list(unmatched1):
            candidates = []

            for f2 in unmatched2:
                score = 0

                # Check if matched callees align
                matched_callees = 0
                for callee1 in f1.callees:
                    if callee1 in matches:
                        if matches[callee1] in f2.callees:
                            matched_callees += 1

                # Check if matched callers align
                matched_callers = 0
                for caller1 in f1.callers:
                    if caller1 in matches:
                        if matches[caller1] in f2.callers:
                            matched_callers += 1

                score = matched_callees + matched_callers
                if score > 0:
                    candidates.append((f2, score))

            if len(candidates) == 1 or (candidates and candidates[0][1] > candidates[1][1] * 2):
                best = max(candidates, key=lambda x: x[1])
                matches[f1] = best[0]
                unmatched1.remove(f1)
                unmatched2.remove(best[0])
                changed = True

    # Pass 3: Fuzzy matching for remaining
    for f1 in list(unmatched1):
        best_sim = 0
        best_match = None

        for f2 in unmatched2:
            sim = minhash_similarity(f1.minhash_signature, f2.minhash_signature)
            if sim > best_sim and sim > 0.7:
                best_sim = sim
                best_match = f2

        if best_match:
            matches[f1] = best_match
            unmatched1.remove(f1)
            unmatched2.remove(best_match)

    return matches, unmatched1, unmatched2
```

### 3.3 ApkDiff Algorithm (Java-specific)

```python
def apkdiff_match(classes1, classes2):
    """
    ApkDiff matching for Android apps.
    Handles obfuscation by using structural features.
    """
    matches = {}

    # Build feature vectors for each class
    def class_features(cls):
        return {
            'superclass': cls.superclass,
            'interface_count': len(cls.interfaces),
            'method_signatures': set(m.signature_shape for m in cls.methods),
            'field_types': set(f.type for f in cls.fields),
            'api_calls': set(flatten(m.api_calls for m in cls.methods)),
            'method_count': len(cls.methods),
            'field_count': len(cls.fields),
        }

    # Pass 1: Match by unique superclass + interface combination
    for c1 in classes1:
        if is_obfuscated(c1.name):
            continue
        for c2 in classes2:
            if c1.name == c2.name:
                matches[c1] = c2
                break

    # Pass 2: Match by structural features
    unmatched1 = [c for c in classes1 if c not in matches]
    unmatched2 = [c for c in classes2 if c not in matches.values()]

    for c1 in unmatched1:
        f1 = class_features(c1)
        candidates = []

        for c2 in unmatched2:
            f2 = class_features(c2)

            # Must have same superclass
            if f1['superclass'] != f2['superclass']:
                continue

            # Score based on feature overlap
            score = 0
            score += len(f1['method_signatures'] & f2['method_signatures'])
            score += len(f1['field_types'] & f2['field_types'])
            score += len(f1['api_calls'] & f2['api_calls'])

            if abs(f1['method_count'] - f2['method_count']) <= 2:
                score += 5

            candidates.append((c2, score))

        if candidates:
            best = max(candidates, key=lambda x: x[1])
            if best[1] > 5:  # threshold
                matches[c1] = best[0]
                unmatched2.remove(best[0])

    return matches
```

### 3.4 Similarity Metrics

```python
# ============================================
# JACCARD SIMILARITY (for sets)
# ============================================
def jaccard(set1, set2):
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union > 0 else 0


# ============================================
# COSINE SIMILARITY (for histograms)
# ============================================
def cosine_similarity(hist1, hist2):
    """Compare instruction histograms."""
    all_keys = set(hist1.keys()) | set(hist2.keys())

    dot = sum(hist1.get(k, 0) * hist2.get(k, 0) for k in all_keys)
    mag1 = sqrt(sum(v**2 for v in hist1.values()))
    mag2 = sqrt(sum(v**2 for v in hist2.values()))

    return dot / (mag1 * mag2) if mag1 * mag2 > 0 else 0


# ============================================
# EDIT DISTANCE RATIO (for sequences)
# ============================================
def edit_distance_ratio(seq1, seq2):
    """Normalized edit distance for instruction sequences."""
    dist = levenshtein_distance(seq1, seq2)
    max_len = max(len(seq1), len(seq2))
    return 1 - (dist / max_len) if max_len > 0 else 1


# ============================================
# COMPOSITE SIMILARITY SCORE
# ============================================
def compute_similarity(func1, func2):
    """Weighted composite similarity score."""
    scores = {
        'api_calls': jaccard(set(func1.api_calls), set(func2.api_calls)),
        'strings': jaccard(set(func1.string_literals), set(func2.string_literals)),
        'histogram': cosine_similarity(func1.opcode_histogram, func2.opcode_histogram),
        'structure': 1.0 if func1.structure_hash == func2.structure_hash else 0.0,
        'size': 1.0 - abs(func1.instruction_count - func2.instruction_count) / max(func1.instruction_count, func2.instruction_count),
    }

    weights = {
        'api_calls': 0.35,
        'strings': 0.15,
        'histogram': 0.20,
        'structure': 0.20,
        'size': 0.10,
    }

    return sum(scores[k] * weights[k] for k in scores)
```

---

## 4. Notable Projects

### 4.1 Java/DEX Diffing

| Project | Language | Key Features | Link |
|---------|----------|--------------|------|
| **apkdiff** | Java | Class structure matching, obfuscation-resistant, uses Soot | [csl-ugent/apkdiff](https://github.com/csl-ugent/apkdiff) |
| **Quarkslab Diff Engine** | Python | Entropy-based obfuscation detection, commercial | [Blog](https://blog.quarkslab.com/android-application-diffing-engine-overview.html) |
| **JADX** | Java | Decompiler with API for custom analysis | [skylot/jadx](https://github.com/skylot/jadx) |
| **Diffuse** | Kotlin | APK/AAR structure diff (not code-level) | [JakeWharton/diffuse](https://github.com/JakeWharton/diffuse) |
| **Androguard** | Python | Full analysis framework, call graphs, xrefs | [androguard/androguard](https://github.com/androguard/androguard) |
| **Soot** | Java | Static analysis framework, CFG, call graphs | [soot-oss/soot](https://github.com/soot-oss/soot) |
| **dex2jar** | Java | DEX manipulation library | [pxb1988/dex2jar](https://github.com/pxb1988/dex2jar) |

### 4.2 Native Binary Diffing

| Project | Language | Key Features | Link |
|---------|----------|--------------|------|
| **BinDiff** | C++ | Industry standard, IDA/Ghidra plugin, prime product | [google/bindiff](https://github.com/google/bindiff) |
| **Diaphora** | Python | IDA plugin, ML-based matching, SQLite export | [joxeankoret/diaphora](https://github.com/joxeankoret/diaphora) |
| **Ghidriff** | Python | Ghidra-based, HTML reports, version tracking | [clearbluejar/ghidriff](https://github.com/clearbluejar/ghidriff) |
| **YaDiff** | C++ | IDA plugin, multiple algorithms | [AaltoSec/yadiff](https://github.com/AaltoSec/yadiff) |
| **BinExport** | C++ | Export disassembly to protobuf for BinDiff | [google/binexport](https://github.com/google/binexport) |
| **Radiff2** | C | Part of Radare2, basic diffing | [radareorg/radare2](https://github.com/radareorg/radare2) |
| **Kam1n0** | Java | ML-based, clone detection, assembly embedding | [McGill-DMaS/Kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community) |

### 4.3 Key Papers

1. **"Graph-based comparison of Executable Objects"** (BinDiff paper)
   - Describes prime product algorithm and call graph propagation

2. **"ApkDiff: Matching Android App Versions Based on Class Structure"** (CheckMATE 2022)
   - [PDF](https://bartcoppens.be/research/deghein2022_apkdiff_checkmate.pdf)
   - Handles obfuscation in Java code

3. **"Diaphora: A Program Diffing Plugin for IDA Pro"**
   - Heuristic-based matching, SQLite schema design

4. **"Asm2Vec: Boosting Static Representation Robustness for Binary Clone Search"**
   - ML-based approach to function similarity

---

## 5. Implementation Notes

### 5.1 Recommended Stack

**For Java/DEX analysis:**
```
JADX (decompilation) + Soot (analysis) + SQLite (storage)
```

**For Native analysis:**
```
Ghidra (headless) + Python + SQLite
  or
Rizin/Radare2 + r2pipe + SQLite
```

### 5.2 Performance Considerations

```sql
-- Essential indexes for matching queries
CREATE INDEX idx_methods_api_hash ON methods(api_call_hash);
CREATE INDEX idx_methods_normalized ON methods(normalized_hash);
CREATE INDEX idx_methods_signature ON methods(return_type, param_count);
CREATE INDEX idx_functions_cfg ON functions(cfg_hash);
CREATE INDEX idx_functions_size ON functions(instruction_count);

-- For fuzzy matching, consider:
-- 1. Pre-filter by size (±20%)
-- 2. Pre-filter by callee_count (±3)
-- 3. Then compute expensive similarity
```

### 5.3 Minimum Viable Schema

If starting simple, these fields give 80% of matching power:

**Java:**
```sql
CREATE TABLE methods (
    id INTEGER PRIMARY KEY,
    apk_version TEXT,
    class_name TEXT,
    method_name TEXT,
    return_type TEXT,
    param_types TEXT,
    instruction_count INTEGER,
    api_calls TEXT,           -- MOST IMPORTANT
    normalized_hash TEXT,
    callee_count INTEGER
);
```

**Native:**
```sql
CREATE TABLE functions (
    id INTEGER PRIMARY KEY,
    binary_version TEXT,
    name TEXT,
    address INTEGER,
    size INTEGER,
    basic_block_count INTEGER,
    cfg_hash TEXT,            -- MOST IMPORTANT
    import_calls TEXT,
    mnemonic_hash TEXT,
    callee_count INTEGER
);
```

### 5.4 Export/Import Formats

Consider supporting standard formats for interoperability:

- **BinExport2** (.BinExport) - Protobuf format used by BinDiff
- **SARIF** - Static analysis results format
- **GraphML** - For call graphs
- **JSON** - For custom tooling

---

## Appendix: SQL Queries for Diffing

### Find Added Methods
```sql
SELECT m2.* FROM methods m2
JOIN classes c2 ON m2.class_id = c2.id
JOIN apks a2 ON c2.apk_id = a2.id
WHERE a2.version = 'v2'
AND NOT EXISTS (
    SELECT 1 FROM methods m1
    JOIN classes c1 ON m1.class_id = c1.id
    JOIN apks a1 ON c1.apk_id = a1.id
    WHERE a1.version = 'v1'
    AND m1.normalized_hash = m2.normalized_hash
);
```

### Find Modified Methods
```sql
SELECT m1.id as v1_id, m2.id as v2_id,
       m1.name, m1.bytecode_hash, m2.bytecode_hash
FROM methods m1
JOIN classes c1 ON m1.class_id = c1.id
JOIN apks a1 ON c1.apk_id = a1.id
JOIN methods m2 ON m1.api_call_hash = m2.api_call_hash
                AND m1.param_types = m2.param_types
JOIN classes c2 ON m2.class_id = c2.id
JOIN apks a2 ON c2.apk_id = a2.id
WHERE a1.version = 'v1' AND a2.version = 'v2'
AND m1.bytecode_hash != m2.bytecode_hash;
```

### Find Best Match Candidates
```sql
SELECT m1.id, m2.id,
    CASE WHEN m1.normalized_hash = m2.normalized_hash THEN 50 ELSE 0 END +
    CASE WHEN m1.api_call_hash = m2.api_call_hash THEN 30 ELSE 0 END +
    CASE WHEN m1.param_types = m2.param_types THEN 10 ELSE 0 END +
    CASE WHEN ABS(m1.instruction_count - m2.instruction_count) < 5 THEN 10 ELSE 0 END
    AS score
FROM methods m1, methods m2
JOIN classes c1 ON m1.class_id = c1.id
JOIN apks a1 ON c1.apk_id = a1.id
JOIN classes c2 ON m2.class_id = c2.id
JOIN apks a2 ON c2.apk_id = a2.id
WHERE a1.version = 'v1' AND a2.version = 'v2'
AND m1.return_type = m2.return_type  -- pre-filter
ORDER BY score DESC;
```

---

## 6. Advanced Techniques from BinDiff & Diaphora

This section documents specific implementation details extracted from analyzing the [BinDiff](https://github.com/google/bindiff) and [Diaphora](https://github.com/joxeankoret/diaphora) source code.

### 6.1 Extended Database Schema (Diaphora-inspired)

Diaphora stores **50+ attributes per function**. Here are the additional fields worth considering:

```sql
-- ============================================
-- EXTENDED FUNCTIONS TABLE (Diaphora-style)
-- ============================================
ALTER TABLE functions ADD COLUMN IF NOT EXISTS (
    -- Topological metrics
    indegree            INTEGER,          -- incoming call references
    outdegree           INTEGER,          -- outgoing code/data references
    strongly_connected  INTEGER,          -- strongly connected component count
    strongly_connected_spp TEXT,          -- primorial of SCC sizes

    -- MD Index (BinDiff's key structural metric)
    md_index            REAL,             -- graph topology metric (see 6.3)
    md_index_top_down   REAL,             -- BFS from entry points
    md_index_bottom_up  REAL,             -- BFS from exit nodes

    -- Advanced hashes
    kgh_hash            TEXT,             -- Koret-Karamitas graph hash (see 6.5)
    bytes_sum           INTEGER,          -- sum of all raw bytes

    -- Fuzzy hashes (Diaphora)
    pseudo_hash1        TEXT,             -- fuzzy hash variant 1
    pseudo_hash2        TEXT,             -- fuzzy hash variant 2
    pseudo_hash3        TEXT,             -- fuzzy hash variant 3

    -- Pseudocode/Decompiler (when available)
    pseudocode          TEXT,             -- decompiled C code
    pseudocode_lines    INTEGER,
    pseudocode_hash     TEXT,             -- exact hash
    pseudocode_primes   TEXT,             -- primorial fingerprint of tokens
    clean_pseudocode    TEXT,             -- normalized (generic names)

    -- Microcode IR (Hex-Rays specific)
    microcode           TEXT,
    microcode_spp       TEXT,             -- primorial of microcode mnemonics

    -- Assembly variants
    assembly            TEXT,             -- full assembly listing
    clean_assembly      TEXT,             -- normalized assembly
    assembly_addrs      TEXT,             -- JSON array of instruction addresses

    -- Tarjan analysis
    tarjan_topological  TEXT,             -- JSON: topological sort of basic blocks

    -- Switches/jump tables
    switches            TEXT,             -- JSON: switch table information

    -- Constants
    constants           TEXT,             -- JSON array of constants
    constants_count     INTEGER
);

-- ============================================
-- INSTRUCTIONS TABLE (detailed)
-- ============================================
CREATE TABLE instructions (
    id                  INTEGER PRIMARY KEY,
    function_id         INTEGER REFERENCES functions(id),
    block_id            INTEGER REFERENCES basic_blocks(id),

    address             INTEGER,
    mnemonic            TEXT,
    disassembly         TEXT,
    raw_bytes           BLOB,

    -- Operand details
    operand_count       INTEGER,
    operands            TEXT,             -- JSON array of operand strings
    operand_types       TEXT,             -- JSON: ["register", "immediate", "memory"]

    -- References
    call_target         INTEGER,          -- target address if CALL
    jump_target         INTEGER,          -- target address if JMP/branch
    data_refs           TEXT,             -- JSON array of data references

    -- Comments (for porting)
    comment             TEXT,
    repeatable_comment  TEXT,

    -- Instruction type classification
    insn_type           TEXT,             -- "call", "jump", "arithmetic", "memory", etc.

    -- For decompiler correlation
    pseudocode_line     INTEGER,

    UNIQUE(function_id, address)
);

CREATE INDEX idx_instructions_block ON instructions(block_id);
CREATE INDEX idx_instructions_mnemonic ON instructions(mnemonic);

-- ============================================
-- EXTENDED BASIC BLOCKS (BinDiff-style)
-- ============================================
ALTER TABLE basic_blocks ADD COLUMN IF NOT EXISTS (
    -- BinDiff vertex properties
    prime_product       INTEGER,          -- product of instruction mnemonic primes
    string_hash         TEXT,             -- hash of string references in block

    -- Topological levels (for MD Index)
    bfs_top_down        INTEGER,          -- level from entry (BFS)
    bfs_bottom_up       INTEGER,          -- level from exits (BFS)

    -- Loop detection
    is_loop_header      BOOLEAN,
    is_in_loop          BOOLEAN,

    -- For matching
    is_entry            BOOLEAN,
    is_exit             BOOLEAN
);

-- ============================================
-- EXTENDED CFG EDGES (BinDiff-style)
-- ============================================
ALTER TABLE cfg_edges ADD COLUMN IF NOT EXISTS (
    -- MD Index components per edge
    md_index_top_down   REAL,
    md_index_bottom_up  REAL,

    -- Lengauer-Tarjan loop detection
    is_back_edge        BOOLEAN,          -- marks loop back-edges

    -- Edge flags
    flags               INTEGER           -- bitfield for edge properties
);
```

### 6.2 BinExport2 Proto Format

BinDiff uses **BinExport2** protobuf format for data exchange. Key structures:

```protobuf
// Simplified from google/binexport/binexport2.proto
message BinExport2 {
  message Meta {
    string executable_name = 1;
    string executable_id = 2;      // SHA256 hash
    string architecture_name = 3;  // "x86-32", "ARM", "MIPS", etc.
    int64 timestamp = 4;
  }

  message Instruction {
    int64 address = 1;             // only when non-sequential
    bytes raw_bytes = 2;
    int32 mnemonic_index = 3;      // index into mnemonic table (deduped)
    repeated int32 operand_index = 4;
    repeated int64 call_target = 5;
  }

  message BasicBlock {
    message IndexRange {
      int32 begin_index = 1;       // instruction index
      int32 end_index = 2;         // exclusive
    }
    repeated IndexRange instruction_index = 1;
  }

  message FlowGraph {
    message Edge {
      int32 source_basic_block_index = 1;
      int32 target_basic_block_index = 2;
      enum Type {
        CONDITION_TRUE = 0;
        CONDITION_FALSE = 1;
        UNCONDITIONAL = 2;
        SWITCH = 3;
      }
      Type type = 3;
      bool is_back_edge = 4;       // Lengauer-Tarjan
    }
    int64 entry_basic_block_index = 1;
    repeated int32 basic_block_index = 2;
    repeated Edge edge = 3;
  }

  message CallGraph {
    message Vertex {
      int64 address = 1;
      enum Type {
        NORMAL = 0;
        LIBRARY = 1;
        IMPORTED = 2;
        THUNK = 3;
      }
      Type type = 2;
      string mangled_name = 3;
      string demangled_name = 4;
    }
    message Edge {
      int32 source_vertex_index = 1;
      int32 target_vertex_index = 2;
    }
    repeated Vertex vertex = 1;
    repeated Edge edge = 2;
  }

  Meta meta_information = 1;
  repeated string mnemonic = 4;         // deduplicated mnemonic strings
  repeated Instruction instruction = 6;
  repeated BasicBlock basic_block = 7;
  repeated FlowGraph flow_graph = 8;
  CallGraph call_graph = 9;
}
```

### 6.3 MD Index Calculation (BinDiff's Key Metric)

The **MD Index** is BinDiff's primary structural matching metric:

```python
from decimal import Decimal
import math

# Weights for MD Index calculation (from BinDiff source)
WEIGHTS = {
    'in_degree_src': 2.0,
    'out_degree_src': 3.0,
    'in_degree_tgt': 5.0,
    'out_degree_tgt': 7.0,
    'level_src': 11.0,      # topological level (0 for vertex-only)
    'level_tgt': 13.0,
}

def compute_md_index_edge(edge, include_topology=True):
    """
    Compute MD Index contribution for a single CFG edge.

    MD Index = 1 / sqrt(w0*in_src + w1*out_src + w2*in_tgt + w3*out_tgt + w4*level_src + w5*level_tgt)
    """
    src, tgt = edge.source_block, edge.target_block

    value = (
        math.sqrt(WEIGHTS['in_degree_src']) * src.in_degree +
        math.sqrt(WEIGHTS['out_degree_src']) * src.out_degree +
        math.sqrt(WEIGHTS['in_degree_tgt']) * tgt.in_degree +
        math.sqrt(WEIGHTS['out_degree_tgt']) * tgt.out_degree
    )

    if include_topology:
        value += math.sqrt(WEIGHTS['level_src']) * src.bfs_level
        value += math.sqrt(WEIGHTS['level_tgt']) * tgt.bfs_level

    return Decimal(1) / Decimal(value) if value > 0 else Decimal(0)


def compute_function_md_index(function):
    """
    Compute full MD Index for a function.
    Sum of MD Index for all CFG edges, calculated both top-down and bottom-up.
    """
    # First compute BFS levels
    compute_bfs_levels(function)

    md_top_down = Decimal(0)
    md_bottom_up = Decimal(0)

    for edge in function.cfg_edges:
        # Top-down: use levels from entry points
        edge.source_block.bfs_level = edge.source_block.bfs_top_down
        edge.target_block.bfs_level = edge.target_block.bfs_top_down
        md_top_down += compute_md_index_edge(edge, include_topology=True)

        # Bottom-up: use levels from exit nodes
        edge.source_block.bfs_level = edge.source_block.bfs_bottom_up
        edge.target_block.bfs_level = edge.target_block.bfs_bottom_up
        md_bottom_up += compute_md_index_edge(edge, include_topology=True)

    return {
        'md_index': float(md_top_down + md_bottom_up),
        'md_index_top_down': float(md_top_down),
        'md_index_bottom_up': float(md_bottom_up),
    }


def compute_bfs_levels(function):
    """
    Compute topological levels using BFS.
    - Top-down: from entry points (in_degree == 0)
    - Bottom-up: from exit nodes (out_degree == 0)
    """
    from collections import deque

    blocks = function.basic_blocks

    # Top-down BFS (from entries)
    entries = [b for b in blocks if b.in_degree == 0]
    queue = deque([(b, 0) for b in entries])
    visited = set()

    while queue:
        block, level = queue.popleft()
        if block.id in visited:
            continue
        visited.add(block.id)
        block.bfs_top_down = level

        for succ in block.successors:
            if succ.id not in visited:
                queue.append((succ, level + 1))

    # Bottom-up BFS (from exits)
    exits = [b for b in blocks if b.out_degree == 0]
    queue = deque([(b, 0) for b in exits])
    visited = set()

    while queue:
        block, level = queue.popleft()
        if block.id in visited:
            continue
        visited.add(block.id)
        block.bfs_bottom_up = level

        for pred in block.predecessors:
            if pred.id not in visited:
                queue.append((pred, level + 1))
```

### 6.4 Prime Product Algorithms

Both BinDiff and Diaphora use **prime products** for structural fingerprinting:

```python
# ============================================
# SMALL PRIMES PRODUCT (SPP) - Diaphora style
# ============================================

def primesbelow(n):
    """Generate all primes below n using Sieve of Eratosthenes."""
    sieve = [True] * (n // 2)
    for i in range(3, int(n**0.5) + 1, 2):
        if sieve[i // 2]:
            sieve[i*i // 2::i] = [False] * ((n - i*i - 1) // (2*i) + 1)
    return [2] + [2*i + 1 for i in range(1, n // 2) if sieve[i]]

PRIMES = primesbelow(10000)

# Mnemonic to prime mapping (build once)
MNEMONIC_PRIMES = {}

def get_mnemonic_prime(mnemonic):
    """Get consistent prime for a mnemonic."""
    if mnemonic not in MNEMONIC_PRIMES:
        idx = len(MNEMONIC_PRIMES) % len(PRIMES)
        MNEMONIC_PRIMES[mnemonic] = PRIMES[idx]
    return MNEMONIC_PRIMES[mnemonic]


def compute_mnemonics_spp(function):
    """
    Small Primes Product of instruction mnemonics.
    Order-independent fingerprint.
    """
    product = 1
    for insn in function.instructions:
        product *= get_mnemonic_prime(insn.mnemonic)
    return product


def compute_pseudocode_primes(pseudocode):
    """
    Primorial fingerprint of pseudocode tokens.
    """
    import re
    tokens = re.findall(r'\w+', pseudocode)
    product = 1
    for token in tokens:
        idx = hash(token) % len(PRIMES)
        product *= PRIMES[idx]
    return product


# ============================================
# INSTRUCTION PRIME (BinDiff style)
# ============================================

# BinDiff assigns unique small primes to each mnemonic
# Function signature = product of all instruction primes
# This is ORDER-INDEPENDENT

def compute_prime_product_bindiff(function):
    """
    BinDiff-style prime product.
    Product of primes for each instruction mnemonic.
    """
    product = 1
    for insn in function.instructions:
        prime = get_mnemonic_prime(insn.mnemonic)
        product *= prime
    return product


def compute_block_prime(basic_block):
    """
    Prime product for a single basic block.
    Used for block-level matching.
    """
    product = 1
    for insn in basic_block.instructions:
        product *= get_mnemonic_prime(insn.mnemonic)
    return product
```

### 6.5 Koret-Karamitas Graph Hash (Diaphora)

A sophisticated structural hash that incorporates multiple graph features:

```python
# ============================================
# KORET-KARAMITAS GRAPH HASH
# ============================================

# Feature primes (from Diaphora source)
KGH_PRIMES = {
    'NODE_ENTRY': 2,
    'NODE_EXIT': 3,
    'NODE_NORMAL': 5,
    'EDGE_OUT_CONDITIONAL': 11,
    'EDGE_IN_CONDITIONAL': 7,
    'FEATURE_LOOP': 19,
    'FEATURE_CALL': 23,
    'FEATURE_DATA_REFS': 29,
    'FEATURE_CALL_REF': 31,
    'FEATURE_STRONGLY_CONNECTED': 37,
    'FEATURE_FUNC_NO_RET': 41,
    'FEATURE_FUNC_LIB': 43,
    'FEATURE_FUNC_THUNK': 47,
}


def compute_kgh_hash(function):
    """
    Koret-Karamitas Graph Hash.
    Multiplies primes based on structural features.
    """
    product = 1

    for block in function.basic_blocks:
        # Node type
        if block.is_entry:
            product *= KGH_PRIMES['NODE_ENTRY']
        elif block.is_exit:
            product *= KGH_PRIMES['NODE_EXIT']
        else:
            product *= KGH_PRIMES['NODE_NORMAL']

        # Edge features
        product *= KGH_PRIMES['EDGE_OUT_CONDITIONAL'] ** block.out_degree
        product *= KGH_PRIMES['EDGE_IN_CONDITIONAL'] ** block.in_degree

        # Instruction features
        for insn in block.instructions:
            if insn.is_call:
                product *= KGH_PRIMES['FEATURE_CALL']
            if insn.has_data_ref:
                product *= KGH_PRIMES['FEATURE_DATA_REFS']

    # Loop features
    product *= KGH_PRIMES['FEATURE_LOOP'] ** function.loop_count

    # Strongly connected components
    product *= KGH_PRIMES['FEATURE_STRONGLY_CONNECTED'] ** function.scc_count

    # Function flags
    if function.is_noreturn:
        product *= KGH_PRIMES['FEATURE_FUNC_NO_RET']
    if function.is_library:
        product *= KGH_PRIMES['FEATURE_FUNC_LIB']
    if function.is_thunk:
        product *= KGH_PRIMES['FEATURE_FUNC_THUNK']

    return product
```

### 6.6 Fuzzy Hashing (Diaphora)

Diaphora uses fuzzy hashing for pseudocode similarity:

```python
# ============================================
# KORET FUZZY HASHING
# ============================================

import base64

FUZZY_BLOCK_SIZE = 512
OUTPUT_SIZE = 32

def koret_fuzzy_hash(data):
    """
    Diaphora's fuzzy hashing algorithm.
    Divides input into blocks, computes modsum, normalizes output.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    # Filter out 0x00 and 0xFF (reduce hash errors)
    data = bytes(b for b in data if b not in (0x00, 0xFF))

    if len(data) == 0:
        return None

    # Divide into blocks
    blocks = []
    for i in range(0, len(data), FUZZY_BLOCK_SIZE):
        block = data[i:i + FUZZY_BLOCK_SIZE]
        blocks.append(block)

    # Compute modsum for each block
    modsums = []
    for block in blocks:
        modsum = sum(block) % 255
        modsums.append(modsum)

    # Normalize to fixed output size
    if len(modsums) < OUTPUT_SIZE:
        # Pad with zeros
        modsums.extend([0] * (OUTPUT_SIZE - len(modsums)))
    elif len(modsums) > OUTPUT_SIZE:
        # Sample evenly
        step = len(modsums) / OUTPUT_SIZE
        modsums = [modsums[int(i * step)] for i in range(OUTPUT_SIZE)]

    return base64.b64encode(bytes(modsums)).decode('ascii')


def compute_pseudocode_fuzzy_hashes(pseudocode):
    """
    Compute three fuzzy hash variants for pseudocode.
    """
    data = pseudocode.encode('utf-8')

    # Variant 1: blocks permuted (mix)
    blocks = [data[i:i+FUZZY_BLOCK_SIZE] for i in range(0, len(data), FUZZY_BLOCK_SIZE)]
    mixed = b''.join(blocks[i] for i in range(0, len(blocks), 2)) + \
            b''.join(blocks[i] for i in range(1, len(blocks), 2))
    hash1 = koret_fuzzy_hash(mixed)

    # Variant 2: original order
    hash2 = koret_fuzzy_hash(data)

    # Variant 3: reversed
    hash3 = koret_fuzzy_hash(data[::-1])

    return hash1, hash2, hash3
```

### 6.7 BinDiff Correlator Pipeline

BinDiff uses **31 matching algorithms** in a specific order:

```python
# ============================================
# BINDIFF MATCHING PIPELINE
# ============================================

FUNCTION_CORRELATORS = [
    # Pass 1: Exact matches (highest confidence)
    ('manual', manual_match),                    # User-defined matches
    ('hash', hash_match),                        # Exact bytes
    ('name', name_match),                        # Same symbol name

    # Pass 2: Structural exact
    ('prime_signature', prime_product_match),    # Exact instruction composition
    ('cfg_hash', cfg_hash_match),                # Exact CFG structure

    # Pass 3: Call graph propagation
    ('cg_edges_md', callgraph_md_match),         # MD index on call graph
    ('cg_edges_proximity', callgraph_prox_match),# 2-level neighborhood
    ('cg_md_index', callgraph_full_md),          # Full graph MD

    # Pass 4: Fuzzy structural
    ('string_refs', string_refs_match),          # Same string references
    ('instruction_count', insn_count_match),     # Same instruction count
    ('loop_count', loop_count_match),            # Same loop count

    # Pass 5: Address-based (last resort)
    ('address_sequence', address_seq_match),     # Sequential address matching
]

BASIC_BLOCK_CORRELATORS = [
    ('manual', bb_manual_match),
    ('hash', bb_hash_match),                     # Exact bytes (min 4 insns)
    ('prime', bb_prime_match),                   # Instruction composition
    ('string_refs', bb_string_refs_match),
    ('entry_node', bb_entry_match),              # Match entry blocks
    ('loop_entry', bb_loop_entry_match),         # Match loop headers
    ('call_refs', bb_call_refs_match),
    ('edges_md', bb_edges_md_match),             # Edge MD index
    ('edges_prime', bb_edges_prime_match),       # Edge prime products
    ('md_index', bb_md_index_match),             # Block MD index
]


def bindiff_match(funcs1, funcs2):
    """
    Multi-pass matching with confidence scores.
    """
    matches = {}           # func1 -> (func2, confidence, algorithm)
    unmatched1 = set(funcs1)
    unmatched2 = set(funcs2)

    for name, correlator in FUNCTION_CORRELATORS:
        new_matches = correlator(unmatched1, unmatched2)

        for f1, f2, confidence in new_matches:
            matches[f1] = (f2, confidence, name)
            unmatched1.discard(f1)
            unmatched2.discard(f2)

    # For each matched function pair, match basic blocks
    block_matches = {}
    for f1, (f2, _, _) in matches.items():
        bb_matches = match_basic_blocks(f1, f2, BASIC_BLOCK_CORRELATORS)
        block_matches[(f1, f2)] = bb_matches

    return matches, block_matches, unmatched1, unmatched2
```

### 6.8 Diaphora Heuristics (47+ matching rules)

Diaphora uses many specialized heuristics:

```python
# ============================================
# DIAPHORA MATCHING HEURISTICS
# ============================================

DIAPHORA_HEURISTICS = {
    # Exact matches
    'same_bytes_hash': {'weight': 1.0, 'fields': ['bytes_hash']},
    'same_pseudocode': {'weight': 0.99, 'fields': ['pseudocode_hash']},

    # Structural
    'same_kgh_hash': {'weight': 0.95, 'fields': ['kgh_hash']},
    'same_cfg_structure': {'weight': 0.90, 'fields': ['cfg_hash', 'edge_count']},
    'same_prime_product': {'weight': 0.85, 'fields': ['prime_product']},

    # Topological
    'same_md_index': {'weight': 0.80, 'fields': ['md_index']},
    'same_tarjan_topo': {'weight': 0.75, 'fields': ['tarjan_topological']},

    # Semantic
    'same_string_refs': {'weight': 0.70, 'fields': ['string_refs']},
    'same_constants': {'weight': 0.65, 'fields': ['constants']},
    'same_api_calls': {'weight': 0.60, 'fields': ['import_calls']},

    # Fuzzy
    'fuzzy_pseudocode': {'weight': 0.55, 'fields': ['pseudo_hash1', 'pseudo_hash2']},
    'similar_mnemonics': {'weight': 0.50, 'fields': ['mnemonics_spp']},

    # ML-based (experimental in Diaphora 3.x)
    'ridge_classifier': {'weight': 0.45, 'fields': ['feature_vector']},
}


def diaphora_match(funcs1, funcs2):
    """
    Diaphora-style matching with multiple heuristics.
    """
    matches = []

    for heuristic_name, config in DIAPHORA_HEURISTICS.items():
        fields = config['fields']
        weight = config['weight']

        # Build index on fields
        index2 = {}
        for f2 in funcs2:
            key = tuple(getattr(f2, field) for field in fields)
            index2.setdefault(key, []).append(f2)

        # Find matches
        for f1 in funcs1:
            key = tuple(getattr(f1, field) for field in fields)
            candidates = index2.get(key, [])

            if len(candidates) == 1:
                # Unique match
                matches.append((f1, candidates[0], weight, heuristic_name))

    return matches
```

### 6.9 Implied Matches (ghidriff/Ghidra VT)

Match unmatched functions based on call relationships:

```python
# ============================================
# IMPLIED MATCH ALGORITHM
# ============================================

def find_implied_matches(matched_pairs, unmatched1, unmatched2):
    """
    If function A calls function B, and A is matched,
    then B's match can be inferred from what A's match calls.

    Based on Ghidra's Version Tracking ImpliedMatchUtils.
    """
    implied = []

    matched_src = {f1: f2 for f1, f2 in matched_pairs}
    matched_dst = {f2: f1 for f1, f2 in matched_pairs}

    for f1 in unmatched1:
        # Find matched callers of f1
        for caller1 in f1.callers:
            if caller1 not in matched_src:
                continue

            caller2 = matched_src[caller1]

            # Use address correlation within matched function pair
            # to find corresponding call target in f2's binary
            for call_site1 in caller1.call_sites_to(f1):
                call_site2 = correlate_address(caller1, caller2, call_site1)
                if call_site2 is None:
                    continue

                target2 = get_call_target(caller2, call_site2)
                if target2 in unmatched2:
                    implied.append((f1, target2, 'implied_match'))

    return implied


def correlate_address(func1, func2, addr1):
    """
    Given matched function pair, find corresponding address in func2
    for an address in func1.

    Uses instruction-level alignment (LCS or similar).
    """
    # Build instruction alignment between matched functions
    alignment = compute_instruction_alignment(func1, func2)

    # Find corresponding instruction
    for insn1, insn2 in alignment:
        if insn1.address == addr1:
            return insn2.address

    return None
```

### 6.10 Ghidra API Reference (for extraction)

Key Ghidra APIs for extracting the required data:

```java
// ============================================
// GHIDRA DATA EXTRACTION REFERENCE
// ============================================

import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;

public class FunctionExtractor {

    public FunctionData extract(Function func, Program program) {
        FunctionData data = new FunctionData();

        // Basic info
        data.address = func.getEntryPoint().getOffset();
        data.name = func.getName();
        data.demangledName = func.getSymbol().getName(true);
        data.size = func.getBody().getNumAddresses();

        // Instruction count
        InstructionIterator insns = program.getListing()
            .getInstructions(func.getBody(), true);
        data.instructionCount = 0;
        while (insns.hasNext()) {
            data.instructionCount++;
            insns.next();
        }

        // Basic blocks and CFG
        BasicBlockModel blockModel = new BasicBlockModel(program);
        CodeBlockIterator blocks = blockModel
            .getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY);

        data.basicBlockCount = 0;
        data.edgeCount = 0;

        while (blocks.hasNext()) {
            CodeBlock block = blocks.next();
            data.basicBlockCount++;
            data.edgeCount += block.getNumDestinations(TaskMonitor.DUMMY);

            // Store block details
            BasicBlockData bb = new BasicBlockData();
            bb.startAddress = block.getMinAddress().getOffset();
            bb.endAddress = block.getMaxAddress().getOffset();
            bb.inDegree = block.getNumSources(TaskMonitor.DUMMY);
            bb.outDegree = block.getNumDestinations(TaskMonitor.DUMMY);

            data.blocks.add(bb);
        }

        // Cyclomatic complexity
        data.cyclomaticComplexity = data.edgeCount - data.basicBlockCount + 2;

        // Call graph
        data.callees = new ArrayList<>();
        for (Function callee : func.getCalledFunctions(TaskMonitor.DUMMY)) {
            data.callees.add(callee.getEntryPoint().getOffset());
        }

        data.callers = new ArrayList<>();
        for (Function caller : func.getCallingFunctions(TaskMonitor.DUMMY)) {
            data.callers.add(caller.getEntryPoint().getOffset());
        }

        // String references
        ReferenceManager refMgr = program.getReferenceManager();
        data.stringRefs = new ArrayList<>();
        for (Address addr : func.getBody().getAddresses(true)) {
            for (Reference ref : refMgr.getReferencesFrom(addr)) {
                Data refData = program.getListing().getDataAt(ref.getToAddress());
                if (refData != null && refData.hasStringValue()) {
                    data.stringRefs.add(refData.getValue().toString());
                }
            }
        }

        // Flags
        data.isThunk = func.isThunk();
        data.isLibrary = func.isLibrary();

        return data;
    }
}
```

### 6.11 Summary: Priority Data for Matching

| Priority | Data | Matching Power | Storage Cost |
|----------|------|----------------|--------------|
| **1** | `bytes_hash` (MD5/SHA256) | Exact match | Low |
| **2** | `prime_product` | Order-independent structure | Low |
| **3** | `cfg_hash` (blocks, edges) | Graph structure | Low |
| **4** | `md_index` | Topological position | Low |
| **5** | Basic blocks + edges | Detailed CFG | Medium |
| **6** | `string_refs` | Semantic similarity | Medium |
| **7** | `import_calls` | API fingerprint | Medium |
| **8** | Instructions table | Fine-grained diff | High |
| **9** | `pseudocode` | Decompiler-based | High |
| **10** | `kgh_hash` | Multi-feature structural | Low |

**Minimum viable schema** for 80% matching accuracy:
```sql
functions: address, name, size, basic_block_count, edge_count,
           bytes_hash, prime_product, cfg_hash, md_index,
           callee_count, caller_count, string_refs_hash
```

**Full schema** for maximum accuracy adds:
- Complete basic_blocks table with BFS levels
- Complete instructions table
- cfg_edges with edge types and back_edge flags
- Pseudocode and fuzzy hashes

---

## 7. Advanced Java/DEX Diffing Techniques

This section documents advanced techniques for Android APK/DEX diffing, extracted from analyzing [ApkDiff](https://github.com/csl-ugent/apkdiff), [SimiDroid](https://github.com/lilicoding/SimiDroid), [Androguard](https://github.com/androguard/androguard), and [Quarkslab's Android Diffing Engine](https://blog.quarkslab.com/android-application-diffing-engine-overview.html).

### 7.1 Extended Java/DEX Schema

```sql
-- ============================================
-- EXTENDED CLASSES TABLE (ApkDiff-inspired)
-- ============================================
ALTER TABLE classes ADD COLUMN IF NOT EXISTS (
    -- Obfuscation detection
    is_name_mangled     BOOLEAN,          -- detected via heuristics
    name_entropy        REAL,             -- Shannon entropy of name

    -- Structural signature (for hash-based matching)
    class_signature     TEXT,             -- structural hash (see 7.3)
    class_hash_128      BLOB,             -- 128-bit SimHash signature

    -- Hierarchy metrics
    inner_class_depth   INTEGER,          -- nesting level
    inner_class_count   INTEGER,

    -- Modifier flags (bitmask)
    is_abstract         BOOLEAN,
    is_final            BOOLEAN,
    is_synthetic        BOOLEAN,
    is_inner            BOOLEAN,

    -- Soot/Jimple IR metrics
    jimple_stmt_count   INTEGER,          -- total Jimple statements
    jimple_hash         TEXT              -- hash of normalized Jimple
);

-- ============================================
-- EXTENDED METHODS TABLE (SimiDroid-inspired)
-- ============================================
ALTER TABLE methods ADD COLUMN IF NOT EXISTS (
    -- Jimple IR features
    jimple_stmts        TEXT,             -- JSON: serialized statements
    jimple_stmt_count   INTEGER,
    jimple_hash         TEXT,             -- hash of normalized Jimple

    -- Statement type histogram
    stmt_histogram      TEXT,             -- JSON: {"AssignStmt": 5, "InvokeStmt": 3, ...}

    -- Call edges (method invocations within this method)
    call_edges          TEXT,             -- JSON: ["<Class: void method()>", ...]
    call_edge_count     INTEGER,

    -- Constants extracted from bytecode
    string_constants    TEXT,             -- JSON array
    numeric_constants   TEXT,             -- JSON array

    -- Abstract opcode sequence (Quarkslab style)
    abstract_opcodes    BLOB,             -- normalized opcode sequence
    abstract_opcode_hash TEXT,            -- hash for quick comparison

    -- Dexofuzzy signature
    opcode_sequence     TEXT,             -- raw opcode sequence
    dexofuzzy_hash      TEXT,             -- ssdeep-style fuzzy hash

    -- Method signature normalization
    normalized_signature TEXT,            -- signature without class names
    signature_shape     TEXT              -- "(II)V" style shape
);

-- ============================================
-- JIMPLE STATEMENTS TABLE (for fine-grained diff)
-- ============================================
CREATE TABLE jimple_statements (
    id                  INTEGER PRIMARY KEY,
    method_id           INTEGER REFERENCES methods(id),

    stmt_index          INTEGER,          -- position in method
    stmt_type           TEXT,             -- AssignStmt, InvokeStmt, IfStmt, etc.

    -- For invocation statements
    invoked_method      TEXT,             -- method signature if invoke
    invoked_class       TEXT,

    -- For field access
    field_signature     TEXT,
    field_class         TEXT,

    -- For constants
    has_string_const    BOOLEAN,
    string_const_value  TEXT,
    has_numeric_const   BOOLEAN,
    numeric_const_value TEXT,

    -- For control flow
    target_stmt_index   INTEGER,          -- jump target if branch

    UNIQUE(method_id, stmt_index)
);

CREATE INDEX idx_jimple_method ON jimple_statements(method_id);
CREATE INDEX idx_jimple_type ON jimple_statements(stmt_type);

-- ============================================
-- INTENT FILTERS (Component-level comparison)
-- ============================================
CREATE TABLE intent_filters (
    id                  INTEGER PRIMARY KEY,
    class_id            INTEGER REFERENCES classes(id),
    component_type      TEXT,             -- "activity", "service", "receiver", "provider"

    actions             TEXT,             -- JSON array of action strings
    categories          TEXT,             -- JSON array of category strings
    data_schemes        TEXT,             -- JSON array
    data_hosts          TEXT,             -- JSON array

    -- For quick comparison
    filter_hash         TEXT,             -- hash of normalized filter

    UNIQUE(class_id, filter_hash)
);

-- ============================================
-- RESOURCES (Resource-level comparison)
-- ============================================
CREATE TABLE resources (
    id                  INTEGER PRIMARY KEY,
    apk_id              INTEGER REFERENCES apks(id),

    file_path           TEXT,             -- path within APK
    file_type           TEXT,             -- extension or MIME type
    file_size           INTEGER,

    -- For comparison
    md5_hash            TEXT,
    sha256_hash         TEXT,

    -- For images/layouts
    dimensions          TEXT,             -- JSON: {"width": 100, "height": 100}

    UNIQUE(apk_id, file_path)
);

CREATE INDEX idx_resources_hash ON resources(md5_hash);
```

### 7.2 Obfuscation Detection (ApkDiff)

ApkDiff uses sophisticated heuristics to detect obfuscated names:

```python
# ============================================
# OBFUSCATION DETECTION HEURISTICS
# ============================================

import re
import math

# Java reserved keywords (if used as identifiers, code is obfuscated)
JAVA_KEYWORDS = {
    'abstract', 'assert', 'boolean', 'break', 'byte', 'case', 'catch',
    'char', 'class', 'const', 'continue', 'default', 'do', 'double',
    'else', 'enum', 'extends', 'final', 'finally', 'float', 'for',
    'goto', 'if', 'implements', 'import', 'instanceof', 'int',
    'interface', 'long', 'native', 'new', 'package', 'private',
    'protected', 'public', 'return', 'short', 'static', 'strictfp',
    'super', 'switch', 'synchronized', 'this', 'throw', 'throws',
    'transient', 'try', 'void', 'volatile', 'while'
}

# Hash patterns from obfuscators
HASH_PATTERNS = [
    r'^md5[0-9a-fA-F]{32}$',              # MD5 hash
    r'^crc(64|32|16|8)[0-9a-fA-F]*$',     # CRC variants
    r'^sha(1|3|224|256|384|512)[0-9a-fA-F]*$',  # SHA variants
]


def is_name_mangled(name: str) -> bool:
    """
    Detect if a Java identifier has been obfuscated.
    Based on ApkDiff's Obfuscation.isNameMangled() method.
    """
    if not name:
        return True

    # 1. Reserved keywords used as identifiers
    if name in JAVA_KEYWORDS:
        return True

    # 2. Invalid Java identifier characters
    if not name[0].isalpha() and name[0] != '_':
        return True
    for char in name:
        if not (char.isalnum() or char == '_'):
            return True

    # 3. Special case: Android R class is never mangled
    if name == 'R':
        return False

    # 4. Very short names (≤2 chars) are typically mangled
    if len(name) <= 2:
        # Exceptions: common short names
        if name in ('io', 'id', 'ok', 'UI'):
            return False
        return True

    # 5. Hash patterns
    for pattern in HASH_PATTERNS:
        if re.match(pattern, name, re.IGNORECASE):
            return True

    # 6. Short identifier + number pattern (a0, b1, aa0, etc.)
    if re.match(r'^[a-zA-Z]{1,2}\d*$', name):
        return True

    # 7. Three or more consecutive consonants (rare in real names)
    consonants = 'bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ'
    consonant_count = 0
    for char in name:
        if char in consonants:
            consonant_count += 1
            if consonant_count >= 3:
                return True
        else:
            consonant_count = 0

    return False


def calculate_name_entropy(name: str) -> float:
    """
    Calculate Shannon entropy of a name.
    High entropy suggests random/obfuscated names.
    """
    if not name:
        return 0.0

    freq = {}
    for char in name:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / len(name)
        entropy -= p * math.log2(p)

    return entropy
```

### 7.3 Class Signature Hash (ApkDiff)

ApkDiff creates a structural hash for each class that ignores obfuscated names:

```python
# ============================================
# CLASS SIGNATURE HASH (ApkDiff Style)
# ============================================

def compute_class_signature(soot_class) -> str:
    """
    Compute structural signature for a class.
    Based on ApkDiff's SootUtil.sootClass2hash() method.

    Format: [modifiers]_[depth]_[interfaces]_[fields]_[methods]
    """
    parts = []

    # 1. Class modifiers
    modifiers = []
    if soot_class.is_abstract:
        modifiers.append('A')
    if soot_class.is_public:
        modifiers.append('P')
    if soot_class.is_private:
        modifiers.append('p')
    if soot_class.is_protected:
        modifiers.append('R')
    if soot_class.is_static:
        modifiers.append('S')
    if soot_class.is_interface:
        modifiers.append('I')
    if soot_class.is_enum:
        modifiers.append('E')
    if soot_class.is_final:
        modifiers.append('F')
    parts.append(''.join(sorted(modifiers)))

    # 2. Inner class depth
    parts.append(str(soot_class.inner_class_depth))

    # 3. Interface count
    parts.append(str(len(soot_class.interfaces)))

    # 4. Field signatures
    field_hashes = []
    for field in sorted(soot_class.fields, key=lambda f: f.type):
        fh = compute_field_signature(field)
        field_hashes.append(fh)
    parts.append(f"{len(field_hashes)},{','.join(field_hashes)}")

    # 5. Method signatures
    method_hashes = []
    for method in sorted(soot_class.methods, key=lambda m: (m.return_type, m.param_count)):
        mh = compute_method_signature(method)
        method_hashes.append(mh)
    parts.append(f"{len(method_hashes)},{','.join(method_hashes)}")

    return '_'.join(parts)


def compute_method_signature(method) -> str:
    """
    Compute structural signature for a method.
    Includes: modifiers, return type shape, parameter type shapes.
    """
    parts = []

    # Modifiers
    mods = []
    if method.is_public:
        mods.append('P')
    if method.is_private:
        mods.append('p')
    if method.is_protected:
        mods.append('R')
    if method.is_static:
        mods.append('S')
    if method.is_final:
        mods.append('F')
    if method.is_abstract:
        mods.append('A')
    if method.is_constructor:
        mods.append('C')
    if method.is_native:
        mods.append('N')
    if method.is_synchronized:
        mods.append('Y')
    parts.append(''.join(sorted(mods)))

    # Return type shape (primitives exact, objects as 'L', arrays as '[')
    parts.append(get_type_shape(method.return_type))

    # Parameter shapes
    param_shapes = [get_type_shape(p) for p in method.param_types]
    parts.append(','.join(param_shapes))

    return ':'.join(parts)


def compute_field_signature(field) -> str:
    """Compute structural signature for a field."""
    parts = []

    mods = []
    if field.is_public:
        mods.append('P')
    if field.is_private:
        mods.append('p')
    if field.is_protected:
        mods.append('R')
    if field.is_static:
        mods.append('S')
    if field.is_final:
        mods.append('F')
    parts.append(''.join(sorted(mods)))

    parts.append(get_type_shape(field.type))

    return ':'.join(parts)


def get_type_shape(type_str: str) -> str:
    """
    Convert Java type to shape.
    Primitives: exact (I, J, Z, etc.)
    Objects: 'L' (or 'L*' if known non-obfuscated)
    Arrays: '[' prefix + element shape
    """
    if type_str.startswith('['):
        # Array type
        return '[' + get_type_shape(type_str[1:])

    # Primitive types
    primitives = {'int': 'I', 'long': 'J', 'boolean': 'Z', 'byte': 'B',
                  'char': 'C', 'short': 'S', 'float': 'F', 'double': 'D',
                  'void': 'V'}
    if type_str in primitives:
        return primitives[type_str]

    # Object type - check if SDK/library class
    if type_str.startswith(('java.', 'android.', 'androidx.')):
        return type_str  # Keep full name for SDK classes

    return 'L'  # Generic object placeholder
```

### 7.4 Abstract Opcodes (Quarkslab)

Quarkslab's engine uses abstract opcodes to handle compilation variations:

```python
# ============================================
# ABSTRACT OPCODES (Quarkslab Style)
# ============================================

from enum import IntEnum

class AbstractOpcode(IntEnum):
    """
    Dalvik opcodes abstracted into categories.
    Ignores register numbers and specific operands.
    """
    NONE = 0          # nop
    TEST = 1          # if-*, switch-*
    END_BLOCK = 2     # return-*, throw
    COMPARISON = 3    # cmp*
    CALL = 4          # invoke-*
    ARITHMETIC = 5    # add, sub, mul, div, rem, and, or, xor, shl, shr
    CAST = 6          # int-to-*, *-to-int
    FIELD_STATIC = 7  # sget-*, sput-*
    FIELD_INSTANCE = 8  # iget-*, iput-*
    ARRAY_ACCESS = 9  # aget-*, aput-*
    STRING_OP = 10    # const-string
    MOVE = 11         # move-*
    INTEGER = 12      # const/4, const/16, const
    NEW_INSTANCE = 13 # new-instance, new-array
    CHECK_CAST = 14   # check-cast, instance-of
    MONITOR = 15      # monitor-enter, monitor-exit
    FILL_ARRAY = 16   # fill-array-data

# Dalvik opcode to abstract opcode mapping
OPCODE_TO_ABSTRACT = {
    0x00: AbstractOpcode.NONE,           # nop

    # Move operations
    0x01: AbstractOpcode.MOVE,           # move
    0x02: AbstractOpcode.MOVE,           # move/from16
    0x03: AbstractOpcode.MOVE,           # move/16
    0x04: AbstractOpcode.MOVE,           # move-wide
    # ... (more move variants)

    # Constants
    0x12: AbstractOpcode.INTEGER,        # const/4
    0x13: AbstractOpcode.INTEGER,        # const/16
    0x14: AbstractOpcode.INTEGER,        # const
    0x15: AbstractOpcode.INTEGER,        # const/high16
    0x1A: AbstractOpcode.STRING_OP,      # const-string
    0x1B: AbstractOpcode.STRING_OP,      # const-string/jumbo
    0x1C: AbstractOpcode.CHECK_CAST,     # const-class

    # Control flow
    0x0E: AbstractOpcode.END_BLOCK,      # return-void
    0x0F: AbstractOpcode.END_BLOCK,      # return
    0x10: AbstractOpcode.END_BLOCK,      # return-wide
    0x11: AbstractOpcode.END_BLOCK,      # return-object
    0x27: AbstractOpcode.END_BLOCK,      # throw

    # Conditionals
    0x32: AbstractOpcode.TEST,           # if-eq
    0x33: AbstractOpcode.TEST,           # if-ne
    0x34: AbstractOpcode.TEST,           # if-lt
    0x35: AbstractOpcode.TEST,           # if-ge
    0x36: AbstractOpcode.TEST,           # if-gt
    0x37: AbstractOpcode.TEST,           # if-le

    # Invocations
    0x6E: AbstractOpcode.CALL,           # invoke-virtual
    0x6F: AbstractOpcode.CALL,           # invoke-super
    0x70: AbstractOpcode.CALL,           # invoke-direct
    0x71: AbstractOpcode.CALL,           # invoke-static
    0x72: AbstractOpcode.CALL,           # invoke-interface

    # Field access
    0x52: AbstractOpcode.FIELD_INSTANCE, # iget
    0x59: AbstractOpcode.FIELD_INSTANCE, # iput
    0x60: AbstractOpcode.FIELD_STATIC,   # sget
    0x67: AbstractOpcode.FIELD_STATIC,   # sput

    # Array access
    0x44: AbstractOpcode.ARRAY_ACCESS,   # aget
    0x4B: AbstractOpcode.ARRAY_ACCESS,   # aput

    # Arithmetic
    0x90: AbstractOpcode.ARITHMETIC,     # add-int
    0x91: AbstractOpcode.ARITHMETIC,     # sub-int
    0x92: AbstractOpcode.ARITHMETIC,     # mul-int
    0x93: AbstractOpcode.ARITHMETIC,     # div-int
    # ... (more arithmetic)
}


def compute_abstract_opcode_sequence(method) -> bytes:
    """
    Convert method bytecode to abstract opcode sequence.
    Returns bytes where each byte is an AbstractOpcode value.
    """
    abstract_seq = []
    for instruction in method.instructions:
        opcode = instruction.opcode
        abstract = OPCODE_TO_ABSTRACT.get(opcode, AbstractOpcode.NONE)
        abstract_seq.append(abstract)
    return bytes(abstract_seq)


def compute_method_16bit_signature(method) -> int:
    """
    Quarkslab's 16-bit method signature for ordering.
    Combines instruction count and XOR of all opcodes.
    """
    insn_count = len(method.instructions)
    opcode_xor = 0
    for instruction in method.instructions:
        opcode_xor ^= instruction.opcode

    # Pack: 8 bits for count (clamped), 8 bits for XOR
    return ((min(insn_count, 255) & 0xFF) << 8) | (opcode_xor & 0xFF)
```

### 7.5 SimHash for Class Signatures (Quarkslab)

```python
# ============================================
# SIMHASH FOR CLASS COMPARISON
# ============================================

import hashlib

def compute_simhash(features: list, hash_bits: int = 128) -> int:
    """
    Compute SimHash from a list of features.
    Used for fast similarity comparison via Hamming distance.
    """
    v = [0] * hash_bits

    for feature in features:
        # Hash the feature
        h = int(hashlib.md5(feature.encode()).hexdigest(), 16)

        for i in range(hash_bits):
            bit = (h >> i) & 1
            if bit:
                v[i] += 1
            else:
                v[i] -= 1

    # Convert to binary fingerprint
    fingerprint = 0
    for i in range(hash_bits):
        if v[i] > 0:
            fingerprint |= (1 << i)

    return fingerprint


def compute_class_simhash(soot_class) -> int:
    """
    Compute 128-bit SimHash for a class.
    Features: method signatures, field signatures, interface names.
    """
    features = []

    # Method features
    for method in soot_class.methods:
        sig = compute_method_signature(method)
        features.append(f"M:{sig}")

    # Field features
    for field in soot_class.fields:
        sig = compute_field_signature(field)
        features.append(f"F:{sig}")

    # Interface features (use full names for SDK interfaces)
    for iface in soot_class.interfaces:
        if not is_name_mangled(iface):
            features.append(f"I:{iface}")

    # Superclass (if not obfuscated)
    if soot_class.superclass and not is_name_mangled(soot_class.superclass):
        features.append(f"S:{soot_class.superclass}")

    return compute_simhash(features)


def simhash_distance(h1: int, h2: int, bits: int = 128) -> int:
    """
    Compute Hamming distance between two SimHash values.
    Lower distance = more similar.
    """
    xor = h1 ^ h2
    return bin(xor).count('1')


def are_classes_similar(h1: int, h2: int, threshold: int = 10) -> bool:
    """
    Check if two classes are similar based on SimHash.
    Default threshold: 10 bits difference out of 128.
    """
    return simhash_distance(h1, h2) <= threshold
```

### 7.6 Jimple IR Comparison (SimiDroid)

```python
# ============================================
# JIMPLE STATEMENT COMPARISON (SimiDroid Style)
# ============================================

from enum import Enum
from dataclasses import dataclass
from typing import List, Optional

class JimpleStmtType(Enum):
    ASSIGN = "AssignStmt"
    INVOKE = "InvokeStmt"
    IDENTITY = "IdentityStmt"
    IF = "IfStmt"
    GOTO = "GotoStmt"
    RETURN = "ReturnStmt"
    RETURN_VOID = "ReturnVoidStmt"
    THROW = "ThrowStmt"
    LOOKUP_SWITCH = "LookupSwitchStmt"
    TABLE_SWITCH = "TableSwitchStmt"
    ENTER_MONITOR = "EnterMonitorStmt"
    EXIT_MONITOR = "ExitMonitorStmt"
    NOP = "NopStmt"
    OTHER = "Other"


@dataclass
class JimpleStatement:
    """Represents a normalized Jimple statement for comparison."""
    stmt_type: JimpleStmtType
    method_signature: Optional[str] = None      # for invoke statements
    field_signature: Optional[str] = None       # for field access
    array_ref_base: Optional[str] = None        # for array access
    string_constant: Optional[str] = None       # string literals
    numeric_constant: Optional[str] = None      # numeric literals

    def equals_to(self, other: 'JimpleStatement') -> tuple:
        """
        Compare two statements.
        Returns (is_equal, explanation) tuple.
        """
        if self.stmt_type != other.stmt_type:
            return False, f"Type mismatch: {self.stmt_type} vs {other.stmt_type}"

        # Check method invocations
        if self.method_signature or other.method_signature:
            if self.method_signature != other.method_signature:
                if self.method_signature and not other.method_signature:
                    return False, "New method call"
                return False, "Method signature mismatch"

        # Check field access
        if self.field_signature or other.field_signature:
            if self.field_signature != other.field_signature:
                return False, "Field mismatch"

        # Check array references
        if self.array_ref_base or other.array_ref_base:
            if self.array_ref_base != other.array_ref_base:
                return False, "ArrayRef mismatch"

        # Check string constants
        if self.string_constant or other.string_constant:
            if self.string_constant != other.string_constant:
                return False, "String constant mismatch"

        # Check numeric constants
        if self.numeric_constant or other.numeric_constant:
            if self.numeric_constant != other.numeric_constant:
                return False, "Numeric constant mismatch"

        return True, None


def compare_methods_jimple(method1_stmts: List[JimpleStatement],
                           method2_stmts: List[JimpleStatement]) -> dict:
    """
    Compare two methods at Jimple statement level.
    Returns detailed comparison results.
    """
    result = {
        'identical': True,
        'stmt_count_1': len(method1_stmts),
        'stmt_count_2': len(method2_stmts),
        'differences': [],
        'similarity_ratio': 0.0
    }

    if len(method1_stmts) != len(method2_stmts):
        result['identical'] = False
        result['differences'].append(
            f"Statement count mismatch: {len(method1_stmts)} vs {len(method2_stmts)}"
        )
        # Use LCS for partial matching
        result['similarity_ratio'] = compute_lcs_ratio(method1_stmts, method2_stmts)
        return result

    matching_stmts = 0
    for i, (s1, s2) in enumerate(zip(method1_stmts, method2_stmts)):
        is_equal, explanation = s1.equals_to(s2)
        if is_equal:
            matching_stmts += 1
        else:
            result['identical'] = False
            result['differences'].append(f"Stmt {i}: {explanation}")

    result['similarity_ratio'] = matching_stmts / len(method1_stmts) if method1_stmts else 1.0
    return result


def compute_lcs_ratio(stmts1: List[JimpleStatement],
                      stmts2: List[JimpleStatement]) -> float:
    """
    Compute similarity using Longest Common Subsequence.
    """
    m, n = len(stmts1), len(stmts2)
    if m == 0 or n == 0:
        return 0.0

    # Build LCS table
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            is_equal, _ = stmts1[i-1].equals_to(stmts2[j-1])
            if is_equal:
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])

    lcs_length = dp[m][n]
    return (2 * lcs_length) / (m + n)
```

### 7.7 Dexofuzzy (Opcode-based Fuzzy Hash)

```python
# ============================================
# DEXOFUZZY: OPCODE-BASED FUZZY HASHING
# ============================================

import ssdeep  # pip install ssdeep

def extract_opcode_sequence(dex_method) -> bytes:
    """
    Extract raw opcode sequence from a DEX method.
    Ignores operands, only keeps opcodes.
    """
    opcodes = []
    for instruction in dex_method.get_instructions():
        opcodes.append(instruction.get_op_value())
    return bytes(opcodes)


def compute_dexofuzzy_hash(dex_file) -> str:
    """
    Compute Dexofuzzy hash for entire DEX file.
    Concatenates all method opcodes and applies ssdeep.
    """
    all_opcodes = bytearray()

    for class_def in dex_file.get_classes():
        for method in class_def.get_methods():
            if method.get_code():
                opcodes = extract_opcode_sequence(method)
                all_opcodes.extend(opcodes)

    if not all_opcodes:
        return ""

    return ssdeep.hash(bytes(all_opcodes))


def compute_method_dexofuzzy(method) -> str:
    """
    Compute Dexofuzzy hash for a single method.
    """
    opcodes = extract_opcode_sequence(method)
    if len(opcodes) < 10:  # Too short for fuzzy hashing
        return ""
    return ssdeep.hash(opcodes)


def dexofuzzy_similarity(hash1: str, hash2: str) -> int:
    """
    Compare two Dexofuzzy hashes.
    Returns similarity score 0-100.
    """
    if not hash1 or not hash2:
        return 0
    return ssdeep.compare(hash1, hash2)


# ============================================
# N-GRAM BASED SIMILARITY (Alternative)
# ============================================

def compute_opcode_ngrams(method, n: int = 3) -> set:
    """
    Extract n-gram features from opcode sequence.
    Used when ssdeep is not available.
    """
    opcodes = extract_opcode_sequence(method)
    if len(opcodes) < n:
        return set()

    ngrams = set()
    for i in range(len(opcodes) - n + 1):
        ngram = tuple(opcodes[i:i+n])
        ngrams.add(ngram)

    return ngrams


def ngram_jaccard_similarity(method1, method2, n: int = 3) -> float:
    """
    Compute Jaccard similarity of opcode n-grams.
    """
    ngrams1 = compute_opcode_ngrams(method1, n)
    ngrams2 = compute_opcode_ngrams(method2, n)

    if not ngrams1 and not ngrams2:
        return 1.0
    if not ngrams1 or not ngrams2:
        return 0.0

    intersection = len(ngrams1 & ngrams2)
    union = len(ngrams1 | ngrams2)

    return intersection / union
```

### 7.8 Multi-Pass Matching Algorithm (ApkDiff)

```python
# ============================================
# APKDIFF MULTI-PASS MATCHING ALGORITHM
# ============================================

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Optional

class MatchMethod(Enum):
    CLASS_SIGNATURE_AND_NAMES = 1   # Signature + readable names match
    CLASS_SIGNATURE = 2              # Structure-only match
    CALL_GRAPH = 3                   # Call graph edges match
    CALL_GRAPH_AFTER_SIGNATURE = 4   # CG to disambiguate signatures
    SUPERCLASS = 5                   # Matched via parent class
    INTERFACE = 6                    # Matched via interface
    FIELD_TYPE = 7                   # Matched via field type reference
    METHOD_TYPE = 8                  # Matched via method param/return type
    SINGLE_OPTION = 9                # Last resort: only one option


@dataclass
class ClassMatch:
    class1: 'SootClass'
    class2: 'SootClass'
    method: MatchMethod
    confidence: float
    bytecode_match: bool = False


def apkdiff_match(classes1: List['SootClass'],
                  classes2: List['SootClass'],
                  config: dict) -> List[ClassMatch]:
    """
    ApkDiff's hierarchical matching algorithm.
    """
    matches = []
    unmatched1 = set(classes1)
    unmatched2 = set(classes2)

    # Build hash indexes for fast lookup
    sig_index1 = build_signature_index(classes1)
    sig_index2 = build_signature_index(classes2)

    # Build call graphs (cached)
    cg1 = build_call_graph(classes1)
    cg2 = build_call_graph(classes2)

    # Iterative matching until no new matches
    changed = True
    while changed:
        changed = False

        for c1 in list(unmatched1):
            sig = compute_class_signature(c1)
            candidates = sig_index2.get(sig, [])
            candidates = [c for c in candidates if c in unmatched2]

            if not candidates:
                continue

            match = None
            method = None

            # Pass 1: Signature + Names
            if config.get('use_names', True):
                name_matches = [c for c in candidates
                               if names_match(c1, c) and not is_name_mangled(c1.name)]
                if len(name_matches) == 1:
                    match = name_matches[0]
                    method = MatchMethod.CLASS_SIGNATURE_AND_NAMES

            # Pass 2: Signature only (unique)
            if not match and len(candidates) == 1:
                match = candidates[0]
                method = MatchMethod.CLASS_SIGNATURE

            # Pass 3: Call graph disambiguation
            if not match and len(candidates) > 1 and config.get('use_callgraph', True):
                cg_match = disambiguate_by_callgraph(c1, candidates, cg1, cg2, matches)
                if cg_match:
                    match = cg_match
                    method = MatchMethod.CALL_GRAPH_AFTER_SIGNATURE

            if match:
                # Verify bytecode compatibility
                bytecode_ok = verify_bytecode_match(c1, match)

                matches.append(ClassMatch(
                    class1=c1,
                    class2=match,
                    method=method,
                    confidence=0.9 if bytecode_ok else 0.7,
                    bytecode_match=bytecode_ok
                ))

                unmatched1.remove(c1)
                unmatched2.remove(match)
                changed = True

                # Propagate: match related classes
                propagate_matches(c1, match, unmatched1, unmatched2,
                                 matches, config)

    # Final pass: single option fallback
    for c1 in list(unmatched1):
        sig = compute_class_signature(c1)
        candidates = [c for c in sig_index2.get(sig, []) if c in unmatched2]
        if len(candidates) == 1:
            matches.append(ClassMatch(
                class1=c1,
                class2=candidates[0],
                method=MatchMethod.SINGLE_OPTION,
                confidence=0.5,
                bytecode_match=False
            ))
            unmatched1.remove(c1)
            unmatched2.remove(candidates[0])

    return matches


def propagate_matches(c1, c2, unmatched1, unmatched2, matches, config):
    """
    When a class is matched, try to match related classes.
    """
    # Superclass propagation
    if config.get('use_superclasses', True):
        if c1.superclass and c2.superclass:
            super1 = find_class_by_name(c1.superclass, unmatched1)
            super2 = find_class_by_name(c2.superclass, unmatched2)
            if super1 and super2:
                matches.append(ClassMatch(super1, super2,
                                         MatchMethod.SUPERCLASS, 0.8))
                unmatched1.discard(super1)
                unmatched2.discard(super2)

    # Interface propagation
    if config.get('use_interfaces', True):
        for iface1, iface2 in zip(c1.interfaces, c2.interfaces):
            i1 = find_class_by_name(iface1, unmatched1)
            i2 = find_class_by_name(iface2, unmatched2)
            if i1 and i2:
                matches.append(ClassMatch(i1, i2,
                                         MatchMethod.INTERFACE, 0.75))
                unmatched1.discard(i1)
                unmatched2.discard(i2)

    # Field type propagation
    if config.get('use_fields', True):
        for f1, f2 in zip_matching_fields(c1, c2):
            ft1 = find_class_by_name(f1.type, unmatched1)
            ft2 = find_class_by_name(f2.type, unmatched2)
            if ft1 and ft2:
                matches.append(ClassMatch(ft1, ft2,
                                         MatchMethod.FIELD_TYPE, 0.7))
                unmatched1.discard(ft1)
                unmatched2.discard(ft2)


def verify_bytecode_match(c1, c2) -> bool:
    """
    Verify that matched classes have compatible bytecode.
    """
    methods1 = sorted(c1.methods, key=lambda m: m.signature)
    methods2 = sorted(c2.methods, key=lambda m: m.signature)

    if len(methods1) != len(methods2):
        return False

    for m1, m2 in zip(methods1, methods2):
        if not m1.has_body() and not m2.has_body():
            continue
        if m1.has_body() != m2.has_body():
            return False

        units1 = list(m1.get_units())
        units2 = list(m2.get_units())

        if len(units1) != len(units2):
            return False

        for u1, u2 in zip(units1, units2):
            if type(u1).__name__ != type(u2).__name__:
                return False

    return True
```

### 7.9 Similarity Calculation (SimiDroid)

```python
# ============================================
# SIMIDROID SIMILARITY CALCULATION
# ============================================

from dataclasses import dataclass
from typing import Dict, Set

@dataclass
class SimilarityResult:
    identical_count: int
    similar_count: int
    new_count: int
    deleted_count: int
    similarity_score: float

    identical_features: Set[str]
    similar_features: Set[str]
    new_features: Set[str]
    deleted_features: Set[str]


def compute_similarity(features1: Dict[str, any],
                       features2: Dict[str, any],
                       compare_func) -> SimilarityResult:
    """
    SimiDroid's similarity calculation.

    Score formula:
        score1 = identical / (total - deleted)
        score2 = identical / (total - new)
        final = max(score1, score2)
    """
    keys1 = set(features1.keys())
    keys2 = set(features2.keys())

    identical = set()
    similar = set()
    new_features = keys2 - keys1
    deleted = keys1 - keys2

    common_keys = keys1 & keys2

    for key in common_keys:
        if compare_func(features1[key], features2[key]):
            identical.add(key)
        else:
            similar.add(key)

    total = len(keys1 | keys2)
    identical_count = len(identical)

    # Avoid division by zero
    denom1 = total - len(deleted)
    denom2 = total - len(new_features)

    score1 = identical_count / denom1 if denom1 > 0 else 0
    score2 = identical_count / denom2 if denom2 > 0 else 0

    return SimilarityResult(
        identical_count=len(identical),
        similar_count=len(similar),
        new_count=len(new_features),
        deleted_count=len(deleted),
        similarity_score=max(score1, score2),
        identical_features=identical,
        similar_features=similar,
        new_features=new_features,
        deleted_features=deleted
    )


# ============================================
# MULTI-LEVEL SIMILARITY (Method + Component + Resource)
# ============================================

def compute_app_similarity(apk1, apk2) -> dict:
    """
    Compute similarity at multiple levels.
    """
    results = {}

    # Method-level (code)
    methods1 = extract_methods(apk1)
    methods2 = extract_methods(apk2)
    results['method'] = compute_similarity(
        methods1, methods2,
        lambda m1, m2: compare_methods_jimple(m1.stmts, m2.stmts)['identical']
    )

    # Component-level (manifest)
    components1 = extract_components(apk1)
    components2 = extract_components(apk2)
    results['component'] = compute_similarity(
        components1, components2,
        lambda c1, c2: c1.intent_filters == c2.intent_filters
    )

    # Resource-level (files)
    resources1 = extract_resources(apk1)
    resources2 = extract_resources(apk2)
    results['resource'] = compute_similarity(
        resources1, resources2,
        lambda r1, r2: r1['md5'] == r2['md5']
    )

    # Overall weighted score
    weights = {'method': 0.6, 'component': 0.2, 'resource': 0.2}
    results['overall'] = sum(
        results[level].similarity_score * weight
        for level, weight in weights.items()
    )

    return results
```

### 7.10 Androguard Cross-References

```python
# ============================================
# ANDROGUARD CROSS-REFERENCE EXTRACTION
# ============================================

from androguard.misc import AnalyzeAPK
import networkx as nx

def extract_xrefs(apk_path: str) -> dict:
    """
    Extract all cross-references from an APK using Androguard.
    """
    a, d, dx = AnalyzeAPK(apk_path)

    xrefs = {
        'method_calls': [],      # method -> method
        'field_reads': [],       # method -> field
        'field_writes': [],      # method -> field
        'string_usage': [],      # method -> string
        'class_instantiation': [],  # method -> class
    }

    for method in dx.get_methods():
        method_sig = method.get_method().get_descriptor()

        # Methods this method calls
        for _, call, _ in method.get_xref_to():
            xrefs['method_calls'].append({
                'caller': method_sig,
                'callee': call.get_descriptor(),
            })

        # Fields read by this method
        for _, field, access_type in method.get_xref_read():
            xrefs['field_reads'].append({
                'method': method_sig,
                'field': str(field),
            })

        # Fields written by this method
        for _, field, access_type in method.get_xref_write():
            xrefs['field_writes'].append({
                'method': method_sig,
                'field': str(field),
            })

    # String references
    for string in dx.get_strings():
        for method, _ in string.get_xref_from():
            xrefs['string_usage'].append({
                'method': method.get_descriptor(),
                'string': string.get_value(),
            })

    return xrefs


def build_call_graph_networkx(apk_path: str) -> nx.DiGraph:
    """
    Build NetworkX call graph from APK.
    """
    a, d, dx = AnalyzeAPK(apk_path)

    G = nx.DiGraph()

    for method in dx.get_methods():
        method_sig = method.get_method().get_descriptor()

        # Add node with attributes
        G.add_node(method_sig,
                   classname=method.get_method().get_class_name(),
                   methodname=method.get_method().get_name(),
                   is_external=method.is_external(),
                   access_flags=method.get_method().get_access_flags_string())

        # Add edges for calls
        for _, callee, _ in method.get_xref_to():
            callee_sig = callee.get_descriptor()
            G.add_edge(method_sig, callee_sig)

    return G


def extract_api_usage(apk_path: str) -> dict:
    """
    Extract Android API usage patterns.
    """
    a, d, dx = AnalyzeAPK(apk_path)

    api_calls = {}  # method -> list of API calls

    for method in dx.get_internal_methods():
        method_sig = method.get_method().get_descriptor()
        api_calls[method_sig] = []

        for _, callee, _ in method.get_xref_to():
            callee_class = callee.get_class_name()

            # Check if it's an Android/Java SDK call
            if callee_class.startswith(('Landroid/', 'Ljava/', 'Ljavax/')):
                api_calls[method_sig].append({
                    'class': callee_class,
                    'method': callee.get_name(),
                    'descriptor': callee.get_descriptor(),
                })

    return api_calls
```

### 7.11 Priority Data for Java/DEX Matching

| Priority | Data | Matching Power | Obfuscation Resistant |
|----------|------|----------------|----------------------|
| **1** | `class_signature` (structural hash) | Exact structural match | Yes |
| **2** | `api_call_hash` (SDK calls) | Semantic fingerprint | Yes |
| **3** | `simhash_128` (class SimHash) | Fast similarity filter | Yes |
| **4** | `abstract_opcodes` (Quarkslab) | Compilation-invariant | Yes |
| **5** | `jimple_hash` (normalized IR) | Statement-level match | Partial |
| **6** | `dexofuzzy_hash` (ssdeep) | Fuzzy code similarity | Yes |
| **7** | `string_constants` | Semantic anchor | Partial |
| **8** | `superclass` + `interfaces` | Type hierarchy | Yes |
| **9** | `intent_filters` | Component behavior | Yes |
| **10** | `call_edges` | Control flow | Yes |

**Minimum viable schema for obfuscated APK matching:**
```sql
classes: name, package, class_signature, simhash_128, superclass,
         interface_count, method_count, field_count, is_name_mangled

methods: class_id, signature_shape, return_type, param_count,
         api_call_hash, abstract_opcode_hash, stmt_count
```

**Sources:**
- [ApkDiff (csl-ugent)](https://github.com/csl-ugent/apkdiff) - Class structure matching
- [SimiDroid (lilicoding)](https://github.com/lilicoding/SimiDroid) - Multi-level similarity
- [Androguard](https://github.com/androguard/androguard) - DEX analysis framework
- [Quarkslab Android Diffing](https://blog.quarkslab.com/android-application-diffing-engine-overview.html) - Abstract opcodes, SimHash
- [Dexofuzzy (Virus Bulletin)](https://www.virusbulletin.com/virusbulletin/2019/11/dexofuzzy-android-malware-similarity-clustering-method-using-opcode-sequence/) - Opcode fuzzy hashing
