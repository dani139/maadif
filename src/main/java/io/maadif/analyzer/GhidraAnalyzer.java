package io.maadif.analyzer;

import ghidra.GhidraApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.util.task.TaskMonitor;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.*;
import java.util.*;

/**
 * Ghidra-based binary analyzer for DEX files and native libraries.
 * Uses Ghidra's headless API to perform deep binary analysis.
 */
public class GhidraAnalyzer {

    private File projectDir;
    private File outputDir;
    private boolean initialized = false;

    // Ghidra installation directory - set via environment or default
    private static final String GHIDRA_HOME = System.getenv("GHIDRA_INSTALL_DIR") != null
        ? System.getenv("GHIDRA_INSTALL_DIR")
        : "/opt/ghidra";

    public GhidraAnalyzer(File outputDir) {
        this.outputDir = outputDir;
        this.projectDir = new File(outputDir, "ghidra_project");
    }

    /**
     * Initialize Ghidra in headless mode using the installation directory.
     */
    public void initialize() throws Exception {
        if (initialized) return;

        if (!Application.isInitialized()) {
            System.out.println("[Ghidra] Initializing from: " + GHIDRA_HOME);

            File ghidraInstallDir = new File(GHIDRA_HOME);
            if (!ghidraInstallDir.exists()) {
                throw new RuntimeException("Ghidra installation not found at: " + GHIDRA_HOME);
            }

            // Use GhidraApplicationLayout with the installation directory
            GhidraApplicationLayout layout = new GhidraApplicationLayout(ghidraInstallDir);
            ApplicationConfiguration config = new HeadlessGhidraApplicationConfiguration();
            Application.initializeApplication(layout, config);

            System.out.println("[Ghidra] Application initialized successfully");
        }

        projectDir.mkdirs();
        initialized = true;
        System.out.println("[Ghidra] Ready for analysis");
    }

    /**
     * Analyze a binary file (DEX or native library) and extract comprehensive information.
     * @param decompile If true, decompile functions to C pseudocode (slower but more detailed)
     */
    public AnalysisResult analyzeFile(File binaryFile, boolean decompile) throws Exception {
        initialize();

        System.out.println("[Ghidra] Analyzing: " + binaryFile.getName() +
                         " (" + formatSize(binaryFile.length()) + ")" +
                         (decompile ? " [with decompilation]" : ""));

        AnalysisResult result = new AnalysisResult();
        result.fileName = binaryFile.getName();
        result.fileSize = binaryFile.length();

        GhidraProject project = null;
        DecompInterface decompiler = null;
        try {
            // Create a temporary project
            String projectPath = projectDir.getAbsolutePath();
            String projectName = "Analysis_" + System.currentTimeMillis();

            System.out.println("[Ghidra] Creating project: " + projectName);
            project = GhidraProject.createProject(projectPath, projectName, true);

            // Import the binary file
            System.out.println("[Ghidra] Importing file...");
            Program program = project.importProgram(binaryFile);

            if (program == null) {
                result.errors.add("Failed to import file: " + binaryFile.getName());
                return result;
            }

            System.out.println("[Ghidra] Running auto-analysis...");
            // Run auto-analysis
            project.analyze(program, true);

            System.out.println("[Ghidra] Extracting analysis data...");

            // Get program info
            result.programName = program.getName();
            result.languageId = program.getLanguageID().getIdAsString();
            result.compilerSpec = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
            result.imageBase = program.getImageBase().toString();

            // Initialize decompiler if requested
            if (decompile) {
                System.out.println("[Ghidra] Initializing decompiler...");
                decompiler = new DecompInterface();
                decompiler.openProgram(program);
            }

            // Get all functions
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            int funcCount = 0;
            int decompiled = 0;
            while (functions.hasNext()) {
                Function func = functions.next();
                FunctionInfo funcInfo = new FunctionInfo();
                funcInfo.name = func.getName();
                funcInfo.address = func.getEntryPoint().toString();
                funcInfo.signature = func.getSignature().getPrototypeString();
                funcInfo.callingConvention = func.getCallingConventionName();
                funcInfo.parameterCount = func.getParameterCount();
                funcInfo.isThunk = func.isThunk();
                funcInfo.isExternal = func.isExternal();
                funcInfo.bodySize = func.getBody().getNumAddresses();

                // Check if function is an export
                Symbol[] symbols = program.getSymbolTable().getSymbols(func.getEntryPoint());
                for (Symbol sym : symbols) {
                    if (sym.isExternalEntryPoint()) {
                        funcInfo.isExport = true;
                        break;
                    }
                }

                // Extract diffing features (hashes) for non-external functions
                if (!func.isExternal() && func.getBody().getNumAddresses() > 0) {
                    extractDiffingFeatures(func, funcInfo, program);
                }

                // Decompile function if requested and not external/thunk
                if (decompile && !func.isExternal() && !func.isThunk() && func.getBody().getNumAddresses() > 0) {
                    try {
                        DecompileResults results = decompiler.decompileFunction(func, 30, TaskMonitor.DUMMY);
                        if (results != null && results.decompileCompleted()) {
                            String code = results.getDecompiledFunction().getC();
                            if (code != null && !code.isEmpty()) {
                                funcInfo.decompiledCode = code;
                                decompiled++;
                            }
                        }
                    } catch (Exception e) {
                        // Decompilation failed for this function, continue
                    }
                }

                // Get called functions (limit to avoid memory issues)
                try {
                    Set<Function> called = func.getCalledFunctions(TaskMonitor.DUMMY);
                    for (Function calledFunc : called) {
                        if (funcInfo.calledFunctions.size() < 50) {
                            funcInfo.calledFunctions.add(calledFunc.getName());
                        }
                    }
                } catch (Exception e) {
                    // Ignore call analysis errors
                }

                result.functions.add(funcInfo);
                funcCount++;

                // Progress logging
                if (funcCount % 500 == 0) {
                    System.out.println("[Ghidra] Processed " + funcCount + " functions" +
                        (decompile ? " (" + decompiled + " decompiled)" : "") + "...");
                }
            }

            if (decompile) {
                System.out.println("[Ghidra] Decompiled " + decompiled + " of " + funcCount + " functions");
            }

            // Get all defined strings
            DataIterator dataIter = program.getListing().getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                DataType dt = data.getDataType();
                if (dt != null) {
                    String typeName = dt.getName().toLowerCase();
                    if (typeName.contains("string") || typeName.equals("char[]")) {
                        Object value = data.getValue();
                        if (value != null) {
                            String str = value.toString();
                            // Filter out very short or very long strings
                            if (str.length() >= 4 && str.length() <= 500) {
                                result.strings.add(str);
                            }
                        }
                    }
                }

                // Limit strings to avoid memory issues
                if (result.strings.size() >= 5000) break;
            }

            // Get all imports/external references
            SymbolTable symTable = program.getSymbolTable();
            SymbolIterator extSymbols = symTable.getExternalSymbols();
            while (extSymbols.hasNext()) {
                Symbol sym = extSymbols.next();
                result.imports.add(sym.getName());
            }

            // Get exports
            SymbolIterator allSymbols = symTable.getAllSymbols(true);
            while (allSymbols.hasNext()) {
                Symbol sym = allSymbols.next();
                if (sym.isExternalEntryPoint()) {
                    result.exports.add(sym.getName());
                }
            }

            // Get memory sections
            Memory memory = program.getMemory();
            for (MemoryBlock block : memory.getBlocks()) {
                MemorySection section = new MemorySection();
                section.name = block.getName();
                section.start = block.getStart().toString();
                section.end = block.getEnd().toString();
                section.size = block.getSize();
                section.isRead = block.isRead();
                section.isWrite = block.isWrite();
                section.isExecute = block.isExecute();
                section.isInitialized = block.isInitialized();
                result.memorySections.add(section);
            }

            // Get data types (structures)
            DataTypeManager dtm = program.getDataTypeManager();
            Iterator<DataType> dtIter = dtm.getAllDataTypes();
            int structCount = 0;
            while (dtIter.hasNext() && structCount < 500) {
                DataType dt = dtIter.next();
                if (dt instanceof Structure) {
                    Structure struct = (Structure) dt;
                    StructureInfo structInfo = new StructureInfo();
                    structInfo.name = struct.getName();
                    structInfo.size = struct.getLength();
                    structInfo.fieldCount = struct.getNumComponents();
                    result.structures.add(structInfo);
                    structCount++;
                }
            }

            result.success = true;
            System.out.println("[Ghidra] Analysis complete: " + result.functions.size() + " functions, " +
                             result.strings.size() + " strings, " + result.imports.size() + " imports");

        } catch (Exception e) {
            result.errors.add("Analysis error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (decompiler != null) {
                try {
                    decompiler.dispose();
                } catch (Exception e) {
                    // Ignore close errors
                }
            }
            if (project != null) {
                try {
                    project.close();
                } catch (Exception e) {
                    // Ignore close errors
                }
            }
        }

        return result;
    }

    /**
     * Analyze a binary file without decompilation (faster).
     */
    public AnalysisResult analyzeFile(File binaryFile) throws Exception {
        return analyzeFile(binaryFile, false);
    }

    /**
     * Save decompiled functions to individual files.
     * @param result The analysis result with decompiled code
     * @param outputDir Directory to save decompiled files
     * @param libName Name of the library (for path construction)
     * @return Number of files saved
     */
    public int saveDecompiledFunctions(AnalysisResult result, File outputDir, String libName) throws Exception {
        // Create directory structure: decompiled/{libName}/
        File decompDir = new File(outputDir, "decompiled/" + libName);
        decompDir.mkdirs();

        int saved = 0;
        for (FunctionInfo func : result.functions) {
            if (func.decompiledCode != null && !func.decompiledCode.isEmpty()) {
                // Sanitize function name for filename
                String safeName = sanitizeFileName(func.name);
                String fileName = safeName + "_" + func.address.replace(":", "_") + ".c";
                File funcFile = new File(decompDir, fileName);

                try (PrintWriter writer = new PrintWriter(new FileWriter(funcFile))) {
                    // Write header comment
                    writer.println("/*");
                    writer.println(" * Function: " + func.name);
                    writer.println(" * Address:  " + func.address);
                    writer.println(" * Signature: " + func.signature);
                    writer.println(" * Size: " + func.bodySize + " bytes");
                    if (!func.calledFunctions.isEmpty()) {
                        writer.println(" * Calls: " + String.join(", ", func.calledFunctions));
                    }
                    writer.println(" */");
                    writer.println();
                    writer.println(func.decompiledCode);
                }

                // Store relative path
                func.decompiledPath = "decompiled/" + libName + "/" + fileName;
                saved++;
            }
        }

        if (saved > 0) {
            System.out.println("[Ghidra] Saved " + saved + " decompiled functions to " + decompDir.getAbsolutePath());
        }

        return saved;
    }

    /**
     * Sanitize a function name for use as a filename.
     */
    private String sanitizeFileName(String name) {
        // Replace characters that are invalid in filenames
        String safe = name.replaceAll("[<>:\"/\\\\|?*]", "_");
        // Limit length
        if (safe.length() > 100) {
            safe = safe.substring(0, 100);
        }
        return safe;
    }

    /**
     * Generate a comprehensive report from analysis results.
     */
    public void generateReport(AnalysisResult result, File reportFile) throws Exception {
        try (PrintWriter writer = new PrintWriter(new FileWriter(reportFile))) {
            writer.println("=".repeat(80));
            writer.println("GHIDRA BINARY ANALYSIS REPORT");
            writer.println("=".repeat(80));
            writer.println("File: " + result.fileName);
            writer.println("Size: " + formatSize(result.fileSize));
            writer.println("Analysis Date: " + new java.util.Date());
            writer.println();

            if (result.programName != null) {
                writer.println("-".repeat(80));
                writer.println("PROGRAM INFO");
                writer.println("-".repeat(80));
                writer.println("  Program Name: " + result.programName);
                writer.println("  Language: " + result.languageId);
                writer.println("  Compiler: " + result.compilerSpec);
                writer.println("  Image Base: " + result.imageBase);
                writer.println();
            }

            writer.println("-".repeat(80));
            writer.println("MEMORY SECTIONS (" + result.memorySections.size() + ")");
            writer.println("-".repeat(80));
            for (MemorySection section : result.memorySections) {
                writer.printf("  %-20s %s - %s (size: %s) [%s%s%s%s]%n",
                    section.name, section.start, section.end, formatSize(section.size),
                    section.isRead ? "R" : "-",
                    section.isWrite ? "W" : "-",
                    section.isExecute ? "X" : "-",
                    section.isInitialized ? "I" : "-");
            }
            writer.println();

            writer.println("-".repeat(80));
            writer.println("FUNCTIONS (" + result.functions.size() + ")");
            writer.println("-".repeat(80));
            int shown = 0;
            for (FunctionInfo func : result.functions) {
                if (shown++ < 100) {
                    writer.printf("  [%s] %s%s%n",
                        func.address,
                        func.signature,
                        func.isExternal ? " [EXTERNAL]" : "");
                    if (!func.calledFunctions.isEmpty()) {
                        writer.println("    Calls: " + String.join(", ",
                            func.calledFunctions.stream().limit(5).toList()));
                    }
                }
            }
            if (result.functions.size() > 100) {
                writer.println("  ... and " + (result.functions.size() - 100) + " more functions");
            }
            writer.println();

            writer.println("-".repeat(80));
            writer.println("IMPORTS (" + result.imports.size() + ")");
            writer.println("-".repeat(80));
            for (String imp : result.imports.stream().limit(100).toList()) {
                writer.println("  " + imp);
            }
            if (result.imports.size() > 100) {
                writer.println("  ... and " + (result.imports.size() - 100) + " more");
            }
            writer.println();

            if (!result.exports.isEmpty()) {
                writer.println("-".repeat(80));
                writer.println("EXPORTS (" + result.exports.size() + ")");
                writer.println("-".repeat(80));
                for (String exp : result.exports.stream().limit(50).toList()) {
                    writer.println("  " + exp);
                }
                writer.println();
            }

            if (!result.structures.isEmpty()) {
                writer.println("-".repeat(80));
                writer.println("STRUCTURES (" + result.structures.size() + ")");
                writer.println("-".repeat(80));
                for (StructureInfo struct : result.structures.stream().limit(50).toList()) {
                    writer.printf("  %-40s size: %d, fields: %d%n",
                        struct.name, struct.size, struct.fieldCount);
                }
                writer.println();
            }

            writer.println("-".repeat(80));
            writer.println("STRINGS (first 100 of " + result.strings.size() + ")");
            writer.println("-".repeat(80));
            for (String str : result.strings.stream().limit(100).toList()) {
                String display = str.length() > 80 ? str.substring(0, 80) + "..." : str;
                writer.println("  " + display.replace("\n", "\\n").replace("\r", "\\r"));
            }

            if (!result.errors.isEmpty()) {
                writer.println();
                writer.println("-".repeat(80));
                writer.println("ERRORS");
                writer.println("-".repeat(80));
                for (String error : result.errors) {
                    writer.println("  " + error);
                }
            }
        }

        System.out.println("[Ghidra] Report written to: " + reportFile.getAbsolutePath());
    }

    private String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
    }

    // =========================================================================
    // Hashing and Diffing Feature Extraction
    // =========================================================================

    // First 200 primes for BinDiff-style prime product hashing
    private static final int[] PRIMES = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
        73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
        157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
        239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
        331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
        421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
        509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
        613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
        709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
        821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
        919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019,
        1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097,
        1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201
    };

    // Mnemonic to prime index mapping (built on first encounter)
    private static final Map<String, Integer> MNEMONIC_PRIME_INDEX = new HashMap<>();
    private static int nextPrimeIndex = 0;

    // KGH primes for Diaphora-style graph hash
    private static final Map<String, Integer> KGH_PRIMES = Map.of(
        "NODE_ENTRY", 2,
        "NODE_EXIT", 3,
        "NODE_NORMAL", 5,
        "EDGE_CONDITIONAL", 7,
        "EDGE_UNCONDITIONAL", 11,
        "FEATURE_LOOP", 13,
        "FEATURE_CALL", 17,
        "FEATURE_DATA_REF", 19,
        "FEATURE_STRING_REF", 23,
        "FEATURE_IMPORT_CALL", 29
    );

    /**
     * Get prime number for a mnemonic (BinDiff-style mapping).
     */
    private static synchronized int getMnemonicPrime(String mnemonic) {
        String normalized = mnemonic.toLowerCase();
        if (!MNEMONIC_PRIME_INDEX.containsKey(normalized)) {
            MNEMONIC_PRIME_INDEX.put(normalized, nextPrimeIndex % PRIMES.length);
            nextPrimeIndex++;
        }
        return PRIMES[MNEMONIC_PRIME_INDEX.get(normalized)];
    }

    /**
     * Extract diffing features for a function using Ghidra's API.
     */
    private void extractDiffingFeatures(Function func, FunctionInfo funcInfo, Program program) {
        try {
            Listing listing = program.getListing();
            AddressSetView body = func.getBody();

            // Extract instruction features
            extractInstructionFeatures(listing, body, funcInfo);

            // Extract import calls (calls to external/thunk functions)
            extractImportCalls(func, funcInfo);

            // Extract string references
            extractStringRefs(listing, body, funcInfo, program);

            // Extract CFG features (basic blocks, edges, complexity)
            extractCfgFeatures(func, funcInfo, program);

            // Compute hashes
            computeHashes(funcInfo);

        } catch (Exception e) {
            // Don't fail analysis for hash extraction errors
            System.err.println("[Ghidra] Warning: Could not extract diffing features for " + func.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Extract instruction-level features: mnemonic sequence, histogram, counts.
     */
    private void extractInstructionFeatures(Listing listing, AddressSetView body, FunctionInfo funcInfo) {
        try {
            InstructionIterator instructions = listing.getInstructions(body, true);
            while (instructions.hasNext()) {
                Instruction insn = instructions.next();
                String mnemonic = insn.getMnemonicString();

                funcInfo.mnemonics.add(mnemonic);
                funcInfo.mnemonicHistogram.merge(mnemonic, 1, Integer::sum);
                funcInfo.instructionCount++;
            }
        } catch (Exception e) {
            // Ignore instruction extraction errors
        }
    }

    /**
     * Extract import calls (external/thunk function calls).
     */
    private void extractImportCalls(Function func, FunctionInfo funcInfo) {
        try {
            Set<Function> calledFuncs = func.getCalledFunctions(TaskMonitor.DUMMY);
            Set<String> importSet = new TreeSet<>(); // TreeSet for sorted order

            for (Function callee : calledFuncs) {
                funcInfo.calleeCount++;
                if (callee.isExternal() || callee.isThunk()) {
                    importSet.add(callee.getName());
                    funcInfo.externalCallCount++;
                }
            }

            funcInfo.importCalls = new ArrayList<>(importSet);
        } catch (Exception e) {
            // Ignore call extraction errors
        }
    }

    /**
     * Extract string references from the function body.
     */
    private void extractStringRefs(Listing listing, AddressSetView body, FunctionInfo funcInfo, Program program) {
        try {
            Set<String> stringSet = new TreeSet<>(); // TreeSet for sorted order
            ReferenceManager refMgr = program.getReferenceManager();

            InstructionIterator instructions = listing.getInstructions(body, true);
            while (instructions.hasNext()) {
                Instruction insn = instructions.next();
                Reference[] refs = insn.getReferencesFrom();

                for (Reference ref : refs) {
                    if (ref.getReferenceType().isData()) {
                        Address toAddr = ref.getToAddress();
                        Data data = listing.getDataAt(toAddr);

                        if (data != null && data.getValue() != null) {
                            String typeName = data.getDataType().getName().toLowerCase();
                            if (typeName.contains("string") || typeName.equals("char[]")) {
                                String str = data.getValue().toString();
                                if (str.length() >= 2 && str.length() <= 200) {
                                    stringSet.add(str);
                                }
                            }
                        }
                    }
                }

                if (stringSet.size() >= 100) break; // Limit to avoid memory issues
            }

            funcInfo.stringRefs = new ArrayList<>(stringSet);
        } catch (Exception e) {
            // Ignore string extraction errors
        }
    }

    /**
     * Extract CFG features: basic block count, edge count, cyclomatic complexity.
     */
    private void extractCfgFeatures(Function func, FunctionInfo funcInfo, Program program) {
        try {
            BasicBlockModel blockModel = new BasicBlockModel(program);
            CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY);

            int blockCount = 0;
            int edgeCount = 0;
            List<CfgBlock> cfgBlocks = new ArrayList<>();

            while (blocks.hasNext()) {
                CodeBlock block = blocks.next();
                blockCount++;

                // Count instructions in this block
                int blockInsnCount = 0;
                InstructionIterator blockInsns = program.getListing().getInstructions(block, true);
                while (blockInsns.hasNext()) {
                    blockInsns.next();
                    blockInsnCount++;
                }

                // Get successors
                List<Integer> successorIndices = new ArrayList<>();
                CodeBlockReferenceIterator dests = block.getDestinations(TaskMonitor.DUMMY);
                while (dests.hasNext()) {
                    CodeBlockReference destRef = dests.next();
                    edgeCount++;
                    // We'll fill in successor indices in a second pass
                    successorIndices.add(-1); // placeholder
                }

                cfgBlocks.add(new CfgBlock(blockInsnCount, successorIndices, block));
            }

            funcInfo.basicBlockCount = blockCount;
            funcInfo.edgeCount = edgeCount;

            // Cyclomatic complexity = E - N + 2
            funcInfo.cyclomaticComplexity = edgeCount - blockCount + 2;

            // Compute CFG hash (simplified: block_count:edge_count:insn_counts)
            if (!cfgBlocks.isEmpty()) {
                funcInfo.cfgHash = computeCfgHash(cfgBlocks);
            }

        } catch (Exception e) {
            // Ignore CFG extraction errors
        }
    }

    // Helper class for CFG blocks
    private static class CfgBlock {
        int instructionCount;
        List<Integer> successorIndices;
        CodeBlock block;

        CfgBlock(int instructionCount, List<Integer> successorIndices, CodeBlock block) {
            this.instructionCount = instructionCount;
            this.successorIndices = successorIndices;
            this.block = block;
        }
    }

    /**
     * Compute CFG hash based on structure.
     */
    private String computeCfgHash(List<CfgBlock> blocks) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < blocks.size(); i++) {
            CfgBlock block = blocks.get(i);
            sb.append(block.instructionCount);
            sb.append(":");
            sb.append(block.successorIndices.size());
            if (i < blocks.size() - 1) {
                sb.append(";");
            }
        }
        return sha256(sb.toString());
    }

    /**
     * Compute all hashes for the function.
     */
    private void computeHashes(FunctionInfo funcInfo) {
        // Mnemonic hash: SHA256 of mnemonic sequence
        if (!funcInfo.mnemonics.isEmpty()) {
            funcInfo.mnemonicHash = sha256(String.join(";", funcInfo.mnemonics));
        }

        // Import call hash: SHA256 of sorted import calls
        if (!funcInfo.importCalls.isEmpty()) {
            funcInfo.importCallHash = sha256(String.join(",", funcInfo.importCalls));
        }

        // String refs hash: SHA256 of sorted string references
        if (!funcInfo.stringRefs.isEmpty()) {
            funcInfo.stringRefsHash = sha256(String.join(",", funcInfo.stringRefs));
        }

        // Prime product: BinDiff-style order-independent hash
        computePrimeProduct(funcInfo);

        // KGH hash: Diaphora-style graph hash
        computeKghHash(funcInfo);
    }

    /**
     * Compute BinDiff-style prime product from mnemonic histogram.
     * Order-independent fingerprint.
     */
    private void computePrimeProduct(FunctionInfo funcInfo) {
        if (funcInfo.mnemonicHistogram.isEmpty()) return;

        try {
            BigInteger product = BigInteger.ONE;

            for (Map.Entry<String, Integer> entry : funcInfo.mnemonicHistogram.entrySet()) {
                int prime = getMnemonicPrime(entry.getKey());
                int count = entry.getValue();

                // product *= prime^count
                BigInteger primeBig = BigInteger.valueOf(prime);
                product = product.multiply(primeBig.pow(count));
            }

            // Store as hex string (can be very large)
            funcInfo.primeProduct = product.toString(16);
        } catch (Exception e) {
            // Ignore prime product errors
        }
    }

    /**
     * Compute Diaphora-style KGH (Koret-Karamitas Graph Hash).
     * Uses primes for structural/semantic features.
     */
    private void computeKghHash(FunctionInfo funcInfo) {
        try {
            BigInteger product = BigInteger.ONE;

            // Node features
            if (funcInfo.basicBlockCount > 0) {
                // Entry node
                product = product.multiply(BigInteger.valueOf(KGH_PRIMES.get("NODE_ENTRY")));

                // Normal nodes
                int normalNodes = Math.max(0, funcInfo.basicBlockCount - 2); // Exclude entry/exit
                if (normalNodes > 0) {
                    product = product.multiply(
                        BigInteger.valueOf(KGH_PRIMES.get("NODE_NORMAL")).pow(normalNodes)
                    );
                }

                // Exit node
                product = product.multiply(BigInteger.valueOf(KGH_PRIMES.get("NODE_EXIT")));
            }

            // Edge features based on edge count vs node count
            int conditionalEdges = Math.max(0, funcInfo.edgeCount - funcInfo.basicBlockCount);
            int unconditionalEdges = Math.min(funcInfo.edgeCount, funcInfo.basicBlockCount);

            if (conditionalEdges > 0) {
                product = product.multiply(
                    BigInteger.valueOf(KGH_PRIMES.get("EDGE_CONDITIONAL")).pow(conditionalEdges)
                );
            }
            if (unconditionalEdges > 0) {
                product = product.multiply(
                    BigInteger.valueOf(KGH_PRIMES.get("EDGE_UNCONDITIONAL")).pow(unconditionalEdges)
                );
            }

            // Call features
            if (funcInfo.calleeCount > 0) {
                product = product.multiply(
                    BigInteger.valueOf(KGH_PRIMES.get("FEATURE_CALL")).pow(funcInfo.calleeCount)
                );
            }

            // Import call features
            if (funcInfo.externalCallCount > 0) {
                product = product.multiply(
                    BigInteger.valueOf(KGH_PRIMES.get("FEATURE_IMPORT_CALL")).pow(funcInfo.externalCallCount)
                );
            }

            // String reference features
            if (!funcInfo.stringRefs.isEmpty()) {
                product = product.multiply(
                    BigInteger.valueOf(KGH_PRIMES.get("FEATURE_STRING_REF")).pow(funcInfo.stringRefs.size())
                );
            }

            funcInfo.kghHash = product.toString(16);
        } catch (Exception e) {
            // Ignore KGH hash errors
        }
    }

    /**
     * Compute SHA256 hash of a string.
     */
    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Convert list to JSON array string.
     */
    public static String toJson(List<String> list) {
        if (list == null || list.isEmpty()) return null;
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(escapeJson(list.get(i))).append("\"");
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Convert map to JSON object string.
     */
    public static String toJson(Map<String, Integer> map) {
        if (map == null || map.isEmpty()) return null;
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Integer> entry : map.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(escapeJson(entry.getKey())).append("\":").append(entry.getValue());
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // =========================================================================
    // SQLite Export
    // =========================================================================

    /**
     * Export analysis results to SQLite database with full decompilation.
     * Creates a comprehensive database with all analysis data.
     * @param result The analysis result to export
     * @param dbPath Path for the SQLite database
     * @return Number of functions exported
     */
    public int saveToSqlite(AnalysisResult result, File dbPath) throws Exception {
        System.out.println("[Ghidra] Exporting to SQLite: " + dbPath.getAbsolutePath());

        // Delete existing database
        if (dbPath.exists()) {
            dbPath.delete();
        }

        dbPath.getParentFile().mkdirs();

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath.getAbsolutePath())) {
            conn.setAutoCommit(false);

            // Create tables
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("""
                    CREATE TABLE library_info (
                        id INTEGER PRIMARY KEY,
                        name TEXT,
                        file_size INTEGER,
                        architecture TEXT,
                        compiler TEXT,
                        image_base TEXT,
                        language TEXT,
                        analysis_date TEXT,
                        function_count INTEGER,
                        string_count INTEGER,
                        import_count INTEGER,
                        export_count INTEGER
                    )
                """);

                stmt.executeUpdate("""
                    CREATE TABLE functions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        address TEXT UNIQUE,
                        signature TEXT,
                        calling_convention TEXT,
                        parameter_count INTEGER,
                        body_size INTEGER,
                        is_thunk INTEGER,
                        is_external INTEGER,
                        is_export INTEGER,
                        instruction_count INTEGER,
                        basic_block_count INTEGER,
                        edge_count INTEGER,
                        cyclomatic_complexity INTEGER,
                        callee_count INTEGER,
                        external_call_count INTEGER,
                        mnemonic_hash TEXT,
                        import_call_hash TEXT,
                        string_refs_hash TEXT,
                        cfg_hash TEXT,
                        prime_product TEXT,
                        kgh_hash TEXT,
                        decompiled TEXT
                    )
                """);

                stmt.executeUpdate("""
                    CREATE TABLE strings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        value TEXT,
                        length INTEGER
                    )
                """);

                stmt.executeUpdate("""
                    CREATE TABLE imports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT
                    )
                """);

                stmt.executeUpdate("""
                    CREATE TABLE exports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT
                    )
                """);

                stmt.executeUpdate("""
                    CREATE TABLE memory_sections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        start_addr TEXT,
                        end_addr TEXT,
                        size INTEGER,
                        is_read INTEGER,
                        is_write INTEGER,
                        is_execute INTEGER,
                        is_initialized INTEGER
                    )
                """);

                stmt.executeUpdate("""
                    CREATE TABLE function_calls (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        caller_address TEXT,
                        callee_name TEXT
                    )
                """);

                stmt.executeUpdate("""
                    CREATE TABLE function_import_calls (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        function_address TEXT,
                        import_name TEXT
                    )
                """);

                stmt.executeUpdate("""
                    CREATE TABLE function_string_refs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        function_address TEXT,
                        string_value TEXT
                    )
                """);

                stmt.executeUpdate("""
                    CREATE TABLE structures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        size INTEGER,
                        field_count INTEGER
                    )
                """);

                // Create indexes
                stmt.executeUpdate("CREATE INDEX idx_functions_name ON functions(name)");
                stmt.executeUpdate("CREATE INDEX idx_functions_address ON functions(address)");
                stmt.executeUpdate("CREATE INDEX idx_functions_mnemonic_hash ON functions(mnemonic_hash)");
                stmt.executeUpdate("CREATE INDEX idx_functions_cfg_hash ON functions(cfg_hash)");
                stmt.executeUpdate("CREATE INDEX idx_strings_value ON strings(value)");
                stmt.executeUpdate("CREATE INDEX idx_imports_name ON imports(name)");
                stmt.executeUpdate("CREATE INDEX idx_exports_name ON exports(name)");
                stmt.executeUpdate("CREATE INDEX idx_function_calls_caller ON function_calls(caller_address)");
                stmt.executeUpdate("CREATE INDEX idx_function_import_calls ON function_import_calls(function_address)");
                stmt.executeUpdate("CREATE INDEX idx_function_string_refs ON function_string_refs(function_address)");
            }

            // Insert library info
            try (PreparedStatement ps = conn.prepareStatement("""
                INSERT INTO library_info (name, file_size, architecture, compiler, image_base, language,
                                          analysis_date, function_count, string_count, import_count, export_count)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?, ?, ?, ?)
            """)) {
                ps.setString(1, result.fileName);
                ps.setLong(2, result.fileSize);
                ps.setString(3, result.languageId);
                ps.setString(4, result.compilerSpec);
                ps.setString(5, result.imageBase);
                ps.setString(6, result.languageId);
                ps.setInt(7, result.functions.size());
                ps.setInt(8, result.strings.size());
                ps.setInt(9, result.imports.size());
                ps.setInt(10, result.exports.size());
                ps.executeUpdate();
            }

            // Insert functions
            int funcCount = 0;
            try (PreparedStatement ps = conn.prepareStatement("""
                INSERT INTO functions (name, address, signature, calling_convention, parameter_count, body_size,
                                       is_thunk, is_external, is_export, instruction_count, basic_block_count,
                                       edge_count, cyclomatic_complexity, callee_count, external_call_count,
                                       mnemonic_hash, import_call_hash, string_refs_hash, cfg_hash,
                                       prime_product, kgh_hash, decompiled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """)) {
                for (FunctionInfo func : result.functions) {
                    ps.setString(1, func.name);
                    ps.setString(2, func.address);
                    ps.setString(3, func.signature);
                    ps.setString(4, func.callingConvention);
                    ps.setInt(5, func.parameterCount);
                    ps.setLong(6, func.bodySize);
                    ps.setInt(7, func.isThunk ? 1 : 0);
                    ps.setInt(8, func.isExternal ? 1 : 0);
                    ps.setInt(9, func.isExport ? 1 : 0);
                    ps.setInt(10, func.instructionCount);
                    ps.setInt(11, func.basicBlockCount);
                    ps.setInt(12, func.edgeCount);
                    ps.setInt(13, func.cyclomaticComplexity);
                    ps.setInt(14, func.calleeCount);
                    ps.setInt(15, func.externalCallCount);
                    ps.setString(16, func.mnemonicHash);
                    ps.setString(17, func.importCallHash);
                    ps.setString(18, func.stringRefsHash);
                    ps.setString(19, func.cfgHash);
                    ps.setString(20, func.primeProduct);
                    ps.setString(21, func.kghHash);
                    ps.setString(22, func.decompiledCode);
                    ps.executeUpdate();
                    funcCount++;
                }
            }

            // Insert function calls
            try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO function_calls (caller_address, callee_name) VALUES (?, ?)")) {
                for (FunctionInfo func : result.functions) {
                    for (String callee : func.calledFunctions) {
                        ps.setString(1, func.address);
                        ps.setString(2, callee);
                        ps.executeUpdate();
                    }
                }
            }

            // Insert import calls per function
            try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO function_import_calls (function_address, import_name) VALUES (?, ?)")) {
                for (FunctionInfo func : result.functions) {
                    for (String imp : func.importCalls) {
                        ps.setString(1, func.address);
                        ps.setString(2, imp);
                        ps.executeUpdate();
                    }
                }
            }

            // Insert string refs per function
            try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO function_string_refs (function_address, string_value) VALUES (?, ?)")) {
                for (FunctionInfo func : result.functions) {
                    for (String str : func.stringRefs) {
                        ps.setString(1, func.address);
                        ps.setString(2, str);
                        ps.executeUpdate();
                    }
                }
            }

            // Insert strings
            try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO strings (value, length) VALUES (?, ?)")) {
                for (String str : result.strings) {
                    ps.setString(1, str);
                    ps.setInt(2, str.length());
                    ps.executeUpdate();
                }
            }

            // Insert imports
            try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO imports (name) VALUES (?)")) {
                for (String imp : result.imports) {
                    ps.setString(1, imp);
                    ps.executeUpdate();
                }
            }

            // Insert exports
            try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO exports (name) VALUES (?)")) {
                for (String exp : result.exports) {
                    ps.setString(1, exp);
                    ps.executeUpdate();
                }
            }

            // Insert memory sections
            try (PreparedStatement ps = conn.prepareStatement("""
                INSERT INTO memory_sections (name, start_addr, end_addr, size, is_read, is_write, is_execute, is_initialized)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """)) {
                for (MemorySection sec : result.memorySections) {
                    ps.setString(1, sec.name);
                    ps.setString(2, sec.start);
                    ps.setString(3, sec.end);
                    ps.setLong(4, sec.size);
                    ps.setInt(5, sec.isRead ? 1 : 0);
                    ps.setInt(6, sec.isWrite ? 1 : 0);
                    ps.setInt(7, sec.isExecute ? 1 : 0);
                    ps.setInt(8, sec.isInitialized ? 1 : 0);
                    ps.executeUpdate();
                }
            }

            // Insert structures
            try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO structures (name, size, field_count) VALUES (?, ?, ?)")) {
                for (StructureInfo struct : result.structures) {
                    ps.setString(1, struct.name);
                    ps.setInt(2, struct.size);
                    ps.setInt(3, struct.fieldCount);
                    ps.executeUpdate();
                }
            }

            conn.commit();

            System.out.println("[Ghidra] SQLite export complete: " + funcCount + " functions, " +
                             result.strings.size() + " strings, " + dbPath.length() + " bytes");
            return funcCount;
        }
    }

    /**
     * Full analysis pipeline: analyze binary with decompilation and export to SQLite.
     * @param binaryFile The .so file to analyze
     * @param outputDir Directory for SQLite output
     * @return Path to the created SQLite database
     */
    public File analyzeAndExport(File binaryFile, File outputDir) throws Exception {
        // Run analysis with decompilation
        AnalysisResult result = analyzeFile(binaryFile, true);

        if (!result.success) {
            throw new Exception("Analysis failed: " + String.join(", ", result.errors));
        }

        // Create SQLite database
        String libName = binaryFile.getName().replace(".so", "");
        File dbFile = new File(outputDir, libName + ".db");
        saveToSqlite(result, dbFile);

        // Save decompiled functions to files
        saveDecompiledFunctions(result, outputDir, libName);

        return dbFile;
    }

    // Data classes for analysis results
    public static class AnalysisResult {
        public String fileName;
        public long fileSize;
        public boolean success = false;

        public String programName;
        public String languageId;
        public String compilerSpec;
        public String imageBase;

        public List<FunctionInfo> functions = new ArrayList<>();
        public List<String> strings = new ArrayList<>();
        public List<String> imports = new ArrayList<>();
        public List<String> exports = new ArrayList<>();
        public List<MemorySection> memorySections = new ArrayList<>();
        public List<StructureInfo> structures = new ArrayList<>();
        public List<String> errors = new ArrayList<>();
    }

    public static class FunctionInfo {
        public String name;
        public String address;
        public String signature;
        public String callingConvention;
        public int parameterCount;
        public boolean isThunk;
        public boolean isExternal;
        public long bodySize;
        public List<String> calledFunctions = new ArrayList<>();
        public String decompiledCode;  // The actual decompiled C pseudocode
        public String decompiledPath;  // Relative path to saved file

        // DIFFING FEATURES (for version comparison)
        public int instructionCount = 0;
        public int basicBlockCount = 0;
        public int edgeCount = 0;
        public int cyclomaticComplexity = 0;   // edges - nodes + 2
        public int calleeCount = 0;            // Total calls made
        public int externalCallCount = 0;      // Calls to imports/external

        // Import calls (external functions called - stable across versions)
        public List<String> importCalls = new ArrayList<>();
        public String importCallHash;          // SHA256 of sorted import calls

        // String references (strings referenced by this function)
        public List<String> stringRefs = new ArrayList<>();
        public String stringRefsHash;          // SHA256 of sorted string refs

        // Instruction features
        public List<String> mnemonics = new ArrayList<>();
        public String mnemonicHash;            // SHA256 of mnemonic sequence
        public Map<String, Integer> mnemonicHistogram = new HashMap<>();

        // Structural hashes
        public String cfgHash;                 // Graph structure hash
        public String primeProduct;            // BinDiff-style prime product
        public String kghHash;                 // Diaphora KOKA graph hash

        // Flags
        public boolean isExport = false;
        public boolean hasNoReturn = false;
    }

    public static class MemorySection {
        public String name;
        public String start;
        public String end;
        public long size;
        public boolean isRead;
        public boolean isWrite;
        public boolean isExecute;
        public boolean isInitialized;
    }

    public static class StructureInfo {
        public String name;
        public int size;
        public int fieldCount;
    }
}
