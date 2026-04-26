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
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
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
     */
    public AnalysisResult analyzeFile(File binaryFile) throws Exception {
        initialize();

        System.out.println("[Ghidra] Analyzing: " + binaryFile.getName() +
                         " (" + formatSize(binaryFile.length()) + ")");

        AnalysisResult result = new AnalysisResult();
        result.fileName = binaryFile.getName();
        result.fileSize = binaryFile.length();

        GhidraProject project = null;
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

            // Get all functions
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            int funcCount = 0;
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
                if (funcCount % 1000 == 0) {
                    System.out.println("[Ghidra] Processed " + funcCount + " functions...");
                }
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
     * Generate a comprehensive report from analysis results.
     */
    public void generateReport(AnalysisResult result, File reportFile) throws Exception {
        try (PrintWriter writer = new PrintWriter(new FileWriter(reportFile))) {
            writer.println("=".repeat(80));
            writer.println("GHIDRA BINARY ANALYSIS REPORT");
            writer.println("=".repeat(80));
            writer.println("File: " + result.fileName);
            writer.println("Size: " + formatSize(result.fileSize));
            writer.println("Analysis Date: " + new Date());
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
