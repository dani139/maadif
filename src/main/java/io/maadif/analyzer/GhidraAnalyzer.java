package io.maadif.analyzer;

import ghidra.GhidraJarApplicationLayout;
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
 * Ghidra-based binary analyzer for DEX files extracted from APKs.
 * Uses Ghidra's headless API to perform deep binary analysis.
 */
public class GhidraAnalyzer {

    private File projectDir;
    private File outputDir;
    private boolean initialized = false;

    public GhidraAnalyzer(File outputDir) {
        this.outputDir = outputDir;
        this.projectDir = new File(outputDir, "ghidra_project");
    }

    /**
     * Initialize Ghidra in headless mode.
     */
    public void initialize() throws Exception {
        if (initialized) return;

        if (!Application.isInitialized()) {
            ApplicationConfiguration config = new HeadlessGhidraApplicationConfiguration();
            Application.initializeApplication(new GhidraJarApplicationLayout(), config);
        }

        projectDir.mkdirs();
        initialized = true;
        System.out.println("[Ghidra] Initialized headless Ghidra");
    }

    /**
     * Analyze a DEX file and extract comprehensive information.
     */
    public AnalysisResult analyzeDexFile(File dexFile) throws Exception {
        initialize();

        System.out.println("[Ghidra] Analyzing: " + dexFile.getName());

        AnalysisResult result = new AnalysisResult();
        result.fileName = dexFile.getName();

        GhidraProject project = null;
        try {
            // Create a temporary project
            String projectPath = projectDir.getAbsolutePath();
            String projectName = "APKAnalysis_" + System.currentTimeMillis();
            project = GhidraProject.createProject(projectPath, projectName, true);

            // Import the DEX file
            Program program = project.importProgram(dexFile);

            if (program == null) {
                result.errors.add("Failed to import file: " + dexFile.getName());
                return result;
            }

            // Run auto-analysis
            project.analyze(program, true);

            // Get all functions
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function func = functions.next();
                FunctionInfo funcInfo = new FunctionInfo();
                funcInfo.name = func.getName();
                funcInfo.address = func.getEntryPoint().toString();
                funcInfo.signature = func.getSignature().getPrototypeString();
                funcInfo.callingConvention = func.getCallingConventionName();
                funcInfo.parameterCount = func.getParameterCount();
                funcInfo.isThunk = func.isThunk();

                // Get called functions
                try {
                    for (Function calledFunc : func.getCalledFunctions(TaskMonitor.DUMMY)) {
                        funcInfo.calledFunctions.add(calledFunc.getName());
                    }
                } catch (Exception e) {
                    // Ignore call analysis errors
                }

                // Get calling functions
                try {
                    for (Function callingFunc : func.getCallingFunctions(TaskMonitor.DUMMY)) {
                        funcInfo.callingFunctions.add(callingFunc.getName());
                    }
                } catch (Exception e) {
                    // Ignore call analysis errors
                }

                result.functions.add(funcInfo);
            }

            // Get all strings
            DataIterator dataIter = program.getListing().getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                DataType dt = data.getDataType();
                if (dt instanceof StringDataType ||
                    (dt != null && dt.getName().toLowerCase().contains("string"))) {
                    Object value = data.getValue();
                    if (value != null) {
                        result.strings.add(value.toString());
                    }
                }
            }

            // Get all imports/external references
            SymbolTable symTable = program.getSymbolTable();
            SymbolIterator extSymbols = symTable.getExternalSymbols();
            while (extSymbols.hasNext()) {
                Symbol sym = extSymbols.next();
                result.imports.add(sym.getName());
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
                result.memorySections.add(section);
            }

            // Get data types (structures)
            DataTypeManager dtm = program.getDataTypeManager();
            Iterator<DataType> dtIter = dtm.getAllDataTypes();
            while (dtIter.hasNext()) {
                DataType dt = dtIter.next();
                if (dt instanceof Structure) {
                    result.structures.add(dt.getName() + ": " + dt.getDescription());
                }
            }

            result.success = true;

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
            writer.println("=" .repeat(80));
            writer.println("GHIDRA ANALYSIS REPORT");
            writer.println("=" .repeat(80));
            writer.println("File: " + result.fileName);
            writer.println("Analysis Date: " + new Date());
            writer.println();

            writer.println("-".repeat(80));
            writer.println("MEMORY SECTIONS (" + result.memorySections.size() + ")");
            writer.println("-".repeat(80));
            for (MemorySection section : result.memorySections) {
                writer.printf("  %-20s %s - %s (size: %d) [%s%s%s]%n",
                    section.name, section.start, section.end, section.size,
                    section.isRead ? "R" : "-",
                    section.isWrite ? "W" : "-",
                    section.isExecute ? "X" : "-");
            }
            writer.println();

            writer.println("-".repeat(80));
            writer.println("FUNCTIONS (" + result.functions.size() + ")");
            writer.println("-".repeat(80));
            for (FunctionInfo func : result.functions) {
                writer.printf("  [%s] %s%n", func.address, func.signature);
                if (!func.calledFunctions.isEmpty()) {
                    writer.println("    Calls: " + String.join(", ", func.calledFunctions.stream().limit(5).toList()));
                }
            }
            writer.println();

            writer.println("-".repeat(80));
            writer.println("IMPORTS (" + result.imports.size() + ")");
            writer.println("-".repeat(80));
            for (String imp : result.imports.stream().limit(100).toList()) {
                writer.println("  " + imp);
            }
            writer.println();

            writer.println("-".repeat(80));
            writer.println("STRINGS (first 100 of " + result.strings.size() + ")");
            writer.println("-".repeat(80));
            for (String str : result.strings.stream().limit(100).toList()) {
                if (str.length() > 100) {
                    str = str.substring(0, 100) + "...";
                }
                writer.println("  " + str.replace("\n", "\\n"));
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

    // Data classes for analysis results
    public static class AnalysisResult {
        public String fileName;
        public boolean success = false;
        public List<FunctionInfo> functions = new ArrayList<>();
        public List<String> strings = new ArrayList<>();
        public List<String> imports = new ArrayList<>();
        public List<MemorySection> memorySections = new ArrayList<>();
        public List<String> structures = new ArrayList<>();
        public List<String> errors = new ArrayList<>();
    }

    public static class FunctionInfo {
        public String name;
        public String address;
        public String signature;
        public String callingConvention;
        public int parameterCount;
        public boolean isThunk;
        public List<String> calledFunctions = new ArrayList<>();
        public List<String> callingFunctions = new ArrayList<>();
    }

    public static class MemorySection {
        public String name;
        public String start;
        public String end;
        public long size;
        public boolean isRead;
        public boolean isWrite;
        public boolean isExecute;
    }
}
