// Ghidra Script: ExportToJson.java
// Full analysis export to JSON: functions, decompiled code, strings, imports, exports
// Usage: analyzeHeadless ... -postScript ExportToJson.java /output/dir
//
// @category Analysis
// @author maadif

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportToJson extends GhidraScript {

    private PrintWriter jsonWriter;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputDir = args.length > 0 ? args[0] : "/tmp/ghidra_export";

        File outDir = new File(outputDir);
        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        String programName = currentProgram.getName();
        String libName = programName.replace(".so", "");
        File jsonFile = new File(outDir, libName + ".json");

        println("[Export] Starting full analysis export for: " + programName);
        println("[Export] Output: " + jsonFile.getAbsolutePath());

        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(jsonFile)))) {
            jsonWriter = pw;

            jsonWriter.println("{");

            // Library info
            writeLibraryInfo();
            jsonWriter.println(",");

            // Functions with decompilation
            int funcCount = writeFunctions();
            jsonWriter.println(",");

            // Strings
            int stringCount = writeStrings();
            jsonWriter.println(",");

            // Imports
            int importCount = writeImports();
            jsonWriter.println(",");

            // Exports
            int exportCount = writeExports();
            jsonWriter.println(",");

            // Memory sections
            writeMemorySections();

            jsonWriter.println("}");

            println("[Export] Complete: " + funcCount + " functions, " + stringCount + " strings, " +
                    importCount + " imports, " + exportCount + " exports");
            println("[Export] JSON: " + jsonFile.getAbsolutePath() + " (" + jsonFile.length() + " bytes)");
        }
    }

    private void writeLibraryInfo() {
        Memory memory = currentProgram.getMemory();
        jsonWriter.println("  \"library\": {");
        jsonWriter.println("    \"name\": " + jsonStr(currentProgram.getName()) + ",");
        jsonWriter.println("    \"architecture\": " + jsonStr(currentProgram.getLanguage().getProcessor().toString()) + ",");
        jsonWriter.println("    \"compiler\": " + jsonStr(currentProgram.getCompiler()) + ",");
        jsonWriter.println("    \"image_base\": " + jsonStr(currentProgram.getImageBase().toString()) + ",");
        jsonWriter.println("    \"language\": " + jsonStr(currentProgram.getLanguageID().getIdAsString()) + ",");
        jsonWriter.println("    \"min_address\": " + jsonStr(memory.getMinAddress().toString()) + ",");
        jsonWriter.println("    \"max_address\": " + jsonStr(memory.getMaxAddress().toString()));
        jsonWriter.println("  }");
    }

    private int writeFunctions() throws Exception {
        println("[Export] Exporting functions...");

        // Initialize decompiler
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);

        jsonWriter.println("  \"functions\": [");

        int funcCount = 0;
        int decompiled = 0;
        FunctionIterator functions = fm.getFunctions(true);

        try {
            while (functions.hasNext()) {
                if (monitor.isCancelled()) break;

                Function func = functions.next();

                if (funcCount > 0) jsonWriter.println(",");

                jsonWriter.println("    {");
                jsonWriter.println("      \"name\": " + jsonStr(func.getName()) + ",");
                jsonWriter.println("      \"address\": " + jsonStr(func.getEntryPoint().toString()) + ",");
                jsonWriter.println("      \"signature\": " + jsonStr(func.getSignature() != null ? func.getSignature().getPrototypeString() : null) + ",");
                jsonWriter.println("      \"calling_convention\": " + jsonStr(func.getCallingConventionName()) + ",");
                jsonWriter.println("      \"parameter_count\": " + func.getParameterCount() + ",");
                jsonWriter.println("      \"body_size\": " + func.getBody().getNumAddresses() + ",");
                jsonWriter.println("      \"is_thunk\": " + func.isThunk() + ",");
                jsonWriter.println("      \"is_external\": " + func.isExternal() + ",");

                // Check if export
                boolean isExport = false;
                Symbol[] symbols = st.getSymbols(func.getEntryPoint());
                for (Symbol sym : symbols) {
                    if (sym.isExternalEntryPoint()) {
                        isExport = true;
                        break;
                    }
                }
                jsonWriter.println("      \"is_export\": " + isExport + ",");

                // Count instructions
                int insnCount = 0;
                InstructionIterator insns = currentProgram.getListing().getInstructions(func.getBody(), true);
                while (insns.hasNext()) {
                    insns.next();
                    insnCount++;
                }
                jsonWriter.println("      \"instruction_count\": " + insnCount + ",");

                // Count basic blocks and edges
                int blockCount = 0;
                int edgeCount = 0;
                try {
                    CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor);
                    while (blocks.hasNext()) {
                        CodeBlock block = blocks.next();
                        blockCount++;
                        CodeBlockReferenceIterator dests = block.getDestinations(monitor);
                        while (dests.hasNext()) {
                            dests.next();
                            edgeCount++;
                        }
                    }
                } catch (Exception e) {
                    // Ignore block analysis errors
                }
                jsonWriter.println("      \"basic_block_count\": " + blockCount + ",");
                jsonWriter.println("      \"edge_count\": " + edgeCount + ",");

                // Decompile if not external/thunk and has code
                String decompiledCode = null;
                String codeHash = null;
                if (!func.isExternal() && !func.isThunk() && func.getBody().getNumAddresses() > 0) {
                    try {
                        DecompileResults results = decompiler.decompileFunction(func, 60, monitor);
                        if (results != null && results.decompileCompleted()) {
                            if (results.getDecompiledFunction() != null) {
                                decompiledCode = results.getDecompiledFunction().getC();
                                if (decompiledCode != null && !decompiledCode.isEmpty()) {
                                    codeHash = sha256(decompiledCode);
                                    decompiled++;
                                }
                            }
                        }
                    } catch (Exception e) {
                        // Decompilation failed, continue
                    }
                }
                jsonWriter.println("      \"code_hash\": " + jsonStr(codeHash) + ",");
                jsonWriter.println("      \"decompiled\": " + jsonStr(decompiledCode));

                jsonWriter.print("    }");
                funcCount++;

                if (funcCount % 500 == 0) {
                    println("[Export] Processed " + funcCount + " functions (" + decompiled + " decompiled)...");
                }
            }
        } finally {
            decompiler.dispose();
        }

        jsonWriter.println();
        jsonWriter.println("  ]");

        println("[Export] Functions: " + funcCount + " (" + decompiled + " decompiled)");
        return funcCount;
    }

    private int writeStrings() {
        println("[Export] Exporting strings...");

        jsonWriter.println("  \"strings\": [");

        int count = 0;
        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);

        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            DataType dt = data.getDataType();

            if (dt != null) {
                String typeName = dt.getName().toLowerCase();
                if (typeName.contains("string") || typeName.equals("char[]")) {
                    Object value = data.getValue();
                    if (value != null) {
                        String str = value.toString();
                        if (str.length() >= 2 && str.length() <= 1000) {
                            if (count > 0) jsonWriter.println(",");

                            jsonWriter.println("    {");
                            jsonWriter.println("      \"address\": " + jsonStr(data.getAddress().toString()) + ",");
                            jsonWriter.println("      \"value\": " + jsonStr(str) + ",");
                            jsonWriter.println("      \"length\": " + str.length());
                            jsonWriter.print("    }");

                            count++;
                            if (count >= 10000) break; // Limit
                        }
                    }
                }
            }
        }

        jsonWriter.println();
        jsonWriter.println("  ]");

        println("[Export] Strings: " + count);
        return count;
    }

    private int writeImports() {
        println("[Export] Exporting imports...");

        jsonWriter.println("  \"imports\": [");

        int count = 0;
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator extSymbols = st.getExternalSymbols();

        while (extSymbols.hasNext()) {
            Symbol sym = extSymbols.next();
            String library = null;

            try {
                ExternalLocation extLoc = currentProgram.getExternalManager().getExternalLocation(sym);
                if (extLoc != null && extLoc.getLibraryName() != null) {
                    library = extLoc.getLibraryName();
                }
            } catch (Exception e) {
                // Ignore
            }

            if (count > 0) jsonWriter.println(",");

            jsonWriter.println("    {");
            jsonWriter.println("      \"name\": " + jsonStr(sym.getName()) + ",");
            jsonWriter.println("      \"address\": " + jsonStr(sym.getAddress().toString()) + ",");
            jsonWriter.println("      \"library\": " + jsonStr(library));
            jsonWriter.print("    }");

            count++;
        }

        jsonWriter.println();
        jsonWriter.println("  ]");

        println("[Export] Imports: " + count);
        return count;
    }

    private int writeExports() {
        println("[Export] Exporting exports...");

        jsonWriter.println("  \"exports\": [");

        int count = 0;
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator symbols = st.getAllSymbols(true);

        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            if (sym.isExternalEntryPoint()) {
                if (count > 0) jsonWriter.println(",");

                jsonWriter.println("    {");
                jsonWriter.println("      \"name\": " + jsonStr(sym.getName()) + ",");
                jsonWriter.println("      \"address\": " + jsonStr(sym.getAddress().toString()));
                jsonWriter.print("    }");

                count++;
            }
        }

        jsonWriter.println();
        jsonWriter.println("  ]");

        println("[Export] Exports: " + count);
        return count;
    }

    private void writeMemorySections() {
        jsonWriter.println("  \"memory_sections\": [");

        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();
        for (int i = 0; i < blocks.length; i++) {
            MemoryBlock block = blocks[i];

            if (i > 0) jsonWriter.println(",");

            jsonWriter.println("    {");
            jsonWriter.println("      \"name\": " + jsonStr(block.getName()) + ",");
            jsonWriter.println("      \"start\": " + jsonStr(block.getStart().toString()) + ",");
            jsonWriter.println("      \"end\": " + jsonStr(block.getEnd().toString()) + ",");
            jsonWriter.println("      \"size\": " + block.getSize() + ",");
            jsonWriter.println("      \"is_read\": " + block.isRead() + ",");
            jsonWriter.println("      \"is_write\": " + block.isWrite() + ",");
            jsonWriter.println("      \"is_execute\": " + block.isExecute() + ",");
            jsonWriter.println("      \"is_initialized\": " + block.isInitialized());
            jsonWriter.print("    }");
        }

        jsonWriter.println();
        jsonWriter.println("  ]");
    }

    private String jsonStr(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 32) {
                        sb.append(String.format("\\u%04x", (int)c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

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
}
