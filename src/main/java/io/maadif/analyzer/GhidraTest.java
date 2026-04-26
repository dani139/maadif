package io.maadif.analyzer;

import java.io.File;

/**
 * Simple test to verify Ghidra analysis works on native libraries.
 */
public class GhidraTest {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java GhidraTest <binary-file> [output-dir]");
            System.out.println("Example: java GhidraTest /path/to/libs.so /path/to/output");
            System.exit(1);
        }

        File binaryFile = new File(args[0]);
        if (!binaryFile.exists()) {
            System.err.println("Error: File not found: " + binaryFile.getAbsolutePath());
            System.exit(1);
        }

        File outputDir;
        if (args.length > 1) {
            outputDir = new File(args[1]);
        } else {
            outputDir = new File("ghidra_test_output");
        }
        outputDir.mkdirs();

        System.out.println("╔══════════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                    GHIDRA ANALYSIS TEST                                      ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("Binary: " + binaryFile.getName());
        System.out.println("Size: " + (binaryFile.length() / 1024) + " KB");
        System.out.println("Output: " + outputDir.getAbsolutePath());
        System.out.println();

        try {
            GhidraAnalyzer analyzer = new GhidraAnalyzer(outputDir);

            long startTime = System.currentTimeMillis();
            GhidraAnalyzer.AnalysisResult result = analyzer.analyzeFile(binaryFile);
            long duration = System.currentTimeMillis() - startTime;

            System.out.println();
            System.out.println("═══════════════════════════════════════════════════════════════════════════════");
            System.out.println("RESULTS");
            System.out.println("═══════════════════════════════════════════════════════════════════════════════");
            System.out.println("Success: " + result.success);
            System.out.println("Duration: " + (duration / 1000) + "s");
            System.out.println();

            if (result.success) {
                System.out.println("Program: " + result.programName);
                System.out.println("Language: " + result.languageId);
                System.out.println("Compiler: " + result.compilerSpec);
                System.out.println("Image Base: " + result.imageBase);
                System.out.println();
                System.out.println("Functions: " + result.functions.size());
                System.out.println("Strings: " + result.strings.size());
                System.out.println("Imports: " + result.imports.size());
                System.out.println("Exports: " + result.exports.size());
                System.out.println("Memory Sections: " + result.memorySections.size());
                System.out.println("Structures: " + result.structures.size());

                // Show some sample functions
                System.out.println();
                System.out.println("Sample Functions (first 10):");
                int count = 0;
                for (GhidraAnalyzer.FunctionInfo func : result.functions) {
                    if (count++ >= 10) break;
                    System.out.println("  " + func.address + " " + func.name);
                }

                // Show some imports
                System.out.println();
                System.out.println("Sample Imports (first 10):");
                count = 0;
                for (String imp : result.imports) {
                    if (count++ >= 10) break;
                    System.out.println("  " + imp);
                }

                // Generate report
                File reportFile = new File(outputDir, "ghidra_report_" + binaryFile.getName() + ".txt");
                analyzer.generateReport(result, reportFile);
            }

            if (!result.errors.isEmpty()) {
                System.out.println();
                System.out.println("Errors:");
                for (String error : result.errors) {
                    System.out.println("  " + error);
                }
            }

            System.exit(result.success ? 0 : 1);

        } catch (Exception e) {
            System.err.println("Fatal error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
