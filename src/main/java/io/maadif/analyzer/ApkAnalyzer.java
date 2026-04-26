package io.maadif.analyzer;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/**
 * MAADIF - Mobile & Application Analysis Docker Image Framework
 * Main APK Analyzer combining Ghidra and JADX capabilities.
 */
public class ApkAnalyzer {

    private File inputApk;
    private File outputDir;
    private File workDir;

    private JadxAnalyzer jadxAnalyzer;
    private GhidraAnalyzer ghidraAnalyzer;

    public ApkAnalyzer(File inputApk, File outputDir) {
        this.inputApk = inputApk;
        this.outputDir = outputDir;
        this.workDir = new File(outputDir, "work");
    }

    /**
     * Run full analysis on the APK using both JADX and Ghidra.
     */
    public FullAnalysisResult analyze() throws Exception {
        FullAnalysisResult result = new FullAnalysisResult();
        result.apkName = inputApk.getName();
        result.apkSize = inputApk.length();
        result.startTime = System.currentTimeMillis();

        System.out.println("╔══════════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                    MAADIF - APK Full Analysis                                ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("APK: " + inputApk.getName());
        System.out.println("Size: " + formatSize(inputApk.length()));
        System.out.println("Output: " + outputDir.getAbsolutePath());
        System.out.println();

        // Create directories
        outputDir.mkdirs();
        workDir.mkdirs();

        // Extract APK info
        System.out.println("═══════════════════════════════════════════════════════════════════════════════");
        System.out.println("Phase 1: APK Extraction");
        System.out.println("═══════════════════════════════════════════════════════════════════════════════");
        extractApk(result);

        // JADX Analysis
        System.out.println();
        System.out.println("═══════════════════════════════════════════════════════════════════════════════");
        System.out.println("Phase 2: JADX Decompilation & Analysis");
        System.out.println("═══════════════════════════════════════════════════════════════════════════════");
        runJadxAnalysis(result);

        // Ghidra Analysis (on DEX files)
        System.out.println();
        System.out.println("═══════════════════════════════════════════════════════════════════════════════");
        System.out.println("Phase 3: Ghidra Binary Analysis");
        System.out.println("═══════════════════════════════════════════════════════════════════════════════");
        runGhidraAnalysis(result);

        // Generate combined report
        System.out.println();
        System.out.println("═══════════════════════════════════════════════════════════════════════════════");
        System.out.println("Phase 4: Report Generation");
        System.out.println("═══════════════════════════════════════════════════════════════════════════════");
        generateCombinedReport(result);

        result.endTime = System.currentTimeMillis();
        result.success = true;

        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                         Analysis Complete                                    ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════════════╝");
        System.out.println("Duration: " + formatDuration(result.endTime - result.startTime));
        System.out.println("Reports: " + outputDir.getAbsolutePath());

        return result;
    }

    private void extractApk(FullAnalysisResult result) throws Exception {
        File extractDir = new File(workDir, "extracted");
        extractDir.mkdirs();

        System.out.println("[Extract] Extracting APK contents...");

        try (ZipFile zip = new ZipFile(inputApk)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();

                // Track file types
                if (name.endsWith(".dex")) {
                    result.dexFiles.add(name);
                    // Extract DEX for Ghidra analysis
                    File dexFile = new File(extractDir, name);
                    dexFile.getParentFile().mkdirs();
                    try (InputStream is = zip.getInputStream(entry);
                         FileOutputStream fos = new FileOutputStream(dexFile)) {
                        is.transferTo(fos);
                    }
                } else if (name.endsWith(".so")) {
                    result.nativeLibraries.add(name);
                    // Extract SO for Ghidra analysis
                    File soFile = new File(extractDir, name);
                    soFile.getParentFile().mkdirs();
                    try (InputStream is = zip.getInputStream(entry);
                         FileOutputStream fos = new FileOutputStream(soFile)) {
                        is.transferTo(fos);
                    }
                } else if (name.equals("AndroidManifest.xml")) {
                    result.hasManifest = true;
                } else if (name.startsWith("res/")) {
                    result.resourceCount++;
                } else if (name.startsWith("assets/")) {
                    result.assetFiles.add(name);
                }
            }
        }

        System.out.println("[Extract] Found " + result.dexFiles.size() + " DEX files");
        System.out.println("[Extract] Found " + result.nativeLibraries.size() + " native libraries");
        System.out.println("[Extract] Found " + result.resourceCount + " resources");
        System.out.println("[Extract] Found " + result.assetFiles.size() + " assets");
    }

    private void runJadxAnalysis(FullAnalysisResult result) {
        try {
            jadxAnalyzer = new JadxAnalyzer(outputDir);
            JadxAnalyzer.DecompilationResult jadxResult = jadxAnalyzer.analyzeApk(inputApk);
            result.jadxResult = jadxResult;

            // Generate JADX-specific report
            File jadxReport = new File(outputDir, "jadx_analysis_report.txt");
            jadxAnalyzer.generateReport(jadxResult, jadxReport);

            System.out.println("[JADX] Decompiled " + jadxResult.totalClasses + " classes");
            System.out.println("[JADX] Found " + jadxResult.permissions.size() + " permissions");
            System.out.println("[JADX] Found " + jadxResult.securityIssues.size() + " security issues");

        } catch (Exception e) {
            System.err.println("[JADX] Error: " + e.getMessage());
            result.errors.add("JADX analysis failed: " + e.getMessage());
        }
    }

    private void runGhidraAnalysis(FullAnalysisResult result) {
        File extractDir = new File(workDir, "extracted");

        try {
            ghidraAnalyzer = new GhidraAnalyzer(outputDir);

            // Analyze each DEX file
            for (String dexFileName : result.dexFiles) {
                File dexFile = new File(extractDir, dexFileName);
                if (dexFile.exists()) {
                    try {
                        GhidraAnalyzer.AnalysisResult ghidraResult = ghidraAnalyzer.analyzeDexFile(dexFile);
                        result.ghidraResults.add(ghidraResult);

                        // Generate Ghidra-specific report for each DEX
                        String reportName = "ghidra_" + dexFileName.replace("/", "_").replace(".dex", "") + "_report.txt";
                        File ghidraReport = new File(outputDir, reportName);
                        ghidraAnalyzer.generateReport(ghidraResult, ghidraReport);

                        System.out.println("[Ghidra] Analyzed " + dexFileName + ": " +
                            ghidraResult.functions.size() + " functions, " +
                            ghidraResult.strings.size() + " strings");

                    } catch (Exception e) {
                        System.err.println("[Ghidra] Error analyzing " + dexFileName + ": " + e.getMessage());
                        result.errors.add("Ghidra failed on " + dexFileName + ": " + e.getMessage());
                    }
                }
            }

            // Analyze native libraries
            for (String soFile : result.nativeLibraries) {
                File libFile = new File(extractDir, soFile);
                if (libFile.exists() && libFile.length() < 50 * 1024 * 1024) { // Skip files > 50MB
                    try {
                        GhidraAnalyzer.AnalysisResult ghidraResult = ghidraAnalyzer.analyzeDexFile(libFile);
                        result.ghidraResults.add(ghidraResult);

                        String reportName = "ghidra_" + soFile.replace("/", "_").replace(".so", "") + "_report.txt";
                        File ghidraReport = new File(outputDir, reportName);
                        ghidraAnalyzer.generateReport(ghidraResult, ghidraReport);

                        System.out.println("[Ghidra] Analyzed " + soFile + ": " +
                            ghidraResult.functions.size() + " functions");

                    } catch (Exception e) {
                        System.err.println("[Ghidra] Error analyzing " + soFile + ": " + e.getMessage());
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("[Ghidra] Initialization error: " + e.getMessage());
            result.errors.add("Ghidra initialization failed: " + e.getMessage());
        }
    }

    private void generateCombinedReport(FullAnalysisResult result) throws Exception {
        File reportFile = new File(outputDir, "full_analysis_report.txt");

        try (PrintWriter writer = new PrintWriter(new FileWriter(reportFile))) {
            writer.println("╔══════════════════════════════════════════════════════════════════════════════╗");
            writer.println("║                    MAADIF - Full APK Analysis Report                         ║");
            writer.println("╚══════════════════════════════════════════════════════════════════════════════╝");
            writer.println();
            writer.println("APK: " + result.apkName);
            writer.println("Size: " + formatSize(result.apkSize));
            writer.println("Analysis Date: " + new Date());
            writer.println();

            // APK Structure
            writer.println("═══════════════════════════════════════════════════════════════════════════════");
            writer.println("APK STRUCTURE");
            writer.println("═══════════════════════════════════════════════════════════════════════════════");
            writer.println("DEX Files: " + result.dexFiles.size());
            for (String dex : result.dexFiles) {
                writer.println("  - " + dex);
            }
            writer.println("Native Libraries: " + result.nativeLibraries.size());
            for (String lib : result.nativeLibraries) {
                writer.println("  - " + lib);
            }
            writer.println("Resources: " + result.resourceCount);
            writer.println("Assets: " + result.assetFiles.size());
            writer.println();

            // JADX Results Summary
            if (result.jadxResult != null) {
                writer.println("═══════════════════════════════════════════════════════════════════════════════");
                writer.println("JADX DECOMPILATION SUMMARY");
                writer.println("═══════════════════════════════════════════════════════════════════════════════");
                writer.println("Package: " + result.jadxResult.packageName);
                writer.println("Total Classes: " + result.jadxResult.totalClasses);
                writer.println("Activities: " + result.jadxResult.activities.size());
                writer.println("Services: " + result.jadxResult.services.size());
                writer.println("Permissions: " + result.jadxResult.permissions.size());
                writer.println();

                // Security Summary
                writer.println("───────────────────────────────────────────────────────────────────────────────");
                writer.println("SECURITY ANALYSIS");
                writer.println("───────────────────────────────────────────────────────────────────────────────");
                for (String issue : result.jadxResult.securityIssues) {
                    writer.println("  [!] " + issue);
                }
                writer.println();

                // Permissions
                writer.println("───────────────────────────────────────────────────────────────────────────────");
                writer.println("PERMISSIONS");
                writer.println("───────────────────────────────────────────────────────────────────────────────");
                for (String perm : result.jadxResult.permissions) {
                    writer.println("  " + perm);
                }
                writer.println();

                // URLs
                if (!result.jadxResult.allUrls.isEmpty()) {
                    writer.println("───────────────────────────────────────────────────────────────────────────────");
                    writer.println("DISCOVERED URLS");
                    writer.println("───────────────────────────────────────────────────────────────────────────────");
                    Set<String> uniqueUrls = new TreeSet<>(result.jadxResult.allUrls);
                    for (String url : uniqueUrls.stream().limit(50).toList()) {
                        writer.println("  " + url);
                    }
                    writer.println();
                }
            }

            // Ghidra Results Summary
            if (!result.ghidraResults.isEmpty()) {
                writer.println("═══════════════════════════════════════════════════════════════════════════════");
                writer.println("GHIDRA BINARY ANALYSIS SUMMARY");
                writer.println("═══════════════════════════════════════════════════════════════════════════════");

                int totalFunctions = 0;
                int totalStrings = 0;
                for (GhidraAnalyzer.AnalysisResult gr : result.ghidraResults) {
                    writer.println("File: " + gr.fileName);
                    writer.println("  Functions: " + gr.functions.size());
                    writer.println("  Strings: " + gr.strings.size());
                    writer.println("  Imports: " + gr.imports.size());
                    totalFunctions += gr.functions.size();
                    totalStrings += gr.strings.size();
                }
                writer.println();
                writer.println("Total Functions Analyzed: " + totalFunctions);
                writer.println("Total Strings Found: " + totalStrings);
                writer.println();
            }

            // Errors
            if (!result.errors.isEmpty()) {
                writer.println("═══════════════════════════════════════════════════════════════════════════════");
                writer.println("ERRORS & WARNINGS");
                writer.println("═══════════════════════════════════════════════════════════════════════════════");
                for (String error : result.errors) {
                    writer.println("  " + error);
                }
            }

            writer.println();
            writer.println("═══════════════════════════════════════════════════════════════════════════════");
            writer.println("END OF REPORT");
            writer.println("═══════════════════════════════════════════════════════════════════════════════");
        }

        System.out.println("[Report] Full analysis report: " + reportFile.getAbsolutePath());

        // Also save as JSON for programmatic access
        saveJsonReport(result);
    }

    private void saveJsonReport(FullAnalysisResult result) throws Exception {
        File jsonFile = new File(outputDir, "analysis_result.json");

        try (PrintWriter writer = new PrintWriter(new FileWriter(jsonFile))) {
            writer.println("{");
            writer.println("  \"apkName\": \"" + escapeJson(result.apkName) + "\",");
            writer.println("  \"apkSize\": " + result.apkSize + ",");
            writer.println("  \"success\": " + result.success + ",");
            writer.println("  \"dexFiles\": " + toJsonArray(result.dexFiles) + ",");
            writer.println("  \"nativeLibraries\": " + toJsonArray(result.nativeLibraries) + ",");

            if (result.jadxResult != null) {
                writer.println("  \"packageName\": \"" + escapeJson(result.jadxResult.packageName) + "\",");
                writer.println("  \"totalClasses\": " + result.jadxResult.totalClasses + ",");
                writer.println("  \"permissions\": " + toJsonArray(result.jadxResult.permissions) + ",");
                writer.println("  \"securityIssues\": " + toJsonArray(result.jadxResult.securityIssues) + ",");
                writer.println("  \"activities\": " + toJsonArray(result.jadxResult.activities) + ",");
                writer.println("  \"services\": " + toJsonArray(result.jadxResult.services) + ",");
                writer.println("  \"urls\": " + toJsonArray(new ArrayList<>(new TreeSet<>(result.jadxResult.allUrls))) + ",");
            }

            int totalFunctions = result.ghidraResults.stream().mapToInt(r -> r.functions.size()).sum();
            writer.println("  \"totalFunctionsAnalyzed\": " + totalFunctions + ",");
            writer.println("  \"errors\": " + toJsonArray(result.errors));
            writer.println("}");
        }

        System.out.println("[Report] JSON report: " + jsonFile.getAbsolutePath());
    }

    private String toJsonArray(List<String> list) {
        if (list == null || list.isEmpty()) return "[]";
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < Math.min(list.size(), 100); i++) {
            if (i > 0) sb.append(", ");
            sb.append("\"").append(escapeJson(list.get(i))).append("\"");
        }
        sb.append("]");
        return sb.toString();
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
    }

    private String formatDuration(long millis) {
        if (millis < 1000) return millis + "ms";
        if (millis < 60000) return String.format("%.1fs", millis / 1000.0);
        return String.format("%dm %ds", millis / 60000, (millis % 60000) / 1000);
    }

    // Result class
    public static class FullAnalysisResult {
        public String apkName;
        public long apkSize;
        public boolean success = false;
        public long startTime;
        public long endTime;

        public boolean hasManifest = false;
        public List<String> dexFiles = new ArrayList<>();
        public List<String> nativeLibraries = new ArrayList<>();
        public List<String> assetFiles = new ArrayList<>();
        public int resourceCount = 0;

        public JadxAnalyzer.DecompilationResult jadxResult;
        public List<GhidraAnalyzer.AnalysisResult> ghidraResults = new ArrayList<>();

        public List<String> errors = new ArrayList<>();
    }

    /**
     * Main entry point.
     */
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java -jar maadif-analyzer.jar <apk-file> [output-dir]");
            System.out.println();
            System.out.println("Arguments:");
            System.out.println("  apk-file    Path to the APK file to analyze");
            System.out.println("  output-dir  Output directory (default: ./analysis_output)");
            System.exit(1);
        }

        File apkFile = new File(args[0]);
        if (!apkFile.exists()) {
            System.err.println("Error: APK file not found: " + apkFile.getAbsolutePath());
            System.exit(1);
        }

        File outputDir;
        if (args.length > 1) {
            outputDir = new File(args[1]);
        } else {
            String baseName = apkFile.getName().replace(".apk", "");
            outputDir = new File("analysis_output", baseName);
        }

        try {
            ApkAnalyzer analyzer = new ApkAnalyzer(apkFile, outputDir);
            FullAnalysisResult result = analyzer.analyze();

            System.exit(result.success ? 0 : 1);

        } catch (Exception e) {
            System.err.println("Fatal error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
