package com.maadif.analysis;

import com.maadif.Config;
import com.maadif.model.ApkInfo;
import com.maadif.model.AnalysisResult;
import com.maadif.storage.Database;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;

/**
 * Service that orchestrates APK analysis using JADX and Ghidra.
 *
 * Analysis steps:
 * 1. Extract APK metadata (manifest parsing)
 * 2. Run JADX for Java decompilation
 * 3. Run Ghidra for native library analysis
 * 4. Build callgraphs and store in database
 */
public class AnalysisService {

    private final Config config;
    private final Database db;

    public AnalysisService(Config config, Database db) {
        this.config = config;
        this.db = db;
    }

    /**
     * Extract basic info from APK without full analysis.
     * Used immediately after upload.
     */
    public ApkInfo extractBasicInfo(String apkId) throws Exception {
        Path apkPath = getApkPath(apkId);
        ApkInfo info = new ApkInfo();
        info.id = apkId;
        info.permissions = new ArrayList<>();

        // Parse AndroidManifest.xml from APK
        try (ZipFile zip = new ZipFile(apkPath.toFile())) {
            ZipEntry manifestEntry = zip.getEntry("AndroidManifest.xml");
            if (manifestEntry != null) {
                // Note: AndroidManifest.xml is binary XML, need to decode
                // For now, use aapt or apktool to extract
                // This is a simplified version - real impl would decode AXML
                extractManifestWithAapt(apkPath, info);
            }
        }

        return info;
    }

    /**
     * Run full analysis on APK.
     */
    public void analyze(String apkId, boolean runJadx, boolean runGhidra, boolean buildCallgraph)
            throws Exception {

        Path apkPath = getApkPath(apkId);
        Path outputDir = getOutputDir(apkId);
        Files.createDirectories(outputDir);

        db.setAnalysisStatus(apkId, "running", "Starting analysis...");

        // Step 1: JADX decompilation
        if (runJadx) {
            db.setAnalysisStatus(apkId, "running", "Running JADX decompilation...");
            runJadxAnalysis(apkId, apkPath, outputDir);
        }

        // Step 2: Extract native libraries
        Path nativeDir = outputDir.resolve("native");
        List<Path> nativeLibs = extractNativeLibs(apkPath, nativeDir);

        // Step 3: Ghidra analysis for each native lib
        if (runGhidra && !nativeLibs.isEmpty()) {
            db.setAnalysisStatus(apkId, "running", "Running Ghidra analysis on native libraries...");
            for (Path lib : nativeLibs) {
                runGhidraAnalysis(apkId, lib, outputDir);
            }
        }

        // Step 4: Build callgraph
        if (buildCallgraph) {
            db.setAnalysisStatus(apkId, "running", "Building callgraph...");
            buildCallgraph(apkId, apkPath, outputDir);
        }

        // Step 5: Save analysis result
        AnalysisResult result = buildAnalysisResult(apkId, outputDir);
        db.saveAnalysisResult(apkId, result);

        db.setAnalysisStatus(apkId, "completed", "Analysis completed");
    }

    // -------------------------------------------------------------------------
    // JADX Analysis
    // -------------------------------------------------------------------------

    private void runJadxAnalysis(String apkId, Path apkPath, Path outputDir) throws Exception {
        Path jadxOutput = outputDir.resolve("jadx");
        Files.createDirectories(jadxOutput);

        // Run JADX command
        ProcessBuilder pb = new ProcessBuilder(
            config.jadxPath,
            "--output-dir", jadxOutput.toString(),
            "--deobf",                    // Deobfuscate
            "--show-bad-code",           // Show decompilation errors
            "--export-gradle",           // Export project structure
            apkPath.toString()
        );

        pb.redirectErrorStream(true);
        Process process = pb.start();

        // Log output
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("[JADX] " + line);
            }
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("JADX failed with exit code: " + exitCode);
        }

        // Index classes and methods into database
        indexJadxOutput(apkId, jadxOutput);
    }

    private void indexJadxOutput(String apkId, Path jadxOutput) throws Exception {
        Path sourcesDir = jadxOutput.resolve("sources");
        if (!Files.exists(sourcesDir)) {
            sourcesDir = jadxOutput; // JADX might output directly
        }

        // Walk all .java files and index
        Files.walk(sourcesDir)
            .filter(p -> p.toString().endsWith(".java"))
            .forEach(javaFile -> {
                try {
                    indexJavaFile(apkId, sourcesDir, javaFile);
                } catch (Exception e) {
                    System.err.println("Failed to index: " + javaFile + " - " + e.getMessage());
                }
            });
    }

    private void indexJavaFile(String apkId, Path baseDir, Path javaFile) throws Exception {
        String relativePath = baseDir.relativize(javaFile).toString();
        String className = relativePath
            .replace(".java", "")
            .replace(File.separator, ".");

        String content = Files.readString(javaFile);
        String hash = hashString(content);

        // Insert class into database
        db.insertJavaClass(apkId, className, hash);

        // Extract method signatures (simple regex-based extraction)
        extractAndIndexMethods(apkId, className, content);
    }

    private void extractAndIndexMethods(String apkId, String className, String content) {
        // Simple regex to find method declarations
        // Real impl would use JavaParser or similar
        var pattern = java.util.regex.Pattern.compile(
            "(public|private|protected)?\\s*(static)?\\s*\\w+\\s+(\\w+)\\s*\\([^)]*\\)\\s*\\{"
        );
        var matcher = pattern.matcher(content);

        while (matcher.find()) {
            String methodName = matcher.group(3);
            if (methodName != null && !methodName.equals("if") && !methodName.equals("for")) {
                db.insertJavaMethod(apkId, className, methodName);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Ghidra Analysis
    // -------------------------------------------------------------------------

    private void runGhidraAnalysis(String apkId, Path nativeLib, Path outputDir) throws Exception {
        String libName = nativeLib.getFileName().toString();
        Path ghidraOutput = outputDir.resolve("ghidra").resolve(libName);
        Files.createDirectories(ghidraOutput);

        // Ghidra project directory
        Path projectDir = ghidraOutput.resolve("project");
        Files.createDirectories(projectDir);

        // Run Ghidra headless
        ProcessBuilder pb = new ProcessBuilder(
            config.ghidraPath + "/support/analyzeHeadless",
            projectDir.toString(),
            "analysis",
            "-import", nativeLib.toString(),
            "-postScript", "ExportFunctions.py", ghidraOutput.resolve("functions.json").toString(),
            "-postScript", "ExportCallgraph.py", ghidraOutput.resolve("callgraph.json").toString(),
            "-deleteProject"  // Clean up after
        );

        pb.redirectErrorStream(true);
        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("[Ghidra] " + line);
            }
        }

        int exitCode = process.waitFor();
        // Ghidra may return non-zero even on success, check output exists
        if (!Files.exists(ghidraOutput.resolve("functions.json"))) {
            System.err.println("Warning: Ghidra analysis may have failed for " + libName);
        }

        // Index native functions into database
        indexGhidraOutput(apkId, libName, ghidraOutput);
    }

    private void indexGhidraOutput(String apkId, String libName, Path ghidraOutput) throws Exception {
        Path functionsFile = ghidraOutput.resolve("functions.json");
        if (!Files.exists(functionsFile)) {
            return;
        }

        // Parse functions.json and insert into database
        // Format: [{"name": "func", "address": "0x1234", "size": 100}, ...]
        String json = Files.readString(functionsFile);
        // Simple JSON parsing - real impl would use Jackson
        db.insertNativeLib(apkId, libName, extractArch(libName));

        // Parse callgraph
        Path callgraphFile = ghidraOutput.resolve("callgraph.json");
        if (Files.exists(callgraphFile)) {
            // Index call edges
            // Format: [{"caller": "func1", "callee": "func2"}, ...]
        }
    }

    // -------------------------------------------------------------------------
    // Callgraph Building
    // -------------------------------------------------------------------------

    private void buildCallgraph(String apkId, Path apkPath, Path outputDir) throws Exception {
        // For Java callgraph, we could:
        // 1. Use androguard (Python) via subprocess
        // 2. Parse JADX output for method calls
        // 3. Use dex2jar + java-callgraph

        // For now, shell out to a Python script that uses androguard
        ProcessBuilder pb = new ProcessBuilder(
            "python3",
            "-c",
            String.format("""
                from androguard.misc import AnalyzeAPK
                import json
                import sqlite3

                a, d, dx = AnalyzeAPK('%s')
                cg = dx.get_call_graph()

                db = sqlite3.connect('%s/maadif.db')
                cursor = db.cursor()

                for caller, callee in cg.edges():
                    caller_str = str(caller.get_method()) if hasattr(caller, 'get_method') else str(caller)
                    callee_str = str(callee.get_method()) if hasattr(callee, 'get_method') else str(callee)
                    cursor.execute(
                        "INSERT OR IGNORE INTO java_calls (apk_id, caller, callee) VALUES (?, ?, ?)",
                        ('%s', caller_str, callee_str)
                    )

                db.commit()
                print(f"Indexed {cg.number_of_edges()} call edges")
                """,
                apkPath.toString(),
                config.outputDir,
                apkId
            )
        );

        pb.redirectErrorStream(true);
        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("[Callgraph] " + line);
            }
        }

        process.waitFor();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private Path getApkPath(String apkId) {
        return Path.of(config.apksDir, apkId + ".apk");
    }

    private Path getOutputDir(String apkId) {
        return Path.of(config.outputDir, "analysis", apkId);
    }

    private List<Path> extractNativeLibs(Path apkPath, Path outputDir) throws Exception {
        List<Path> libs = new ArrayList<>();
        Files.createDirectories(outputDir);

        try (ZipFile zip = new ZipFile(apkPath.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();

                // Extract .so files from lib/ directory
                if (name.startsWith("lib/") && name.endsWith(".so")) {
                    Path outPath = outputDir.resolve(name.substring(4)); // Remove "lib/"
                    Files.createDirectories(outPath.getParent());

                    try (InputStream in = zip.getInputStream(entry)) {
                        Files.copy(in, outPath, StandardCopyOption.REPLACE_EXISTING);
                    }
                    libs.add(outPath);
                }
            }
        }

        return libs;
    }

    private void extractManifestWithAapt(Path apkPath, ApkInfo info) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(
            "aapt", "dump", "badging", apkPath.toString()
        );

        pb.redirectErrorStream(true);
        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("package:")) {
                    // package: name='com.example' versionCode='1' versionName='1.0'
                    info.packageName = extractValue(line, "name");
                    info.versionName = extractValue(line, "versionName");
                    String vc = extractValue(line, "versionCode");
                    if (vc != null) info.versionCode = Integer.parseInt(vc);
                } else if (line.startsWith("sdkVersion:")) {
                    info.minSdk = Integer.parseInt(line.split("'")[1]);
                } else if (line.startsWith("targetSdkVersion:")) {
                    info.targetSdk = Integer.parseInt(line.split("'")[1]);
                } else if (line.startsWith("uses-permission:")) {
                    String perm = extractValue(line, "name");
                    if (perm != null) info.permissions.add(perm);
                }
            }
        }

        process.waitFor();
    }

    private String extractValue(String line, String key) {
        String search = key + "='";
        int start = line.indexOf(search);
        if (start == -1) return null;
        start += search.length();
        int end = line.indexOf("'", start);
        if (end == -1) return null;
        return line.substring(start, end);
    }

    private String extractArch(String libPath) {
        if (libPath.contains("arm64")) return "arm64-v8a";
        if (libPath.contains("armeabi")) return "armeabi-v7a";
        if (libPath.contains("x86_64")) return "x86_64";
        if (libPath.contains("x86")) return "x86";
        return "unknown";
    }

    private String hashString(String content) throws Exception {
        var md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(content.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString().substring(0, 16); // Short hash
    }

    private AnalysisResult buildAnalysisResult(String apkId, Path outputDir) {
        AnalysisResult result = new AnalysisResult();
        result.apkId = apkId;
        result.apkInfo = db.getApk(apkId);
        result.classCount = db.countClasses(apkId);
        result.methodCount = db.countMethods(apkId);
        result.nativeLibCount = db.countNativeLibs(apkId);
        return result;
    }
}
