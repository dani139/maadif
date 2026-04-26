package io.maadif.server;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import io.maadif.analyzer.ApkAnalyzer;
import io.maadif.analyzer.JadxAnalyzer;
import io.maadif.analyzer.GhidraAnalyzer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.nio.charset.StandardCharsets;

/**
 * MAADIF REST API Server
 *
 * Endpoints:
 *   GET  /health              - Health check
 *   GET  /apks                - List available APKs
 *   POST /analyze             - Start APK analysis
 *   POST /native              - Analyze specific native library
 *   GET  /status/{id}         - Get job status
 *   GET  /analysis/{id}       - Get analysis results
 *   GET  /download/versions   - List available versions for a package
 *   POST /download            - Download APK by package and version
 *
 * Version Tracking:
 *   GET  /track/scrape        - Scrape and save versions from sources
 *   GET  /track/versions      - List versions from tracking database
 *   GET  /track/status        - Show tracking database status
 *   POST /track/add           - Add a new package to track
 */
public class ApiServer {

    private static final int DEFAULT_PORT = 8080;
    private static final String APKS_DIR = System.getenv("MAADIF_APKS_DIR") != null
        ? System.getenv("MAADIF_APKS_DIR") : "/workspace/apks";
    private static final String OUTPUT_DIR = System.getenv("MAADIF_OUTPUT_DIR") != null
        ? System.getenv("MAADIF_OUTPUT_DIR") : "/workspace/output";
    private static final String DATA_DIR = System.getenv("MAADIF_DATA_DIR") != null
        ? System.getenv("MAADIF_DATA_DIR") : "/workspace/data";

    private final HttpServer server;
    private final Database globalDb;  // Global database for jobs, releases, subscriptions
    private final ExecutorService analysisExecutor;
    private final ScheduledExecutorService releaseScheduler;

    public ApiServer(int port) throws Exception {
        // Initialize global database (for jobs, release tracking)
        new File(DATA_DIR).mkdirs();
        this.globalDb = new Database(DATA_DIR + "/maadif.db");
        this.globalDb.initializeGlobalSchema();

        // Thread pool for analysis jobs
        this.analysisExecutor = Executors.newFixedThreadPool(2);

        // Scheduler for release monitoring
        this.releaseScheduler = Executors.newScheduledThreadPool(1);

        // Create HTTP server
        this.server = HttpServer.create(new InetSocketAddress(port), 0);

        // Register endpoints
        server.createContext("/health", this::handleHealth);
        server.createContext("/apks", this::handleApks);
        server.createContext("/analyze", this::handleAnalyze);
        server.createContext("/native", this::handleNative);
        server.createContext("/status/", this::handleStatus);
        server.createContext("/analysis/", this::handleAnalysis);
        server.createContext("/download/versions", this::handleDownloadVersions);
        server.createContext("/download", this::handleDownload);

        // Version tracking endpoints (new version_tracker.py)
        server.createContext("/track/scrape", this::handleTrackScrape);
        server.createContext("/track/versions", this::handleTrackVersions);
        server.createContext("/track/status", this::handleTrackStatus);
        server.createContext("/track/add", this::handleTrackAdd);

        // Release tracking endpoints
        server.createContext("/releases/check", this::handleReleasesCheck);
        server.createContext("/releases/subscribe", this::handleReleasesSubscribe);
        server.createContext("/releases/subscriptions", this::handleReleasesSubscriptions);
        server.createContext("/releases/history", this::handleReleasesHistory);
        server.createContext("/releases", this::handleReleases);

        server.setExecutor(Executors.newFixedThreadPool(4));
    }

    public void start() {
        server.start();

        // Start background release checker (every 30 minutes)
        releaseScheduler.scheduleAtFixedRate(
            this::checkSubscribedReleases,
            1, 30, TimeUnit.MINUTES
        );

        System.out.println("╔══════════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                    MAADIF API Server                                         ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("Server running on port " + server.getAddress().getPort());
        System.out.println("APKs directory: " + APKS_DIR);
        System.out.println("Output directory: " + OUTPUT_DIR);
        System.out.println("Database: " + DATA_DIR + "/maadif.db");
        System.out.println();
        System.out.println("Endpoints:");
        System.out.println("  GET  /health              - Health check");
        System.out.println("  GET  /apks                - List available APKs");
        System.out.println("  POST /analyze             - Start APK analysis");
        System.out.println("  POST /native              - Analyze specific native library");
        System.out.println("  GET  /status/{id}         - Get job status");
        System.out.println("  GET  /analysis/{id}       - Get analysis results");
        System.out.println("  GET  /download/versions   - List available versions (?package=com.app)");
        System.out.println("  POST /download            - Download APK (package, version)");
        System.out.println();
        System.out.println("Version Tracking:");
        System.out.println("  GET  /track/scrape        - Scrape versions (?package=com.whatsapp&source=all)");
        System.out.println("  GET  /track/versions      - List versions (?package=...&channel=...&limit=...)");
        System.out.println("  GET  /track/status        - Tracking database status");
        System.out.println("  POST /track/add           - Add package to track (package, name)");
        System.out.println();
        System.out.println("Release Tracking (legacy):");
        System.out.println("  GET  /releases            - Get latest releases (?package=com.whatsapp)");
        System.out.println("  GET  /releases/check      - Check for new releases");
        System.out.println("  GET  /releases/history    - Get release history from DB");
        System.out.println("  POST /releases/subscribe  - Subscribe to release notifications");
        System.out.println("  GET  /releases/subscriptions - List active subscriptions");
        System.out.println();
        System.out.println("Background: Release checker running every 30 minutes");
        System.out.println();
    }

    // =========================================================================
    // Health Check
    // =========================================================================

    private void handleHealth(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        boolean jadxOk = new File("/opt/jadx/bin/jadx").exists();
        boolean ghidraOk = new File("/opt/ghidra/support/analyzeHeadless").exists();

        String json = String.format("""
            {
              "status": "ok",
              "tools": {
                "jadx": %s,
                "ghidra": %s
              },
              "apks_dir": "%s",
              "output_dir": "%s"
            }
            """, jadxOk, ghidraOk, APKS_DIR, OUTPUT_DIR);

        sendJson(exchange, 200, json);
    }

    // =========================================================================
    // List APKs
    // =========================================================================

    private void handleApks(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        List<Map<String, Object>> apks = new ArrayList<>();
        File apksDir = new File(APKS_DIR);

        if (apksDir.exists()) {
            findApks(apksDir, apksDir, apks);
        }

        StringBuilder json = new StringBuilder();
        json.append("{\"apks\": [");
        for (int i = 0; i < apks.size(); i++) {
            if (i > 0) json.append(",");
            Map<String, Object> apk = apks.get(i);
            json.append(String.format("""
                {"path": "%s", "name": "%s", "size": %d}""",
                escape(apk.get("path").toString()),
                escape(apk.get("name").toString()),
                apk.get("size")));
        }
        json.append("]}");

        sendJson(exchange, 200, json.toString());
    }

    private void findApks(File baseDir, File dir, List<Map<String, Object>> apks) {
        File[] files = dir.listFiles();
        if (files == null) return;

        for (File file : files) {
            if (file.isDirectory()) {
                findApks(baseDir, file, apks);
            } else if (file.getName().endsWith(".apk") || file.getName().endsWith(".xapk")) {
                Map<String, Object> apk = new HashMap<>();
                String relativePath = baseDir.toPath().relativize(file.toPath()).toString();
                apk.put("path", relativePath);
                apk.put("name", file.getName());
                apk.put("size", file.length());
                apks.add(apk);
            }
        }
    }

    // =========================================================================
    // Analyze APK
    // =========================================================================

    private void handleAnalyze(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("POST")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        // Parse request body
        String body = new String(exchange.getRequestBody().readAllBytes());
        Map<String, String> params = parseJson(body);

        String apkPath = params.get("apk");
        if (apkPath == null || apkPath.isEmpty()) {
            sendError(exchange, 400, "Missing 'apk' parameter");
            return;
        }

        File apkFile = new File(APKS_DIR, apkPath);
        if (!apkFile.exists()) {
            sendError(exchange, 404, "APK not found: " + apkPath);
            return;
        }

        boolean analyzeNatives = "true".equals(params.get("natives"));
        boolean decompile = !"false".equals(params.get("decompile")); // default true

        try {
            // Create job in global database
            String optionsJson = String.format("{\"natives\": %s, \"decompile\": %s}",
                analyzeNatives, decompile);
            String jobId = globalDb.createJob(apkPath, optionsJson);

            // Start analysis in background
            analysisExecutor.submit(() -> runAnalysis(jobId, apkFile, analyzeNatives, decompile));

            String json = String.format("""
                {
                  "id": "%s",
                  "status": "pending",
                  "message": "Analysis job created"
                }
                """, jobId);

            sendJson(exchange, 202, json);

        } catch (Exception e) {
            sendError(exchange, 500, "Failed to create job: " + e.getMessage());
        }
    }

    private void runAnalysis(String jobId, File apkFile, boolean analyzeNatives, boolean decompile) {
        Database apkDb = null;
        long totalTimingId = 0;
        File extractedApk = null;
        File xapkTempDir = null;
        try {
            globalDb.updateJobStatus(jobId, "running", 0, "Starting analysis...");

            // Check if this is an XAPK file (ZIP containing base.apk)
            File fileToAnalyze = apkFile;
            if (apkFile.getName().toLowerCase().endsWith(".xapk")) {
                globalDb.updateJobStatus(jobId, "running", 5, "Extracting XAPK...");
                xapkTempDir = new File(OUTPUT_DIR, jobId + "_xapk_temp");
                extractedApk = extractXapk(apkFile, xapkTempDir);
                if (extractedApk != null && extractedApk.exists()) {
                    fileToAnalyze = extractedApk;
                    System.out.println("[XAPK] Extracted base.apk: " + extractedApk.getAbsolutePath());
                } else {
                    System.err.println("[XAPK] Failed to extract base.apk, attempting to analyze original file");
                }
            }

            // Run JADX analysis first to get package name and version
            globalDb.updateJobStatus(jobId, "running", 10, "Running JADX decompilation...");

            File tempOutputDir = new File(OUTPUT_DIR, jobId);
            tempOutputDir.mkdirs();

            JadxAnalyzer jadx = new JadxAnalyzer(tempOutputDir);
            JadxAnalyzer.DecompilationResult jadxResult = jadx.analyzeApk(fileToAnalyze);

            // Extract version from JADX result (or use "unknown")
            String packageName = jadxResult.packageName != null ? jadxResult.packageName : "unknown";
            String version = jadxResult.versionName != null ? jadxResult.versionName : "unknown";

            // Create per-APK database: data/{package}/{version}/analysis.db
            apkDb = Database.forApk(DATA_DIR, packageName, version);
            apkDb.initializeApkSchema();

            // Setup output directory structure
            File versionDir = Database.getVersionDir(DATA_DIR, packageName, version);

            // Copy JADX output to version directory (copy instead of move for cross-filesystem support)
            File jadxOutput = new File(tempOutputDir, "jadx_output");
            File jadxSources = new File(jadxOutput, "sources");
            File jadxResources = new File(jadxOutput, "resources");
            File targetSources = new File(versionDir, "sources");
            File targetResources = new File(versionDir, "resources");

            if (jadxSources.exists()) {
                copyDirectory(jadxSources, targetSources);
            }
            if (jadxResources.exists()) {
                copyDirectory(jadxResources, targetResources);
            }

            // Start timing
            totalTimingId = apkDb.startTiming(jobId, "total");
            apkDb.log(jobId, "INFO", "init", "Starting analysis for: " + apkFile.getName());
            apkDb.log(jobId, "INFO", "init", "Database: " + apkDb.getDbPath());

            // Log JADX completion
            long jadxTimingId = apkDb.startTiming(jobId, "jadx_decompilation");
            apkDb.endTiming(jadxTimingId, "completed");
            apkDb.log(jobId, "INFO", "jadx", String.format("JADX completed: %d classes, %d resources",
                jadxResult.totalClasses, jadxResult.resources.size()));

            // Save to database
            apkDb.log(jobId, "INFO", "database", "Saving results to database...");
            globalDb.updateJobStatus(jobId, "running", 60, "Saving results to database...");
            long dbTimingId = apkDb.startTiming(jobId, "database_save");

            int failedClasses = 0;
            int failedMethods = 0;
            int totalMethods = 0;

            // Build batch data and count stats
            List<Database.ClassData> classDataList = new ArrayList<>();
            for (JadxAnalyzer.ClassInfo cls : jadxResult.classes) {
                totalMethods += cls.methods.size();

                Database.ClassData classData = new Database.ClassData();
                classData.name = cls.fullName;
                classData.packageName = cls.packageName;
                // Compute source path relative to version directory
                classData.sourcePath = "sources/" + cls.fullName.replace('.', '/') + ".java";
                classData.methodCount = cls.methods.size();
                classData.decompileFailed = cls.decompileFailed;
                classData.errorMessage = cls.errorMessage;

                int classFailedMethods = 0;
                for (JadxAnalyzer.MethodInfo method : cls.methods) {
                    Database.MethodData methodData = new Database.MethodData();
                    methodData.name = method.name;
                    methodData.signature = method.signature;
                    methodData.decompileFailed = method.decompileFailed;
                    methodData.errorMessage = method.errorMessage;
                    classData.methods.add(methodData);

                    if (method.decompileFailed) {
                        classFailedMethods++;
                        failedMethods++;
                    }
                }

                classData.failedMethods = classFailedMethods;
                if (cls.decompileFailed) failedClasses++;

                classDataList.add(classData);
            }

            // Batch save all classes and methods
            apkDb.saveClassesBatch(classDataList);
            apkDb.log(jobId, "INFO", "database", String.format("Saved %d classes with %d methods",
                classDataList.size(), totalMethods));

            // Save method calls (call graph)
            if (!jadxResult.methodCalls.isEmpty()) {
                apkDb.log(jobId, "INFO", "database", String.format("Saving %d method calls...", jadxResult.methodCalls.size()));
                List<Database.MethodCallData> callDataList = new ArrayList<>();
                for (JadxAnalyzer.MethodCall call : jadxResult.methodCalls) {
                    callDataList.add(new Database.MethodCallData(
                        call.callerClass, call.callerMethod, call.callerSignature,
                        call.calleeClass, call.calleeMethod, call.calleeSignature
                    ));
                }
                apkDb.saveMethodCallsBatch(callDataList);
                apkDb.log(jobId, "INFO", "database", String.format("Saved %d method calls", callDataList.size()));
            }

            apkDb.endTiming(dbTimingId, "completed");

            // Save APK info
            apkDb.saveApkInfo(packageName, version, apkFile.getName(), apkFile.length(), 0, 0);

            // Save permissions
            for (String perm : jadxResult.permissions) {
                apkDb.savePermission(perm, isDangerousPermission(perm));
            }

            // Save components
            for (String activity : jadxResult.activities) {
                apkDb.saveComponent("activity", activity);
            }
            for (String service : jadxResult.services) {
                apkDb.saveComponent("service", service);
            }

            // Save security findings
            for (String issue : jadxResult.securityIssues) {
                apkDb.saveSecurityFinding("security_issue", "medium", issue, null);
            }
            for (String secret : jadxResult.potentialSecrets) {
                apkDb.saveSecurityFinding("potential_secret", "high", secret, null);
            }

            // Save URLs
            Set<String> uniqueUrls = new HashSet<>(jadxResult.allUrls);
            for (String url : uniqueUrls) {
                apkDb.saveUrl(url, null);
            }

            // Generate report
            File reportFile = new File(versionDir, "jadx_analysis_report.txt");
            jadx.generateReport(jadxResult, reportFile);

            // Native analysis if requested - only arm64-v8a to avoid duplicates
            int libsAnalyzed = 0;
            if (analyzeNatives && !jadxResult.nativeLibraries.isEmpty()) {
                // Filter to arm64-v8a only
                List<String> arm64Libs = jadxResult.nativeLibraries.stream()
                    .filter(lib -> lib.contains("arm64-v8a"))
                    .toList();

                apkDb.log(jobId, "INFO", "ghidra", String.format(
                    "Starting native library analysis (%d arm64 libs of %d total)...",
                    arm64Libs.size(), jadxResult.nativeLibraries.size()));
                globalDb.updateJobStatus(jobId, "running", 80, "Analyzing native libraries...");
                long nativeTimingId = apkDb.startTiming(jobId, "native_analysis");

                File workDir = new File(versionDir, "native_work");
                workDir.mkdirs();

                for (String libPath : arm64Libs) {
                    try {
                        File libFile = extractFromApk(fileToAnalyze, libPath, workDir);
                        if (libFile != null) {
                            long libSize = libFile.length() / (1024 * 1024); // MB
                            apkDb.log(jobId, "INFO", "ghidra", String.format(
                                "Analyzing: %s (%d MB)", libPath, libSize));

                            // Create separate database for this native library
                            String libName = libFile.getName();
                            Database nativeDb = Database.forNativeLib(DATA_DIR, packageName, version, libName);
                            nativeDb.initializeNativeSchema();

                            GhidraAnalyzer ghidra = new GhidraAnalyzer(versionDir);
                            GhidraAnalyzer.AnalysisResult ghidraResult = ghidra.analyzeFile(libFile, true);

                            String arch = libPath.contains("arm64") ? "arm64-v8a" :
                                         libPath.contains("armeabi") ? "armeabi-v7a" :
                                         libPath.contains("x86_64") ? "x86_64" :
                                         libPath.contains("x86") ? "x86" : "unknown";

                            // Save lib info in the native database
                            nativeDb.saveLibInfo(libName, libPath, arch, libFile.length(),
                                ghidraResult.languageId, ghidraResult.compilerSpec, ghidraResult.imageBase);

                            // Save decompiled functions to files
                            int decompiledCount = ghidra.saveDecompiledFunctions(ghidraResult, versionDir, libName);

                            // Save functions to native database (with decompiled paths)
                            for (GhidraAnalyzer.FunctionInfo func : ghidraResult.functions) {
                                nativeDb.saveFunction(func.name, func.address, func.signature,
                                    func.callingConvention, func.parameterCount, func.bodySize,
                                    func.isThunk, func.isExternal, !func.name.startsWith("FUN_"),
                                    func.decompiledPath);
                            }

                            // Save strings to native database
                            for (String str : ghidraResult.strings) {
                                nativeDb.saveString(str, null);
                            }

                            // Save imports to native database
                            for (String imp : ghidraResult.imports) {
                                nativeDb.saveImport(imp);
                            }

                            // Save exports to native database
                            for (String exp : ghidraResult.exports) {
                                nativeDb.saveExport(exp);
                            }

                            // Save memory sections to native database
                            for (GhidraAnalyzer.MemorySection section : ghidraResult.memorySections) {
                                nativeDb.saveMemorySection(section.name, section.start, section.end,
                                    section.size, section.isRead, section.isWrite, section.isExecute, section.isInitialized);
                            }

                            // Save metadata to main APK database with db_path reference
                            String relativeDbPath = "natives/" + libName + ".db";
                            apkDb.saveNativeLibMetadata(libPath, libName, arch, libFile.length(),
                                true, ghidraResult.functions.size(), ghidraResult.strings.size(),
                                ghidraResult.imports.size(), ghidraResult.exports.size(), relativeDbPath);

                            apkDb.log(jobId, "INFO", "ghidra", String.format("Analyzed %s: %d functions (%d decompiled), db: %s",
                                libName, ghidraResult.functions.size(), decompiledCount, relativeDbPath));
                            libsAnalyzed++;
                        }
                    } catch (Exception e) {
                        apkDb.log(jobId, "WARN", "ghidra", "Failed to analyze " + libPath + ": " + e.getMessage());
                    }
                }

                apkDb.endTiming(nativeTimingId, "completed");
                apkDb.log(jobId, "INFO", "ghidra", String.format("Native analysis complete: %d libraries", libsAnalyzed));
            }

            // Save analysis summary
            apkDb.saveAnalysisSummary(jadxResult.totalClasses, totalMethods, failedClasses, failedMethods,
                jadxResult.nativeLibraries.size(), libsAnalyzed, versionDir.getAbsolutePath());

            apkDb.endTiming(totalTimingId, "completed");
            apkDb.log(jobId, "INFO", "complete", String.format(
                "Analysis complete. Classes: %d (failed: %d), Methods: %d (failed: %d)",
                jadxResult.totalClasses, failedClasses, totalMethods, failedMethods));

            globalDb.updateJobStatus(jobId, "completed", 100,
                String.format("Analysis complete. DB: %s. Classes: %d (failed: %d), Methods: %d (failed: %d)",
                    apkDb.getDbPath(), jadxResult.totalClasses, failedClasses, totalMethods, failedMethods));

            // Update tracking database to mark version as analyzed
            updateTrackingDbAnalyzed(packageName, version, apkDb.getDbPath());

            // Cleanup XAPK temp directory
            if (xapkTempDir != null && xapkTempDir.exists()) {
                deleteDirectory(xapkTempDir);
            }

        } catch (Exception e) {
            try {
                if (apkDb != null && totalTimingId > 0) apkDb.endTiming(totalTimingId, "failed");
                if (apkDb != null) apkDb.log(jobId, "ERROR", "error", "Analysis failed: " + e.getMessage());
                globalDb.updateJobStatus(jobId, "failed", 0, "Error: " + e.getMessage());
            } catch (Exception ignored) {}
            e.printStackTrace();
        } finally {
            // Cleanup XAPK temp directory on error too
            if (xapkTempDir != null && xapkTempDir.exists()) {
                deleteDirectory(xapkTempDir);
            }
        }
    }

    /**
     * Extract XAPK file and return the path to base.apk.
     * XAPK is a ZIP file containing base.apk and optional split APKs.
     */
    private File extractXapk(File xapkFile, File outputDir) {
        try {
            outputDir.mkdirs();

            try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(xapkFile)) {
                java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = zip.entries();
                File baseApk = null;

                while (entries.hasMoreElements()) {
                    java.util.zip.ZipEntry entry = entries.nextElement();
                    String name = entry.getName();

                    // Extract base.apk or any .apk file
                    if (name.endsWith(".apk") && !entry.isDirectory()) {
                        File outFile = new File(outputDir, new File(name).getName());
                        try (InputStream in = zip.getInputStream(entry);
                             FileOutputStream out = new FileOutputStream(outFile)) {
                            in.transferTo(out);
                        }

                        // Prefer base.apk, but fall back to any APK
                        if (name.equals("base.apk") || name.endsWith("/base.apk")) {
                            baseApk = outFile;
                        } else if (baseApk == null && !name.contains("config.") && !name.contains("split_config")) {
                            // Use first non-config APK as fallback
                            baseApk = outFile;
                        }
                    }
                }

                return baseApk;
            }
        } catch (Exception e) {
            System.err.println("[XAPK] Error extracting: " + e.getMessage());
            return null;
        }
    }

    /**
     * Recursively delete a directory.
     */
    private void deleteDirectory(File dir) {
        if (dir == null || !dir.exists()) return;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    deleteDirectory(file);
                } else {
                    file.delete();
                }
            }
        }
        dir.delete();
    }

    // =========================================================================
    // Analyze Specific Native Library
    // =========================================================================

    private void handleNative(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("POST")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String body = new String(exchange.getRequestBody().readAllBytes());
        Map<String, String> params = parseJson(body);

        String apkPath = params.get("apk");
        String libraryPath = params.get("library");

        if (apkPath == null || libraryPath == null) {
            sendError(exchange, 400, "Missing 'apk' or 'library' parameter");
            return;
        }

        File apkFile = new File(APKS_DIR, apkPath);
        if (!apkFile.exists()) {
            sendError(exchange, 404, "APK not found: " + apkPath);
            return;
        }

        try {
            String optionsJson = String.format("{\"library\": \"%s\"}", escape(libraryPath));
            String jobId = globalDb.createJob(apkPath, optionsJson);

            // Start native analysis in background
            analysisExecutor.submit(() -> runNativeAnalysis(jobId, apkFile, libraryPath));

            String json = String.format("""
                {
                  "id": "%s",
                  "status": "pending",
                  "message": "Native analysis job created"
                }
                """, jobId);

            sendJson(exchange, 202, json);

        } catch (Exception e) {
            sendError(exchange, 500, "Failed to create job: " + e.getMessage());
        }
    }

    private void runNativeAnalysis(String jobId, File apkFile, String libraryPath) {
        try {
            globalDb.updateJobStatus(jobId, "running", 0, "Extracting native library...");

            File outputDir = new File(OUTPUT_DIR, jobId);
            File workDir = new File(outputDir, "work");
            workDir.mkdirs();

            // Extract the specific library from APK
            File libFile = extractFromApk(apkFile, libraryPath, workDir);
            if (libFile == null) {
                globalDb.updateJobStatus(jobId, "failed", 0, "Library not found in APK: " + libraryPath);
                return;
            }

            globalDb.updateJobStatus(jobId, "running", 30, "Running Ghidra analysis...");

            // Run Ghidra analysis
            GhidraAnalyzer ghidra = new GhidraAnalyzer(outputDir);
            GhidraAnalyzer.AnalysisResult result = ghidra.analyzeFile(libFile, true);

            globalDb.updateJobStatus(jobId, "running", 80, "Saving results...");

            // Create standalone native database
            String libName = libFile.getName();
            Database nativeDb = new Database(outputDir.getAbsolutePath() + "/" + libName + ".db");
            nativeDb.initializeNativeSchema();

            String arch = libraryPath.contains("arm64") ? "arm64-v8a" :
                         libraryPath.contains("armeabi") ? "armeabi-v7a" :
                         libraryPath.contains("x86_64") ? "x86_64" : "unknown";

            // Save lib info
            nativeDb.saveLibInfo(libName, libraryPath, arch, libFile.length(),
                result.languageId, result.compilerSpec, result.imageBase);

            // Save decompiled functions to files
            int decompiledCount = ghidra.saveDecompiledFunctions(result, outputDir, libName);

            // Save functions (with decompiled paths)
            for (GhidraAnalyzer.FunctionInfo func : result.functions) {
                nativeDb.saveFunction(func.name, func.address, func.signature,
                    func.callingConvention, func.parameterCount, func.bodySize,
                    func.isThunk, func.isExternal, !func.name.startsWith("FUN_"),
                    func.decompiledPath);
            }

            // Save strings
            for (String str : result.strings) {
                nativeDb.saveString(str, null);
            }

            // Save imports
            for (String imp : result.imports) {
                nativeDb.saveImport(imp);
            }

            // Save exports
            for (String exp : result.exports) {
                nativeDb.saveExport(exp);
            }

            // Save memory sections
            for (GhidraAnalyzer.MemorySection section : result.memorySections) {
                nativeDb.saveMemorySection(section.name, section.start, section.end,
                    section.size, section.isRead, section.isWrite, section.isExecute, section.isInitialized);
            }

            // Generate report
            File reportFile = new File(outputDir, "ghidra_report.txt");
            ghidra.generateReport(result, reportFile);

            globalDb.updateJobStatus(jobId, "completed", 100,
                String.format("Native analysis complete. DB: %s. Functions: %d (%d decompiled), Strings: %d",
                    nativeDb.getDbPath(), result.functions.size(), decompiledCount, result.strings.size()));

        } catch (Exception e) {
            try {
                globalDb.updateJobStatus(jobId, "failed", 0, "Error: " + e.getMessage());
            } catch (Exception ignored) {}
            e.printStackTrace();
        }
    }

    private File extractFromApk(File apkFile, String entryPath, File outputDir) {
        try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(apkFile)) {
            java.util.zip.ZipEntry entry = zip.getEntry(entryPath);
            if (entry == null) return null;

            File outFile = new File(outputDir, new File(entryPath).getName());
            try (InputStream in = zip.getInputStream(entry);
                 FileOutputStream out = new FileOutputStream(outFile)) {
                in.transferTo(out);
            }
            return outFile;
        } catch (Exception e) {
            return null;
        }
    }

    private void copyDirectory(File source, File target) {
        try {
            if (!source.exists()) return;
            target.mkdirs();

            File[] files = source.listFiles();
            if (files == null) return;

            for (File file : files) {
                File targetFile = new File(target, file.getName());
                if (file.isDirectory()) {
                    copyDirectory(file, targetFile);
                } else {
                    Files.copy(file.toPath(), targetFile.toPath(),
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
        } catch (Exception e) {
            System.err.println("[Warning] Failed to copy " + source + " to " + target + ": " + e.getMessage());
        }
    }

    // =========================================================================
    // Job Status
    // =========================================================================

    private void handleStatus(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String path = exchange.getRequestURI().getPath();
        String jobId = path.substring("/status/".length());

        if (jobId.isEmpty()) {
            sendError(exchange, 400, "Missing job ID");
            return;
        }

        try {
            Map<String, Object> job = globalDb.getJob(jobId);
            if (job == null) {
                sendError(exchange, 404, "Job not found: " + jobId);
                return;
            }

            String json = String.format("""
                {
                  "id": "%s",
                  "status": "%s",
                  "progress": %d,
                  "message": "%s",
                  "started_at": %s,
                  "completed_at": %s
                }
                """,
                job.get("id"),
                job.get("status"),
                job.get("progress"),
                escape(job.get("message") != null ? job.get("message").toString() : ""),
                job.get("started_at"),
                job.get("completed_at"));

            sendJson(exchange, 200, json);

        } catch (Exception e) {
            sendError(exchange, 500, "Error: " + e.getMessage());
        }
    }

    // =========================================================================
    // Analysis Results
    // =========================================================================

    private void handleAnalysis(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String path = exchange.getRequestURI().getPath();
        String jobId = path.substring("/analysis/".length());

        if (jobId.isEmpty()) {
            sendError(exchange, 400, "Missing job ID");
            return;
        }

        try {
            // Get job to find the database path from message
            Map<String, Object> job = globalDb.getJob(jobId);
            if (job == null) {
                sendError(exchange, 404, "Job not found: " + jobId);
                return;
            }

            // Parse database path from job message (format: "Analysis complete. DB: /path/to/analysis.db. Classes...")
            String message = nullSafe(job.get("message"));
            String dbPath = null;
            if (message.contains("DB: ")) {
                int start = message.indexOf("DB: ") + 4;
                int end = message.indexOf(".db", start);
                if (end > start) {
                    dbPath = message.substring(start, end + 3); // include .db
                }
            }

            // If we found a DB path, use that database; otherwise return basic job info
            if (dbPath != null && new File(dbPath).exists()) {
                Database apkDb = new Database(dbPath);

                Map<String, Object> analysis = apkDb.getAnalysis(jobId);
                if (analysis == null) {
                    sendError(exchange, 404, "Analysis not found in database: " + dbPath);
                    return;
                }

                // Build JSON response
                StringBuilder json = new StringBuilder();
                json.append("{\n");
                json.append(String.format("  \"id\": \"%s\",\n", jobId));
                json.append(String.format("  \"database_path\": \"%s\",\n", escape(dbPath)));
                json.append(String.format("  \"total_classes\": %s,\n", nullSafe(analysis.get("total_classes"))));
                json.append(String.format("  \"total_methods\": %s,\n", nullSafe(analysis.get("total_methods"))));
                json.append(String.format("  \"failed_classes\": %s,\n", nullSafe(analysis.get("failed_classes"))));
                json.append(String.format("  \"failed_methods\": %s,\n", nullSafe(analysis.get("failed_methods"))));
                json.append(String.format("  \"output_path\": \"%s\",\n", escape(nullSafe(analysis.get("output_path")))));

                // Permissions
                json.append("  \"permissions\": ").append(toJsonArray((List<?>) analysis.get("permissions"), "permission")).append(",\n");

                // Components
                json.append("  \"components\": ").append(toJsonObjectArray((List<?>) analysis.get("components"))).append(",\n");

                // Native libs
                json.append("  \"native_libs\": ").append(toJsonObjectArray((List<?>) analysis.get("native_libs"))).append(",\n");

                // Security findings
                json.append("  \"security_findings\": ").append(toJsonObjectArray((List<?>) analysis.get("security_findings"))).append(",\n");

                // Timing data
                List<Map<String, Object>> timings = apkDb.getTimings(jobId);
                json.append("  \"timing\": ").append(toJsonObjectArray(timings)).append(",\n");

                // Logs
                List<Map<String, Object>> logs = apkDb.getLogs(jobId);
                json.append("  \"logs\": ").append(toJsonObjectArray(logs)).append("\n");

                json.append("}");

                sendJson(exchange, 200, json.toString());
            } else {
                // Return basic job info if database not found
                String json = String.format("""
                    {
                      "id": "%s",
                      "status": "%s",
                      "message": "%s",
                      "note": "Full analysis results are in the APK-specific database"
                    }
                    """, jobId, job.get("status"), escape(message));
                sendJson(exchange, 200, json);
            }

        } catch (Exception e) {
            e.printStackTrace();
            sendError(exchange, 500, "Error: " + e.getMessage());
        }
    }

    // =========================================================================
    // Download Versions
    // =========================================================================

    private void handleDownloadVersions(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        // Parse query parameters
        String query = exchange.getRequestURI().getQuery();
        String packageName = "com.whatsapp"; // default

        if (query != null) {
            for (String param : query.split("&")) {
                String[] kv = param.split("=", 2);
                if (kv.length == 2 && kv[0].equals("package")) {
                    packageName = kv[1];
                }
            }
        }

        try {
            // Call Python script to list versions
            String[] cmd = {
                "python3", "/workspace/scripts/download_apk.py",
                "-p", packageName,
                "-l", "--json"
            };

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(false);
            Process process = pb.start();

            String stdout = new String(process.getInputStream().readAllBytes());
            String stderr = new String(process.getErrorStream().readAllBytes());

            int exitCode = process.waitFor();

            if (exitCode == 0 && !stdout.isEmpty()) {
                sendJson(exchange, 200, stdout);
            } else {
                sendError(exchange, 500, "Failed to fetch versions: " + stderr);
            }

        } catch (Exception e) {
            sendError(exchange, 500, "Error: " + e.getMessage());
        }
    }

    // =========================================================================
    // Download APK
    // =========================================================================

    private void handleDownload(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("POST")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        // Parse request body
        String body = new String(exchange.getRequestBody().readAllBytes());
        Map<String, String> params = parseJson(body);

        String packageName = params.get("package");
        String version = params.get("version");

        if (packageName == null || packageName.isEmpty()) {
            sendError(exchange, 400, "Missing 'package' parameter");
            return;
        }

        // Default to "latest" if no version specified
        if (version == null || version.isEmpty()) {
            version = "latest";
        }

        try {
            // Create download job
            String optionsJson = String.format("{\"package\": \"%s\", \"version\": \"%s\"}",
                escape(packageName), escape(version));
            String jobId = globalDb.createJob("download:" + packageName, optionsJson);

            // Start download in background
            final String pkg = packageName;
            final String ver = version;
            analysisExecutor.submit(() -> runDownload(jobId, pkg, ver));

            String json = String.format("""
                {
                  "id": "%s",
                  "status": "pending",
                  "message": "Download job created for %s %s"
                }
                """, jobId, packageName, version);

            sendJson(exchange, 202, json);

        } catch (Exception e) {
            sendError(exchange, 500, "Failed to create download job: " + e.getMessage());
        }
    }

    private void runDownload(String jobId, String packageName, String version) {
        try {
            globalDb.updateJobStatus(jobId, "running", 10, "Fetching version info...");

            // Call Python script to download
            String[] cmd = {
                "python3", "/workspace/scripts/download_apk.py",
                "-p", packageName,
                "-v", version,
                "-o", APKS_DIR,
                "--json"
            };

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(false);
            Process process = pb.start();

            // Read output
            String stdout = new String(process.getInputStream().readAllBytes());
            String stderr = new String(process.getErrorStream().readAllBytes());

            int exitCode = process.waitFor();

            if (exitCode == 0 && !stdout.isEmpty()) {
                globalDb.updateJobStatus(jobId, "completed", 100, "Download completed: " + stdout);
                // Update tracking database to mark version as downloaded
                updateTrackingDbDownloaded(packageName, version);
            } else {
                globalDb.updateJobStatus(jobId, "failed", 0, "Download failed: " + stderr);
            }

        } catch (Exception e) {
            try {
                globalDb.updateJobStatus(jobId, "failed", 0, "Error: " + e.getMessage());
            } catch (Exception ignored) {}
            e.printStackTrace();
        }
    }

    // =========================================================================
    // Version Tracking Endpoints (using version_tracker.py)
    // =========================================================================

    /**
     * GET /track/scrape - Scrape versions for a package and save to database
     * Query params: package (default: com.whatsapp), source (apkpure, uptodown, all)
     */
    private void handleTrackScrape(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String query = exchange.getRequestURI().getQuery();
        String packageName = getQueryParam(query, "package", "com.whatsapp");
        String source = getQueryParam(query, "source", "all");

        try {
            String[] cmd = {
                "python3", getScriptPath("version_tracker.py"),
                "-p", packageName,
                "--scrape",
                "--source", source,
                "--json",
                "-d", DATA_DIR + "/tracking.db"
            };

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(false);
            Process process = pb.start();

            String stdout = new String(process.getInputStream().readAllBytes());
            String stderr = new String(process.getErrorStream().readAllBytes());
            int exitCode = process.waitFor();

            if (exitCode == 0 && !stdout.isEmpty()) {
                sendJson(exchange, 200, stdout);
            } else {
                // If stderr has content but stdout is empty, use stderr for error
                String errorMsg = stderr.isEmpty() ? "Unknown error" : stderr.trim();
                sendError(exchange, 500, "Scrape failed: " + errorMsg);
            }

        } catch (Exception e) {
            sendError(exchange, 500, "Error: " + e.getMessage());
        }
    }

    /**
     * GET /track/versions - List versions from tracking database
     * Query params: package, channel (stable, beta, all), limit, source
     */
    private void handleTrackVersions(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String query = exchange.getRequestURI().getQuery();
        String packageName = getQueryParam(query, "package", "com.whatsapp");
        String channel = getQueryParam(query, "channel", "all");
        String limit = getQueryParam(query, "limit", "50");

        try {
            List<String> cmdList = new ArrayList<>();
            cmdList.add("python3");
            cmdList.add(getScriptPath("version_tracker.py"));
            cmdList.add("-p");
            cmdList.add(packageName);
            cmdList.add("--list");
            cmdList.add("--channel");
            cmdList.add(channel);
            cmdList.add("--limit");
            cmdList.add(limit);
            cmdList.add("--json");
            cmdList.add("-d");
            cmdList.add(DATA_DIR + "/tracking.db");

            ProcessBuilder pb = new ProcessBuilder(cmdList);
            pb.redirectErrorStream(false);
            Process process = pb.start();

            String stdout = new String(process.getInputStream().readAllBytes());
            String stderr = new String(process.getErrorStream().readAllBytes());
            int exitCode = process.waitFor();

            if (exitCode == 0 && !stdout.isEmpty()) {
                sendJson(exchange, 200, stdout);
            } else {
                sendError(exchange, 500, "List failed: " + stderr);
            }

        } catch (Exception e) {
            sendError(exchange, 500, "Error: " + e.getMessage());
        }
    }

    /**
     * GET /track/status - Show tracking database status
     */
    private void handleTrackStatus(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        try {
            File trackingDb = new File(DATA_DIR, "tracking.db");

            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"database\": \"").append(escape(trackingDb.getAbsolutePath())).append("\",\n");
            json.append("  \"exists\": ").append(trackingDb.exists()).append(",\n");

            if (trackingDb.exists()) {
                json.append("  \"size_bytes\": ").append(trackingDb.length()).append(",\n");
                json.append("  \"size_kb\": ").append(trackingDb.length() / 1024).append(",\n");

                // Query database for counts
                String[] cmd = {
                    "sqlite3", trackingDb.getAbsolutePath(),
                    "SELECT " +
                    "(SELECT COUNT(DISTINCT package_name) FROM versions) as packages, " +
                    "(SELECT COUNT(*) FROM versions) as total_versions, " +
                    "(SELECT COUNT(*) FROM versions WHERE channel='stable') as stable, " +
                    "(SELECT COUNT(*) FROM versions WHERE channel='beta') as beta"
                };

                ProcessBuilder pb = new ProcessBuilder(cmd);
                pb.redirectErrorStream(false);
                Process process = pb.start();

                String stdout = new String(process.getInputStream().readAllBytes()).trim();
                int exitCode = process.waitFor();

                if (exitCode == 0 && !stdout.isEmpty()) {
                    String[] parts = stdout.split("\\|");
                    if (parts.length >= 4) {
                        json.append("  \"packages\": ").append(parts[0]).append(",\n");
                        json.append("  \"total_versions\": ").append(parts[1]).append(",\n");
                        json.append("  \"stable_versions\": ").append(parts[2]).append(",\n");
                        json.append("  \"beta_versions\": ").append(parts[3]).append(",\n");
                    }
                }

                // Get list of tracked packages
                String[] pkgCmd = {
                    "sqlite3", trackingDb.getAbsolutePath(),
                    "SELECT package_name, COUNT(*) as count FROM versions GROUP BY package_name ORDER BY count DESC"
                };

                ProcessBuilder pkgPb = new ProcessBuilder(pkgCmd);
                Process pkgProcess = pkgPb.start();
                String pkgOutput = new String(pkgProcess.getInputStream().readAllBytes()).trim();
                pkgProcess.waitFor();

                json.append("  \"tracked_packages\": [");
                if (!pkgOutput.isEmpty()) {
                    String[] lines = pkgOutput.split("\n");
                    for (int i = 0; i < lines.length; i++) {
                        String[] kv = lines[i].split("\\|");
                        if (kv.length >= 2) {
                            if (i > 0) json.append(", ");
                            json.append("{\"package\": \"").append(kv[0]).append("\", \"versions\": ").append(kv[1]).append("}");
                        }
                    }
                }
                json.append("]\n");
            } else {
                json.append("  \"tracked_packages\": []\n");
            }

            json.append("}");

            sendJson(exchange, 200, json.toString());

        } catch (Exception e) {
            sendError(exchange, 500, "Error: " + e.getMessage());
        }
    }

    /**
     * POST /track/add - Add a new package to track
     * Body: { "package": "com.example.app", "name": "Example App" }
     */
    private void handleTrackAdd(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("POST")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String body = new String(exchange.getRequestBody().readAllBytes());
        Map<String, String> params = parseJson(body);

        String packageName = params.get("package");
        String displayName = params.getOrDefault("name", packageName);

        if (packageName == null || packageName.isEmpty()) {
            sendError(exchange, 400, "Missing 'package' parameter");
            return;
        }

        try {
            // Initialize the tracking database and add the package
            String[] initCmd = {
                "python3", getScriptPath("version_tracker.py"),
                "-d", DATA_DIR + "/tracking.db",
                "--init"
            };

            ProcessBuilder initPb = new ProcessBuilder(initCmd);
            Process initProcess = initPb.start();
            initProcess.waitFor();

            // Run initial scrape for the package
            String[] scrapeCmd = {
                "python3", getScriptPath("version_tracker.py"),
                "-p", packageName,
                "-d", DATA_DIR + "/tracking.db",
                "--scrape",
                "--json"
            };

            ProcessBuilder pb = new ProcessBuilder(scrapeCmd);
            pb.redirectErrorStream(false);
            Process process = pb.start();

            String stdout = new String(process.getInputStream().readAllBytes());
            String stderr = new String(process.getErrorStream().readAllBytes());
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                // Parse the result to get the count
                String json = String.format("""
                    {
                      "package": "%s",
                      "name": "%s",
                      "status": "added",
                      "initial_scrape": %s
                    }
                    """,
                    escape(packageName),
                    escape(displayName),
                    stdout.isEmpty() ? "{}" : stdout.trim());
                sendJson(exchange, 201, json);
            } else {
                sendError(exchange, 500, "Failed to add package: " + stderr);
            }

        } catch (Exception e) {
            sendError(exchange, 500, "Error: " + e.getMessage());
        }
    }

    // =========================================================================
    // Release Tracking Endpoints (legacy)
    // =========================================================================

    /**
     * GET /releases - Get latest releases from APKPure
     * Query params: package (default: com.whatsapp)
     */
    private void handleReleases(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String query = exchange.getRequestURI().getQuery();
        String packageName = getQueryParam(query, "package", "com.whatsapp");

        try {
            // Call Python script to get releases
            String[] cmd = {
                "python3", getScriptPath("track_releases.py"),
                "--list", "--json"
            };

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(false);
            Process process = pb.start();

            String stdout = new String(process.getInputStream().readAllBytes());
            String stderr = new String(process.getErrorStream().readAllBytes());
            int exitCode = process.waitFor();

            if (exitCode == 0 && !stdout.isEmpty()) {
                sendJson(exchange, 200, stdout);
            } else {
                sendError(exchange, 500, "Failed to fetch releases: " + stderr);
            }

        } catch (Exception e) {
            sendError(exchange, 500, "Error: " + e.getMessage());
        }
    }

    /**
     * GET /releases/check - Check for new releases and save to database
     * Query params: package (default: com.whatsapp)
     */
    private void handleReleasesCheck(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String query = exchange.getRequestURI().getQuery();
        String packageName = getQueryParam(query, "package", "com.whatsapp");

        try {
            // Call Python script to check releases
            String[] cmd = {
                "python3", getScriptPath("track_releases.py"),
                "--check", "--json"
            };

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(false);
            Process process = pb.start();

            String stdout = new String(process.getInputStream().readAllBytes());
            String stderr = new String(process.getErrorStream().readAllBytes());
            int exitCode = process.waitFor();

            if (exitCode != 0 || stdout.isEmpty()) {
                sendError(exchange, 500, "Failed to check releases: " + stderr);
                return;
            }

            // Parse result and save new releases to database
            List<Map<String, Object>> newReleases = parseReleasesJson(stdout);
            int savedCount = 0;

            for (Map<String, Object> release : newReleases) {
                String version = (String) release.get("version");
                String channel = (String) release.get("channel");
                String arch = (String) release.get("arch");
                String url = (String) release.get("url");
                boolean isBeta = Boolean.TRUE.equals(release.get("is_beta"));
                String source = (String) release.getOrDefault("source", "apkpure");

                boolean isNew = globalDb.saveRelease(packageName, version, channel, arch, url, isBeta, source);
                if (isNew) savedCount++;
            }

            // Get latest versions from database
            Map<String, Map<String, Object>> latest = globalDb.getLatestReleases(packageName);

            // Build response
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"package\": \"").append(packageName).append("\",\n");
            json.append("  \"new_releases_count\": ").append(newReleases.size()).append(",\n");
            json.append("  \"saved_to_db\": ").append(savedCount).append(",\n");
            json.append("  \"latest\": {\n");

            if (latest.containsKey("stable")) {
                Map<String, Object> stable = latest.get("stable");
                json.append("    \"stable\": \"").append(stable.get("version")).append("\",\n");
            } else {
                json.append("    \"stable\": null,\n");
            }

            if (latest.containsKey("beta")) {
                Map<String, Object> beta = latest.get("beta");
                json.append("    \"beta\": \"").append(beta.get("version")).append("\"\n");
            } else {
                json.append("    \"beta\": null\n");
            }

            json.append("  },\n");
            json.append("  \"new_releases\": ").append(toJsonObjectArray(newReleases)).append("\n");
            json.append("}");

            sendJson(exchange, 200, json.toString());

        } catch (Exception e) {
            e.printStackTrace();
            sendError(exchange, 500, "Error: " + e.getMessage());
        }
    }

    /**
     * GET /releases/history - Get release history from database
     * Query params: package, channel (beta/stable/all), limit
     */
    private void handleReleasesHistory(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String query = exchange.getRequestURI().getQuery();
        String packageName = getQueryParam(query, "package", "com.whatsapp");
        String channel = getQueryParam(query, "channel", "all");
        int limit = Integer.parseInt(getQueryParam(query, "limit", "50"));

        try {
            List<Map<String, Object>> releases = globalDb.getReleases(packageName, channel, limit);
            Map<String, Map<String, Object>> latest = globalDb.getLatestReleases(packageName);

            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"package\": \"").append(packageName).append("\",\n");
            json.append("  \"channel_filter\": \"").append(channel).append("\",\n");
            json.append("  \"total\": ").append(releases.size()).append(",\n");
            json.append("  \"latest\": {\n");

            if (latest.containsKey("stable")) {
                json.append("    \"stable\": \"").append(latest.get("stable").get("version")).append("\",\n");
            } else {
                json.append("    \"stable\": null,\n");
            }
            if (latest.containsKey("beta")) {
                json.append("    \"beta\": \"").append(latest.get("beta").get("version")).append("\"\n");
            } else {
                json.append("    \"beta\": null\n");
            }

            json.append("  },\n");
            json.append("  \"releases\": ").append(toJsonObjectArray(releases)).append("\n");
            json.append("}");

            sendJson(exchange, 200, json.toString());

        } catch (Exception e) {
            sendError(exchange, 500, "Error: " + e.getMessage());
        }
    }

    /**
     * POST /releases/subscribe - Subscribe to release notifications
     * Body: { "package": "com.whatsapp", "webhook_url": "https://...", "channel": "all" }
     */
    private void handleReleasesSubscribe(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("POST")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String body = new String(exchange.getRequestBody().readAllBytes());
        Map<String, String> params = parseJson(body);

        String packageName = params.getOrDefault("package", "com.whatsapp");
        String webhookUrl = params.get("webhook_url");
        String channelFilter = params.getOrDefault("channel", "all");

        try {
            long subId = globalDb.createSubscription(packageName, webhookUrl, channelFilter);

            String json = String.format("""
                {
                  "id": %d,
                  "package": "%s",
                  "webhook_url": %s,
                  "channel_filter": "%s",
                  "message": "Subscription created. Releases will be checked every 30 minutes."
                }
                """,
                subId,
                packageName,
                webhookUrl != null ? "\"" + escape(webhookUrl) + "\"" : "null",
                channelFilter);

            sendJson(exchange, 201, json);

        } catch (Exception e) {
            sendError(exchange, 500, "Error: " + e.getMessage());
        }
    }

    /**
     * GET /releases/subscriptions - List active subscriptions
     */
    private void handleReleasesSubscriptions(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        try {
            List<Map<String, Object>> subs = globalDb.getAllActiveSubscriptions();

            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"count\": ").append(subs.size()).append(",\n");
            json.append("  \"subscriptions\": ").append(toJsonObjectArray(subs)).append("\n");
            json.append("}");

            sendJson(exchange, 200, json.toString());

        } catch (Exception e) {
            sendError(exchange, 500, "Error: " + e.getMessage());
        }
    }

    /**
     * Background task: Check releases for all subscriptions.
     */
    private void checkSubscribedReleases() {
        System.out.println("[ReleaseChecker] Running scheduled release check...");

        try {
            List<Map<String, Object>> subs = globalDb.getAllActiveSubscriptions();
            if (subs.isEmpty()) {
                System.out.println("[ReleaseChecker] No active subscriptions");
                return;
            }

            // Group by package to avoid duplicate checks
            Set<String> packages = new HashSet<>();
            for (Map<String, Object> sub : subs) {
                packages.add((String) sub.get("package_name"));
            }

            for (String packageName : packages) {
                try {
                    System.out.println("[ReleaseChecker] Checking: " + packageName);
                    List<Map<String, Object>> newReleases = checkReleasesForPackage(packageName);

                    if (!newReleases.isEmpty()) {
                        System.out.println("[ReleaseChecker] Found " + newReleases.size() + " new releases for " + packageName);

                        // Send webhooks to matching subscriptions
                        for (Map<String, Object> sub : subs) {
                            if (!packageName.equals(sub.get("package_name"))) continue;

                            String webhookUrl = (String) sub.get("webhook_url");
                            String channelFilter = (String) sub.get("channel_filter");

                            if (webhookUrl != null && !webhookUrl.isEmpty()) {
                                // Filter releases by channel if needed
                                List<Map<String, Object>> filteredReleases = newReleases;
                                if (!"all".equals(channelFilter)) {
                                    filteredReleases = newReleases.stream()
                                        .filter(r -> channelFilter.equals(r.get("channel")))
                                        .toList();
                                }

                                if (!filteredReleases.isEmpty()) {
                                    sendWebhookNotification(webhookUrl, packageName, filteredReleases);
                                }
                            }

                            // Update last check time
                            globalDb.updateSubscriptionLastCheck(((Number) sub.get("id")).longValue());
                        }
                    }

                } catch (Exception e) {
                    System.err.println("[ReleaseChecker] Error checking " + packageName + ": " + e.getMessage());
                }
            }

            System.out.println("[ReleaseChecker] Check complete");

        } catch (Exception e) {
            System.err.println("[ReleaseChecker] Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Check releases for a specific package and save new ones to database.
     */
    private List<Map<String, Object>> checkReleasesForPackage(String packageName) throws Exception {
        String[] cmd = {
            "python3", getScriptPath("track_releases.py"),
            "--check", "--json"
        };

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(false);
        Process process = pb.start();

        String stdout = new String(process.getInputStream().readAllBytes());
        process.waitFor();

        List<Map<String, Object>> newReleases = parseReleasesJson(stdout);
        List<Map<String, Object>> savedReleases = new ArrayList<>();

        for (Map<String, Object> release : newReleases) {
            String version = (String) release.get("version");
            String channel = (String) release.get("channel");
            String arch = (String) release.get("arch");
            String url = (String) release.get("url");
            boolean isBeta = Boolean.TRUE.equals(release.get("is_beta"));
            String source = (String) release.getOrDefault("source", "apkpure");

            boolean isNew = globalDb.saveRelease(packageName, version, channel, arch, url, isBeta, source);
            if (isNew) {
                savedReleases.add(release);
            }
        }

        return savedReleases;
    }

    /**
     * Send webhook notification for new releases.
     */
    private void sendWebhookNotification(String webhookUrl, String packageName, List<Map<String, Object>> releases) {
        try {
            StringBuilder payload = new StringBuilder();
            payload.append("{\n");
            payload.append("  \"event\": \"new_releases\",\n");
            payload.append("  \"package\": \"").append(packageName).append("\",\n");
            payload.append("  \"count\": ").append(releases.size()).append(",\n");
            payload.append("  \"releases\": ").append(toJsonObjectArray(releases)).append(",\n");
            payload.append("  \"timestamp\": ").append(System.currentTimeMillis() / 1000).append("\n");
            payload.append("}");

            URL url = new URL(webhookUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload.toString().getBytes(StandardCharsets.UTF_8));
            }

            int responseCode = conn.getResponseCode();
            if (responseCode >= 200 && responseCode < 300) {
                System.out.println("[Webhook] Sent to " + webhookUrl + " - " + responseCode);
            } else {
                System.err.println("[Webhook] Failed: " + webhookUrl + " - " + responseCode);
            }

            conn.disconnect();

        } catch (Exception e) {
            System.err.println("[Webhook] Error sending to " + webhookUrl + ": " + e.getMessage());
        }
    }

    /**
     * Parse releases JSON from Python script output.
     */
    private List<Map<String, Object>> parseReleasesJson(String json) {
        List<Map<String, Object>> releases = new ArrayList<>();

        // Find "new_releases" array in JSON
        int startIdx = json.indexOf("\"new_releases\"");
        if (startIdx == -1) return releases;

        int arrayStart = json.indexOf("[", startIdx);
        if (arrayStart == -1) return releases;

        // Simple parsing - find each object in the array
        int depth = 0;
        int objStart = -1;

        for (int i = arrayStart; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{') {
                if (depth == 1) objStart = i;
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 1 && objStart != -1) {
                    String objJson = json.substring(objStart, i + 1);
                    Map<String, Object> release = parseReleaseObject(objJson);
                    if (release != null) releases.add(release);
                    objStart = -1;
                }
            } else if (c == ']' && depth == 1) {
                break;
            }
        }

        return releases;
    }

    /**
     * Parse a single release object.
     */
    private Map<String, Object> parseReleaseObject(String json) {
        Map<String, Object> release = new HashMap<>();

        // Extract string fields
        String[] stringFields = {"version", "channel", "arch", "url", "source"};
        for (String field : stringFields) {
            String pattern = "\"" + field + "\"\\s*:\\s*\"([^\"]*)\"";
            java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
            if (m.find()) {
                release.put(field, m.group(1));
            }
        }

        // Extract is_beta boolean
        if (json.contains("\"is_beta\": true") || json.contains("\"is_beta\":true")) {
            release.put("is_beta", true);
        } else {
            release.put("is_beta", false);
        }

        return release.isEmpty() ? null : release;
    }

    /**
     * Get query parameter with default value.
     */
    private String getQueryParam(String query, String name, String defaultValue) {
        if (query == null) return defaultValue;
        for (String param : query.split("&")) {
            String[] kv = param.split("=", 2);
            if (kv.length == 2 && kv[0].equals(name)) {
                return kv[1];
            }
        }
        return defaultValue;
    }

    /**
     * Get path to Python scripts.
     */
    private String getScriptPath(String scriptName) {
        // Check workspace first, then relative path
        String workspacePath = "/workspace/scripts/" + scriptName;
        if (new File(workspacePath).exists()) {
            return workspacePath;
        }
        // Fallback to relative path for local development
        return "scripts/" + scriptName;
    }

    // =========================================================================
    // Utility Methods
    // =========================================================================

    private void sendJson(HttpExchange exchange, int code, String json) throws IOException {
        byte[] response = json.getBytes();
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(code, response.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response);
        }
    }

    private void sendError(HttpExchange exchange, int code, String message) throws IOException {
        String json = String.format("{\"error\": \"%s\"}", escape(message));
        sendJson(exchange, code, json);
    }

    private Map<String, String> parseJson(String json) {
        Map<String, String> result = new HashMap<>();
        // Simple JSON parsing (handles flat objects only)
        json = json.trim();
        if (json.startsWith("{")) json = json.substring(1);
        if (json.endsWith("}")) json = json.substring(0, json.length() - 1);

        String[] pairs = json.split(",");
        for (String pair : pairs) {
            String[] kv = pair.split(":", 2);
            if (kv.length == 2) {
                String key = kv[0].trim().replace("\"", "");
                String value = kv[1].trim().replace("\"", "");
                result.put(key, value);
            }
        }
        return result;
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }

    private String nullSafe(Object o) {
        return o != null ? o.toString() : "";
    }

    private String toJsonArray(List<?> list, String field) {
        if (list == null || list.isEmpty()) return "[]";
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(", ");
            Object item = list.get(i);
            if (item instanceof Map) {
                sb.append("\"").append(escape(((Map<?, ?>) item).get(field).toString())).append("\"");
            } else {
                sb.append("\"").append(escape(item.toString())).append("\"");
            }
        }
        sb.append("]");
        return sb.toString();
    }

    private String toJsonObjectArray(List<?> list) {
        if (list == null || list.isEmpty()) return "[]";
        StringBuilder sb = new StringBuilder("[\n");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",\n");
            Map<?, ?> map = (Map<?, ?>) list.get(i);
            sb.append("    {");
            int j = 0;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (j++ > 0) sb.append(", ");
                Object val = entry.getValue();
                if (val instanceof Number) {
                    sb.append("\"").append(entry.getKey()).append("\": ").append(val);
                } else {
                    sb.append("\"").append(entry.getKey()).append("\": \"").append(escape(nullSafe(val))).append("\"");
                }
            }
            sb.append("}");
        }
        sb.append("\n  ]");
        return sb.toString();
    }

    private boolean isDangerousPermission(String perm) {
        return perm.contains("SMS") || perm.contains("CALL") || perm.contains("LOCATION") ||
               perm.contains("CAMERA") || perm.contains("MICROPHONE") || perm.contains("CONTACTS") ||
               perm.contains("RECORD_AUDIO") || perm.contains("READ_PHONE");
    }

    // =========================================================================
    // Tracking Database Updates
    // =========================================================================

    /**
     * Update tracking database to mark a version as downloaded.
     */
    private void updateTrackingDbDownloaded(String packageName, String version) {
        String trackingDbPath = DATA_DIR + "/tracking.db";
        File trackingDb = new File(trackingDbPath);
        if (!trackingDb.exists()) {
            System.out.println("[Tracking] Database not found: " + trackingDbPath);
            return;
        }

        try (java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:sqlite:" + trackingDbPath)) {
            String sql = "UPDATE versions SET downloaded_at = ? WHERE package_name = ? AND version_name LIKE ?";
            try (java.sql.PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setLong(1, System.currentTimeMillis() / 1000);
                stmt.setString(2, packageName);
                stmt.setString(3, version.equals("latest") ? "%" : "%" + version + "%");
                int updated = stmt.executeUpdate();
                System.out.println("[Tracking] Marked " + updated + " version(s) as downloaded for " + packageName + " " + version);
            }
        } catch (Exception e) {
            System.err.println("[Tracking] Failed to update downloaded_at: " + e.getMessage());
        }
    }

    /**
     * Update tracking database to mark a version as analyzed.
     */
    private void updateTrackingDbAnalyzed(String packageName, String version, String dbPath) {
        String trackingDbPath = DATA_DIR + "/tracking.db";
        File trackingDb = new File(trackingDbPath);
        if (!trackingDb.exists()) {
            System.out.println("[Tracking] Database not found: " + trackingDbPath);
            return;
        }

        try (java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:sqlite:" + trackingDbPath)) {
            String sql = "UPDATE versions SET analyzed_at = ?, analysis_db_path = ? WHERE package_name = ? AND version_name = ?";
            try (java.sql.PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setLong(1, System.currentTimeMillis() / 1000);
                stmt.setString(2, dbPath);
                stmt.setString(3, packageName);
                stmt.setString(4, version);
                int updated = stmt.executeUpdate();
                System.out.println("[Tracking] Marked " + updated + " version(s) as analyzed for " + packageName + " " + version);
            }
        } catch (Exception e) {
            System.err.println("[Tracking] Failed to update analyzed_at: " + e.getMessage());
        }
    }

    // =========================================================================
    // Main
    // =========================================================================

    public static void main(String[] args) {
        int port = DEFAULT_PORT;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port: " + args[0]);
                System.exit(1);
            }
        }

        try {
            ApiServer server = new ApiServer(port);
            server.start();

            // Keep running
            Thread.currentThread().join();

        } catch (Exception e) {
            System.err.println("Failed to start server: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
