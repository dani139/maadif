package com.maadif.api;

import com.maadif.Config;
import com.maadif.analysis.AnalysisService;
import com.maadif.model.ApkInfo;
import com.maadif.model.AnalysisResult;
import com.maadif.model.AnalysisStatus;
import com.maadif.storage.Database;
import io.javalin.http.Context;
import io.javalin.http.UploadedFile;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/**
 * Controller for APK upload and analysis operations.
 *
 * Endpoints:
 *   GET  /apks              - List all APKs
 *   POST /apks/upload       - Upload new APK
 *   POST /apks/{id}/analyze - Start analysis (JADX + Ghidra)
 *   GET  /apks/{id}/status  - Get analysis status
 *   GET  /apks/{id}/analysis - Get analysis results
 */
public class ApkController {

    private final Config config;
    private final Database db;
    private final AnalysisService analysisService;

    public ApkController(Config config, Database db) {
        this.config = config;
        this.db = db;
        this.analysisService = new AnalysisService(config, db);
    }

    /**
     * GET /apks - List all uploaded APKs
     */
    public void list(Context ctx) {
        List<ApkInfo> apks = db.listApks();
        ctx.json(Map.of("apks", apks));
    }

    /**
     * POST /apks/upload - Upload APK file
     *
     * Request: multipart/form-data with "file" field
     * Response: { "id": "sha256hash", "package": "com.example", "version": "1.0.0" }
     */
    public void upload(Context ctx) {
        UploadedFile file = ctx.uploadedFile("file");

        if (file == null) {
            ctx.status(400).json(Map.of("error", "No file uploaded. Use 'file' field."));
            return;
        }

        if (!file.filename().endsWith(".apk")) {
            ctx.status(400).json(Map.of("error", "File must be an APK"));
            return;
        }

        try {
            // Calculate SHA256 and save file
            String apkId = saveApk(file);

            // Extract basic info from APK
            ApkInfo info = analysisService.extractBasicInfo(apkId);
            db.saveApk(info);

            ctx.status(201).json(Map.of(
                "id", apkId,
                "package", info.packageName,
                "versionName", info.versionName,
                "versionCode", info.versionCode,
                "message", "APK uploaded. Call POST /apks/" + apkId + "/analyze to start analysis."
            ));

        } catch (Exception e) {
            ctx.status(500).json(Map.of("error", "Upload failed: " + e.getMessage()));
        }
    }

    /**
     * POST /apks/{id}/analyze - Start full analysis
     *
     * Query params:
     *   jadx=true     - Run JADX decompilation (default: true)
     *   ghidra=true   - Run Ghidra native analysis (default: true)
     *   callgraph=true - Build callgraph (default: true)
     *
     * Response: { "status": "started", "id": "..." }
     */
    public void analyze(Context ctx) {
        String apkId = ctx.pathParam("id");

        // Check APK exists
        ApkInfo apk = db.getApk(apkId);
        if (apk == null) {
            ctx.status(404).json(Map.of("error", "APK not found: " + apkId));
            return;
        }

        // Parse options
        boolean runJadx = ctx.queryParamAsClass("jadx", Boolean.class).getOrDefault(true);
        boolean runGhidra = ctx.queryParamAsClass("ghidra", Boolean.class).getOrDefault(true);
        boolean buildCallgraph = ctx.queryParamAsClass("callgraph", Boolean.class).getOrDefault(true);

        // Check if already analyzing
        AnalysisStatus status = db.getAnalysisStatus(apkId);
        if (status != null && status.state.equals("running")) {
            ctx.status(409).json(Map.of(
                "error", "Analysis already in progress",
                "status", status
            ));
            return;
        }

        // Start analysis in background thread
        db.setAnalysisStatus(apkId, "running", "Starting analysis...");

        new Thread(() -> {
            try {
                analysisService.analyze(apkId, runJadx, runGhidra, buildCallgraph);
                db.setAnalysisStatus(apkId, "completed", "Analysis completed successfully");
            } catch (Exception e) {
                db.setAnalysisStatus(apkId, "failed", "Error: " + e.getMessage());
                e.printStackTrace();
            }
        }).start();

        ctx.status(202).json(Map.of(
            "status", "started",
            "id", apkId,
            "message", "Analysis started. Check GET /apks/" + apkId + "/status for progress."
        ));
    }

    /**
     * GET /apks/{id}/status - Get analysis status
     */
    public void status(Context ctx) {
        String apkId = ctx.pathParam("id");

        AnalysisStatus status = db.getAnalysisStatus(apkId);
        if (status == null) {
            ctx.status(404).json(Map.of("error", "No analysis found for: " + apkId));
            return;
        }

        ctx.json(status);
    }

    /**
     * GET /apks/{id}/analysis - Get full analysis results
     */
    public void getAnalysis(Context ctx) {
        String apkId = ctx.pathParam("id");

        AnalysisResult result = db.getAnalysisResult(apkId);
        if (result == null) {
            ctx.status(404).json(Map.of("error", "No analysis found for: " + apkId));
            return;
        }

        ctx.json(result);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private String saveApk(UploadedFile file) throws Exception {
        // Read file and calculate hash
        byte[] content = file.content().readAllBytes();
        String hash = sha256(content);

        // Save to apks directory: apks/{hash}.apk
        Path apkPath = Path.of(config.apksDir, hash + ".apk");
        Files.createDirectories(apkPath.getParent());
        Files.write(apkPath, content);

        return hash;
    }

    private String sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
