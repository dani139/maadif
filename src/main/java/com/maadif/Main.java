package com.maadif;

import com.maadif.api.ApkController;
import com.maadif.api.DiffController;
import com.maadif.api.HealthController;
import com.maadif.storage.Database;
import io.javalin.Javalin;
import io.javalin.http.staticfiles.Location;

/**
 * MAADIF - Mobile Application Analysis & Diff Framework
 *
 * Main entry point for the API server.
 *
 * Environment:
 *   MAADIF_APKS_DIR   - Directory for APK storage (default: /workspace/apks)
 *   MAADIF_OUTPUT_DIR - Directory for analysis output (default: /workspace/output)
 *   MAADIF_PORT       - Server port (default: 8080)
 */
public class Main {

    public static void main(String[] args) {
        // Initialize configuration
        Config config = Config.load();

        // Initialize database
        Database db = new Database(config.outputDir + "/maadif.db");
        db.initialize();

        // Create services
        var apkController = new ApkController(config, db);
        var diffController = new DiffController(config, db);

        // Create and configure server
        Javalin app = Javalin.create(javalinConfig -> {
            javalinConfig.http.defaultContentType = "application/json";
            javalinConfig.bundledPlugins.enableCors(cors -> {
                cors.addRule(rule -> rule.anyHost());
            });
        });

        // Register routes
        registerRoutes(app, apkController, diffController);

        // Start server
        app.start(config.port);

        System.out.println("===========================================");
        System.out.println("  MAADIF API Server started on port " + config.port);
        System.out.println("===========================================");
        System.out.println("  APKs directory:   " + config.apksDir);
        System.out.println("  Output directory: " + config.outputDir);
        System.out.println("===========================================");
        System.out.println();
        System.out.println("Endpoints:");
        System.out.println("  GET  /health              - Health check");
        System.out.println("  GET  /apks                - List all APKs");
        System.out.println("  POST /apks/upload         - Upload APK");
        System.out.println("  POST /apks/{id}/analyze   - Start analysis");
        System.out.println("  GET  /apks/{id}/status    - Analysis status");
        System.out.println("  GET  /apks/{id}/analysis  - Get analysis result");
        System.out.println("  GET  /diff/{id1}/{id2}    - Compare two APKs");
        System.out.println("===========================================");
    }

    private static void registerRoutes(Javalin app, ApkController apk, DiffController diff) {
        // Health check
        app.get("/health", HealthController::health);

        // APK management
        app.get("/apks", apk::list);
        app.post("/apks/upload", apk::upload);
        app.post("/apks/{id}/analyze", apk::analyze);
        app.get("/apks/{id}/status", apk::status);
        app.get("/apks/{id}/analysis", apk::getAnalysis);

        // Diff
        app.get("/diff/{id1}/{id2}", diff::compare);
    }
}
