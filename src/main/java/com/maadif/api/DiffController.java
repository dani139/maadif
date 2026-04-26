package com.maadif.api;

import com.maadif.Config;
import com.maadif.diff.DiffService;
import com.maadif.model.DiffResult;
import com.maadif.storage.Database;
import io.javalin.http.Context;

import java.util.Map;

/**
 * Controller for comparing two analyzed APKs.
 *
 * Endpoints:
 *   GET /diff/{id1}/{id2} - Compare two APKs
 */
public class DiffController {

    private final Config config;
    private final Database db;
    private final DiffService diffService;

    public DiffController(Config config, Database db) {
        this.config = config;
        this.db = db;
        this.diffService = new DiffService(config, db);
    }

    /**
     * GET /diff/{id1}/{id2} - Compare two analyzed APKs
     *
     * Query params:
     *   manifest=true   - Include manifest diff (default: true)
     *   classes=true    - Include Java class diff (default: true)
     *   native=true     - Include native code diff (default: true)
     *   callgraph=true  - Include callgraph diff (default: true)
     *
     * Response: DiffResult with all changes between versions
     */
    public void compare(Context ctx) {
        String id1 = ctx.pathParam("id1");
        String id2 = ctx.pathParam("id2");

        // Verify both APKs exist and are analyzed
        var status1 = db.getAnalysisStatus(id1);
        var status2 = db.getAnalysisStatus(id2);

        if (status1 == null || !status1.state.equals("completed")) {
            ctx.status(400).json(Map.of(
                "error", "APK not analyzed: " + id1,
                "hint", "Run POST /apks/" + id1 + "/analyze first"
            ));
            return;
        }

        if (status2 == null || !status2.state.equals("completed")) {
            ctx.status(400).json(Map.of(
                "error", "APK not analyzed: " + id2,
                "hint", "Run POST /apks/" + id2 + "/analyze first"
            ));
            return;
        }

        // Parse options
        boolean diffManifest = ctx.queryParamAsClass("manifest", Boolean.class).getOrDefault(true);
        boolean diffClasses = ctx.queryParamAsClass("classes", Boolean.class).getOrDefault(true);
        boolean diffNative = ctx.queryParamAsClass("native", Boolean.class).getOrDefault(true);
        boolean diffCallgraph = ctx.queryParamAsClass("callgraph", Boolean.class).getOrDefault(true);

        try {
            DiffResult result = diffService.compare(id1, id2, diffManifest, diffClasses, diffNative, diffCallgraph);
            ctx.json(result);
        } catch (Exception e) {
            ctx.status(500).json(Map.of("error", "Diff failed: " + e.getMessage()));
        }
    }
}
