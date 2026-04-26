package io.maadif.server;

import java.io.File;
import java.sql.*;
import java.util.*;

/**
 * SQLite database for storing APK analysis results.
 *
 * Database structure:
 *   data/{package}/{version}/
 *   ├── analysis.db              # APK analysis (classes, permissions, native lib metadata)
 *   └── natives/
 *       ├── libs.so.db           # Ghidra analysis per native library
 *       └── libsuperpack.so.db
 */
public class Database {

    private final String dbPath;

    public Database(String dbPath) {
        this.dbPath = dbPath;
        // Ensure parent directory exists
        new File(dbPath).getParentFile().mkdirs();
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + dbPath);
    }

    public String getDbPath() {
        return dbPath;
    }

    // =========================================================================
    // Static factory methods for creating databases
    // =========================================================================

    /**
     * Create or open the main analysis database for an APK.
     * Path: data/{package}/{version}/analysis.db
     */
    public static Database forApk(String dataDir, String packageName, String version) {
        String path = String.format("%s/%s/%s/analysis.db", dataDir, packageName, version);
        return new Database(path);
    }

    /**
     * Create or open a native library database.
     * Path: data/{package}/{version}/natives/{libname}.db
     */
    public static Database forNativeLib(String dataDir, String packageName, String version, String libName) {
        // Sanitize lib name (remove path, keep filename)
        String safeName = new File(libName).getName();
        String path = String.format("%s/%s/%s/natives/%s.db", dataDir, packageName, version, safeName);
        return new Database(path);
    }

    /**
     * Get the natives directory for a package/version.
     */
    public static File getNativesDir(String dataDir, String packageName, String version) {
        File dir = new File(String.format("%s/%s/%s/natives", dataDir, packageName, version));
        dir.mkdirs();
        return dir;
    }

    /**
     * Get the version directory for a package/version.
     */
    public static File getVersionDir(String dataDir, String packageName, String version) {
        File dir = new File(String.format("%s/%s/%s", dataDir, packageName, version));
        dir.mkdirs();
        return dir;
    }

    // =========================================================================
    // Main APK Analysis Schema (analysis.db)
    // =========================================================================

    /**
     * Initialize main APK analysis database schema.
     */
    public void initializeApkSchema() throws SQLException {
        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {

            // APK metadata
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS apk_info (
                    id INTEGER PRIMARY KEY,
                    package_name TEXT NOT NULL,
                    version_name TEXT,
                    version_code INTEGER,
                    file_name TEXT,
                    file_size INTEGER,
                    min_sdk INTEGER,
                    target_sdk INTEGER,
                    analyzed_at INTEGER DEFAULT (strftime('%s', 'now'))
                )
            """);

            // Analysis jobs for this APK
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS analysis_jobs (
                    id TEXT PRIMARY KEY,
                    status TEXT DEFAULT 'pending',
                    progress INTEGER DEFAULT 0,
                    message TEXT,
                    options_json TEXT,
                    started_at INTEGER,
                    completed_at INTEGER,
                    created_at INTEGER DEFAULT (strftime('%s', 'now'))
                )
            """);

            // Permissions
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    permission TEXT UNIQUE,
                    is_dangerous INTEGER DEFAULT 0
                )
            """);

            // Components (activities, services, receivers, providers)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS components (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT,
                    name TEXT,
                    exported INTEGER DEFAULT 0,
                    UNIQUE(type, name)
                )
            """);

            // Classes with decompilation status
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE,
                    package_name TEXT,
                    source_path TEXT,
                    method_count INTEGER DEFAULT 0,
                    failed_methods INTEGER DEFAULT 0,
                    decompile_failed INTEGER DEFAULT 0,
                    error_message TEXT
                )
            """);

            // Methods with decompilation status
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS methods (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    class_id INTEGER REFERENCES classes(id),
                    name TEXT,
                    signature TEXT,
                    decompile_failed INTEGER DEFAULT 0,
                    error_message TEXT
                )
            """);

            // Method calls (call graph for Java code)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS method_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    caller_class TEXT NOT NULL,
                    caller_method TEXT NOT NULL,
                    caller_signature TEXT,
                    callee_class TEXT NOT NULL,
                    callee_method TEXT NOT NULL,
                    callee_signature TEXT
                )
            """);

            // Native libraries metadata (detailed analysis in separate DBs)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS native_libs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT UNIQUE,
                    name TEXT,
                    arch TEXT,
                    size INTEGER,
                    analyzed INTEGER DEFAULT 0,
                    function_count INTEGER DEFAULT 0,
                    string_count INTEGER DEFAULT 0,
                    import_count INTEGER DEFAULT 0,
                    export_count INTEGER DEFAULT 0,
                    db_path TEXT
                )
            """);

            // Security findings
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS security_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT,
                    severity TEXT,
                    description TEXT,
                    location TEXT
                )
            """);

            // URLs found
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE,
                    source_class TEXT
                )
            """);

            // Process timing
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS process_timing (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT,
                    phase TEXT NOT NULL,
                    started_at INTEGER,
                    ended_at INTEGER,
                    duration_ms INTEGER,
                    status TEXT DEFAULT 'running'
                )
            """);

            // Logs
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT,
                    timestamp INTEGER DEFAULT (strftime('%s', 'now')),
                    level TEXT DEFAULT 'INFO',
                    phase TEXT,
                    message TEXT
                )
            """);

            // Analysis summary stats
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS analysis_summary (
                    id INTEGER PRIMARY KEY,
                    total_classes INTEGER DEFAULT 0,
                    total_methods INTEGER DEFAULT 0,
                    failed_classes INTEGER DEFAULT 0,
                    failed_methods INTEGER DEFAULT 0,
                    total_native_libs INTEGER DEFAULT 0,
                    analyzed_native_libs INTEGER DEFAULT 0,
                    output_path TEXT
                )
            """);

            // Indexes
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_classes_package ON classes(package_name)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_methods_class ON methods(class_id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_method_calls_caller ON method_calls(caller_class, caller_method)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_method_calls_callee ON method_calls(callee_class, callee_method)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_timing_job ON process_timing(job_id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_logs_job ON logs(job_id)");

            System.out.println("[Database] Initialized APK schema: " + dbPath);
        }
    }

    // =========================================================================
    // Native Library Analysis Schema (*.so.db files)
    // =========================================================================

    /**
     * Initialize native library database schema.
     */
    public void initializeNativeSchema() throws SQLException {
        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {

            // Library info
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS lib_info (
                    id INTEGER PRIMARY KEY,
                    name TEXT,
                    path TEXT,
                    arch TEXT,
                    size INTEGER,
                    language_id TEXT,
                    compiler_spec TEXT,
                    image_base TEXT,
                    analyzed_at INTEGER DEFAULT (strftime('%s', 'now'))
                )
            """);

            // Functions
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS functions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    address TEXT UNIQUE,
                    signature TEXT,
                    calling_convention TEXT,
                    parameter_count INTEGER DEFAULT 0,
                    body_size INTEGER DEFAULT 0,
                    is_thunk INTEGER DEFAULT 0,
                    is_external INTEGER DEFAULT 0,
                    is_export INTEGER DEFAULT 0,
                    decompiled_path TEXT
                )
            """);

            // Function calls (call graph)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS function_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    caller_id INTEGER REFERENCES functions(id),
                    callee_name TEXT
                )
            """);

            // Strings
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS strings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    value TEXT,
                    address TEXT
                )
            """);

            // Imports
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS imports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE
                )
            """);

            // Exports
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS exports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE
                )
            """);

            // Memory sections
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS memory_sections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    start_addr TEXT,
                    end_addr TEXT,
                    size INTEGER,
                    is_read INTEGER DEFAULT 0,
                    is_write INTEGER DEFAULT 0,
                    is_execute INTEGER DEFAULT 0,
                    is_initialized INTEGER DEFAULT 0
                )
            """);

            // Data structures
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS structures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    size INTEGER,
                    field_count INTEGER
                )
            """);

            // Indexes
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_calls_caller ON function_calls(caller_id)");

            System.out.println("[Database] Initialized native schema: " + dbPath);
        }
    }

    // =========================================================================
    // Legacy initialize() for backwards compatibility
    // =========================================================================

    public void initialize() throws SQLException {
        initializeApkSchema();
    }

    // =========================================================================
    // APK Info Methods
    // =========================================================================

    public void saveApkInfo(String packageName, String versionName, String fileName,
                           long fileSize, int minSdk, int targetSdk) throws SQLException {
        String sql = """
            INSERT OR REPLACE INTO apk_info (id, package_name, version_name, file_name, file_size, min_sdk, target_sdk)
            VALUES (1, ?, ?, ?, ?, ?, ?)
        """;
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, packageName);
            ps.setString(2, versionName);
            ps.setString(3, fileName);
            ps.setLong(4, fileSize);
            ps.setInt(5, minSdk);
            ps.setInt(6, targetSdk);
            ps.executeUpdate();
        }
    }

    // =========================================================================
    // Job Management
    // =========================================================================

    public String createJob(String apkPath, String optionsJson) throws SQLException {
        String id = UUID.randomUUID().toString().substring(0, 8);
        String sql = "INSERT INTO analysis_jobs (id, status, options_json) VALUES (?, 'pending', ?)";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            ps.setString(2, optionsJson);
            ps.executeUpdate();
        }
        return id;
    }

    public void updateJobStatus(String jobId, String status, int progress, String message) throws SQLException {
        String sql = """
            UPDATE analysis_jobs SET status = ?, progress = ?, message = ?,
            started_at = CASE WHEN started_at IS NULL AND ? = 'running' THEN strftime('%s','now') ELSE started_at END,
            completed_at = CASE WHEN ? IN ('completed', 'failed') THEN strftime('%s','now') ELSE completed_at END
            WHERE id = ?
        """;

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, status);
            ps.setInt(2, progress);
            ps.setString(3, message);
            ps.setString(4, status);
            ps.setString(5, status);
            ps.setString(6, jobId);
            ps.executeUpdate();
        }
    }

    public Map<String, Object> getJob(String jobId) throws SQLException {
        String sql = "SELECT * FROM analysis_jobs WHERE id = ?";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, jobId);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                Map<String, Object> job = new HashMap<>();
                job.put("id", rs.getString("id"));
                job.put("status", rs.getString("status"));
                job.put("progress", rs.getInt("progress"));
                job.put("message", rs.getString("message"));
                job.put("started_at", rs.getLong("started_at"));
                job.put("completed_at", rs.getLong("completed_at"));
                return job;
            }
        }
        return null;
    }

    // =========================================================================
    // Permissions & Components
    // =========================================================================

    public void savePermission(String permission, boolean isDangerous) throws SQLException {
        String sql = "INSERT OR IGNORE INTO permissions (permission, is_dangerous) VALUES (?, ?)";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, permission);
            ps.setInt(2, isDangerous ? 1 : 0);
            ps.executeUpdate();
        }
    }

    // Backwards compatible version
    public void savePermission(String analysisId, String permission, boolean isDangerous) throws SQLException {
        savePermission(permission, isDangerous);
    }

    public void saveComponent(String type, String name) throws SQLException {
        String sql = "INSERT OR IGNORE INTO components (type, name) VALUES (?, ?)";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, type);
            ps.setString(2, name);
            ps.executeUpdate();
        }
    }

    // Backwards compatible version
    public void saveComponent(String analysisId, String type, String name) throws SQLException {
        saveComponent(type, name);
    }

    // =========================================================================
    // Classes & Methods
    // =========================================================================

    public void saveClassesBatch(List<ClassData> classes) throws SQLException {
        String classSql = """
            INSERT OR IGNORE INTO classes (name, package_name, source_path, method_count, failed_methods, decompile_failed, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """;
        String methodSql = """
            INSERT INTO methods (class_id, name, signature, decompile_failed, error_message)
            VALUES (?, ?, ?, ?, ?)
        """;

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);

            int classCount = 0;
            try (PreparedStatement classPs = conn.prepareStatement(classSql, Statement.RETURN_GENERATED_KEYS);
                 PreparedStatement methodPs = conn.prepareStatement(methodSql)) {

                for (ClassData cls : classes) {
                    classPs.setString(1, cls.name);
                    classPs.setString(2, cls.packageName);
                    classPs.setString(3, cls.sourcePath);
                    classPs.setInt(4, cls.methodCount);
                    classPs.setInt(5, cls.failedMethods);
                    classPs.setInt(6, cls.decompileFailed ? 1 : 0);
                    classPs.setString(7, cls.errorMessage);
                    classPs.executeUpdate();

                    ResultSet keys = classPs.getGeneratedKeys();
                    long classId = keys.next() ? keys.getLong(1) : -1;

                    for (MethodData method : cls.methods) {
                        methodPs.setLong(1, classId);
                        methodPs.setString(2, method.name);
                        methodPs.setString(3, method.signature);
                        methodPs.setInt(4, method.decompileFailed ? 1 : 0);
                        methodPs.setString(5, method.errorMessage);
                        methodPs.addBatch();
                    }

                    if (cls.methods.size() > 0) {
                        methodPs.executeBatch();
                    }

                    classCount++;
                    if (classCount % 500 == 0) {
                        System.out.println("[Database] Saved " + classCount + "/" + classes.size() + " classes");
                        conn.commit();
                    }
                }

                conn.commit();
                System.out.println("[Database] Saved all " + classes.size() + " classes");
            } catch (Exception e) {
                conn.rollback();
                throw e;
            }
        }
    }

    // Backwards compatible version
    public void saveClassesBatch(String analysisId, List<ClassData> classes) throws SQLException {
        saveClassesBatch(classes);
    }

    /**
     * Save method calls (call graph edges) in batch.
     */
    public void saveMethodCallsBatch(List<MethodCallData> calls) throws SQLException {
        if (calls == null || calls.isEmpty()) {
            return;
        }

        String sql = """
            INSERT INTO method_calls (caller_class, caller_method, caller_signature, callee_class, callee_method, callee_signature)
            VALUES (?, ?, ?, ?, ?, ?)
        """;

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);

            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                int count = 0;
                for (MethodCallData call : calls) {
                    ps.setString(1, call.callerClass);
                    ps.setString(2, call.callerMethod);
                    ps.setString(3, call.callerSignature);
                    ps.setString(4, call.calleeClass);
                    ps.setString(5, call.calleeMethod);
                    ps.setString(6, call.calleeSignature);
                    ps.addBatch();

                    count++;
                    if (count % 5000 == 0) {
                        ps.executeBatch();
                        conn.commit();
                        System.out.println("[Database] Saved " + count + "/" + calls.size() + " method calls");
                    }
                }

                ps.executeBatch();
                conn.commit();
                System.out.println("[Database] Saved all " + calls.size() + " method calls");
            } catch (Exception e) {
                conn.rollback();
                throw e;
            }
        }
    }

    /**
     * Get method call statistics.
     */
    public Map<String, Object> getMethodCallStats() throws SQLException {
        Map<String, Object> stats = new HashMap<>();

        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {
            // Total calls
            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) as total FROM method_calls");
            if (rs.next()) {
                stats.put("total_calls", rs.getInt("total"));
            }

            // Unique caller methods
            rs = stmt.executeQuery("SELECT COUNT(DISTINCT caller_class || '.' || caller_method) as unique_callers FROM method_calls");
            if (rs.next()) {
                stats.put("unique_callers", rs.getInt("unique_callers"));
            }

            // Unique callee methods
            rs = stmt.executeQuery("SELECT COUNT(DISTINCT callee_class || '.' || callee_method) as unique_callees FROM method_calls");
            if (rs.next()) {
                stats.put("unique_callees", rs.getInt("unique_callees"));
            }
        }

        return stats;
    }

    /**
     * Get methods called by a specific method.
     */
    public List<Map<String, Object>> getMethodCallsFrom(String className, String methodName) throws SQLException {
        String sql = """
            SELECT callee_class, callee_method, callee_signature, COUNT(*) as call_count
            FROM method_calls
            WHERE caller_class = ? AND caller_method = ?
            GROUP BY callee_class, callee_method, callee_signature
            ORDER BY call_count DESC
        """;

        List<Map<String, Object>> results = new ArrayList<>();
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, className);
            ps.setString(2, methodName);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("callee_class", rs.getString("callee_class"));
                row.put("callee_method", rs.getString("callee_method"));
                row.put("callee_signature", rs.getString("callee_signature"));
                row.put("call_count", rs.getInt("call_count"));
                results.add(row);
            }
        }
        return results;
    }

    /**
     * Get methods that call a specific method.
     */
    public List<Map<String, Object>> getMethodCallsTo(String className, String methodName) throws SQLException {
        String sql = """
            SELECT caller_class, caller_method, caller_signature, COUNT(*) as call_count
            FROM method_calls
            WHERE callee_class = ? AND callee_method = ?
            GROUP BY caller_class, caller_method, caller_signature
            ORDER BY call_count DESC
        """;

        List<Map<String, Object>> results = new ArrayList<>();
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, className);
            ps.setString(2, methodName);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("caller_class", rs.getString("caller_class"));
                row.put("caller_method", rs.getString("caller_method"));
                row.put("caller_signature", rs.getString("caller_signature"));
                row.put("call_count", rs.getInt("call_count"));
                results.add(row);
            }
        }
        return results;
    }

    // =========================================================================
    // Native Library Metadata (in main analysis.db)
    // =========================================================================

    public void saveNativeLibMetadata(String path, String name, String arch, long size,
                                      boolean analyzed, int functionCount, int stringCount,
                                      int importCount, int exportCount, String dbPath) throws SQLException {
        String sql = """
            INSERT OR REPLACE INTO native_libs (path, name, arch, size, analyzed, function_count, string_count, import_count, export_count, db_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """;

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, path);
            ps.setString(2, name);
            ps.setString(3, arch);
            ps.setLong(4, size);
            ps.setInt(5, analyzed ? 1 : 0);
            ps.setInt(6, functionCount);
            ps.setInt(7, stringCount);
            ps.setInt(8, importCount);
            ps.setInt(9, exportCount);
            ps.setString(10, dbPath);
            ps.executeUpdate();
        }
    }

    // Backwards compatible version (without separate DB)
    public long saveNativeLib(String analysisId, String path, String arch, long size, boolean analyzed) throws SQLException {
        String sql = """
            INSERT OR REPLACE INTO native_libs (path, name, arch, size, analyzed)
            VALUES (?, ?, ?, ?, ?)
        """;

        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, path);
            ps.setString(2, new File(path).getName());
            ps.setString(3, arch);
            ps.setLong(4, size);
            ps.setInt(5, analyzed ? 1 : 0);
            ps.executeUpdate();

            ResultSet keys = ps.getGeneratedKeys();
            return keys.next() ? keys.getLong(1) : -1;
        }
    }

    // =========================================================================
    // Native Library Database Methods (for *.so.db files)
    // =========================================================================

    public void saveLibInfo(String name, String path, String arch, long size,
                           String languageId, String compilerSpec, String imageBase) throws SQLException {
        String sql = """
            INSERT OR REPLACE INTO lib_info (id, name, path, arch, size, language_id, compiler_spec, image_base)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?)
        """;

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, name);
            ps.setString(2, path);
            ps.setString(3, arch);
            ps.setLong(4, size);
            ps.setString(5, languageId);
            ps.setString(6, compilerSpec);
            ps.setString(7, imageBase);
            ps.executeUpdate();
        }
    }

    public long saveFunction(String name, String address, String signature,
                            String callingConvention, int paramCount, long bodySize,
                            boolean isThunk, boolean isExternal, boolean isExport,
                            String decompiledPath) throws SQLException {
        String sql = """
            INSERT OR IGNORE INTO functions (name, address, signature, calling_convention, parameter_count, body_size, is_thunk, is_external, is_export, decompiled_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """;

        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, name);
            ps.setString(2, address);
            ps.setString(3, signature);
            ps.setString(4, callingConvention);
            ps.setInt(5, paramCount);
            ps.setLong(6, bodySize);
            ps.setInt(7, isThunk ? 1 : 0);
            ps.setInt(8, isExternal ? 1 : 0);
            ps.setInt(9, isExport ? 1 : 0);
            ps.setString(10, decompiledPath);
            ps.executeUpdate();

            ResultSet keys = ps.getGeneratedKeys();
            return keys.next() ? keys.getLong(1) : -1;
        }
    }

    // Backward compatible version without decompiledPath
    public long saveFunction(String name, String address, String signature,
                            String callingConvention, int paramCount, long bodySize,
                            boolean isThunk, boolean isExternal, boolean isExport) throws SQLException {
        return saveFunction(name, address, signature, callingConvention, paramCount, bodySize,
                           isThunk, isExternal, isExport, null);
    }

    public void saveFunctionCall(long callerId, String calleeName) throws SQLException {
        String sql = "INSERT INTO function_calls (caller_id, callee_name) VALUES (?, ?)";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, callerId);
            ps.setString(2, calleeName);
            ps.executeUpdate();
        }
    }

    public void saveString(String value, String address) throws SQLException {
        String sql = "INSERT INTO strings (value, address) VALUES (?, ?)";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, value);
            ps.setString(2, address);
            ps.executeUpdate();
        }
    }

    public void saveImport(String name) throws SQLException {
        String sql = "INSERT OR IGNORE INTO imports (name) VALUES (?)";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, name);
            ps.executeUpdate();
        }
    }

    public void saveExport(String name) throws SQLException {
        String sql = "INSERT OR IGNORE INTO exports (name) VALUES (?)";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, name);
            ps.executeUpdate();
        }
    }

    public void saveMemorySection(String name, String start, String end, long size,
                                  boolean isRead, boolean isWrite, boolean isExecute,
                                  boolean isInitialized) throws SQLException {
        String sql = """
            INSERT INTO memory_sections (name, start_addr, end_addr, size, is_read, is_write, is_execute, is_initialized)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """;

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, name);
            ps.setString(2, start);
            ps.setString(3, end);
            ps.setLong(4, size);
            ps.setInt(5, isRead ? 1 : 0);
            ps.setInt(6, isWrite ? 1 : 0);
            ps.setInt(7, isExecute ? 1 : 0);
            ps.setInt(8, isInitialized ? 1 : 0);
            ps.executeUpdate();
        }
    }

    public void saveStructure(String name, int size, int fieldCount) throws SQLException {
        String sql = "INSERT INTO structures (name, size, field_count) VALUES (?, ?, ?)";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, name);
            ps.setInt(2, size);
            ps.setInt(3, fieldCount);
            ps.executeUpdate();
        }
    }

    // Backwards compatible (saves to native_functions in same db - legacy)
    public void saveNativeFunction(long libId, String name, String address,
                                   String signature, boolean isExport) throws SQLException {
        // For new structure, use saveFunction() on native db instead
        saveFunction(name, address, signature, null, 0, 0, false, false, isExport);
    }

    // =========================================================================
    // Security & URLs
    // =========================================================================

    public void saveSecurityFinding(String type, String severity, String description, String location) throws SQLException {
        String sql = "INSERT INTO security_findings (type, severity, description, location) VALUES (?, ?, ?, ?)";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, type);
            ps.setString(2, severity);
            ps.setString(3, description);
            ps.setString(4, location);
            ps.executeUpdate();
        }
    }

    // Backwards compatible version
    public void saveSecurityFinding(String analysisId, String type, String severity,
                                    String description, String location) throws SQLException {
        saveSecurityFinding(type, severity, description, location);
    }

    public void saveUrl(String url, String sourceClass) throws SQLException {
        String sql = "INSERT OR IGNORE INTO urls (url, source_class) VALUES (?, ?)";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, url);
            ps.setString(2, sourceClass);
            ps.executeUpdate();
        }
    }

    // Backwards compatible version
    public void saveUrl(String analysisId, String url, String sourceClass) throws SQLException {
        saveUrl(url, sourceClass);
    }

    // =========================================================================
    // Analysis Summary
    // =========================================================================

    public void saveAnalysisSummary(int totalClasses, int totalMethods, int failedClasses,
                                    int failedMethods, int totalNativeLibs, int analyzedNativeLibs,
                                    String outputPath) throws SQLException {
        String sql = """
            INSERT OR REPLACE INTO analysis_summary
            (id, total_classes, total_methods, failed_classes, failed_methods, total_native_libs, analyzed_native_libs, output_path)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?)
        """;

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, totalClasses);
            ps.setInt(2, totalMethods);
            ps.setInt(3, failedClasses);
            ps.setInt(4, failedMethods);
            ps.setInt(5, totalNativeLibs);
            ps.setInt(6, analyzedNativeLibs);
            ps.setString(7, outputPath);
            ps.executeUpdate();
        }
    }

    // Backwards compatible version
    public void saveAnalysis(String jobId, String analysisId, String packageName,
                            String versionName, int totalClasses, int totalMethods,
                            int failedClasses, int failedMethods, String outputPath) throws SQLException {
        saveApkInfo(packageName, versionName, null, 0, 0, 0);
        saveAnalysisSummary(totalClasses, totalMethods, failedClasses, failedMethods, 0, 0, outputPath);
    }

    // =========================================================================
    // Timing and Logging
    // =========================================================================

    public long startTiming(String jobId, String phase) throws SQLException {
        String sql = "INSERT INTO process_timing (job_id, phase, started_at, status) VALUES (?, ?, strftime('%s','now') * 1000, 'running')";

        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, jobId);
            ps.setString(2, phase);
            ps.executeUpdate();

            ResultSet keys = ps.getGeneratedKeys();
            return keys.next() ? keys.getLong(1) : -1;
        }
    }

    public void endTiming(long timingId, String status) throws SQLException {
        String sql = """
            UPDATE process_timing
            SET ended_at = strftime('%s','now') * 1000, duration_ms = strftime('%s','now') * 1000 - started_at, status = ?
            WHERE id = ?
        """;

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, status);
            ps.setLong(2, timingId);
            ps.executeUpdate();
        }
    }

    public void log(String jobId, String level, String phase, String message) throws SQLException {
        String sql = "INSERT INTO logs (job_id, level, phase, message) VALUES (?, ?, ?, ?)";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, jobId);
            ps.setString(2, level);
            ps.setString(3, phase);
            ps.setString(4, message);
            ps.executeUpdate();
        }
    }

    public List<Map<String, Object>> getTimings(String jobId) throws SQLException {
        return queryList("SELECT phase, started_at, ended_at, duration_ms, status FROM process_timing WHERE job_id = ? ORDER BY id", jobId);
    }

    public List<Map<String, Object>> getLogs(String jobId) throws SQLException {
        return queryList("SELECT timestamp, level, phase, message FROM logs WHERE job_id = ? ORDER BY id", jobId);
    }

    // =========================================================================
    // Query Methods
    // =========================================================================

    public Map<String, Object> getAnalysisSummary() throws SQLException {
        String sql = "SELECT * FROM analysis_summary WHERE id = 1";

        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery(sql);
            if (rs.next()) {
                Map<String, Object> result = new HashMap<>();
                result.put("total_classes", rs.getInt("total_classes"));
                result.put("total_methods", rs.getInt("total_methods"));
                result.put("failed_classes", rs.getInt("failed_classes"));
                result.put("failed_methods", rs.getInt("failed_methods"));
                result.put("total_native_libs", rs.getInt("total_native_libs"));
                result.put("analyzed_native_libs", rs.getInt("analyzed_native_libs"));
                result.put("output_path", rs.getString("output_path"));
                return result;
            }
        }
        return null;
    }

    public List<Map<String, Object>> getNativeLibs() throws SQLException {
        return queryListNoParam("SELECT * FROM native_libs ORDER BY path");
    }

    public List<Map<String, Object>> getPermissions() throws SQLException {
        return queryListNoParam("SELECT permission, is_dangerous FROM permissions ORDER BY permission");
    }

    public List<Map<String, Object>> getComponents() throws SQLException {
        return queryListNoParam("SELECT type, name, exported FROM components ORDER BY type, name");
    }

    public List<Map<String, Object>> getSecurityFindings() throws SQLException {
        return queryListNoParam("SELECT type, severity, description, location FROM security_findings");
    }

    // Backwards compatible
    public Map<String, Object> getAnalysis(String jobId) throws SQLException {
        Map<String, Object> result = new HashMap<>();
        result.put("id", jobId);

        Map<String, Object> summary = getAnalysisSummary();
        if (summary != null) {
            result.putAll(summary);
        }

        result.put("permissions", getPermissions());
        result.put("components", getComponents());
        result.put("native_libs", getNativeLibs());
        result.put("security_findings", getSecurityFindings());

        return result;
    }

    private List<Map<String, Object>> queryList(String sql, String param) throws SQLException {
        List<Map<String, Object>> results = new ArrayList<>();

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            if (param != null) {
                ps.setString(1, param);
            }
            ResultSet rs = ps.executeQuery();
            ResultSetMetaData meta = rs.getMetaData();
            int cols = meta.getColumnCount();

            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                for (int i = 1; i <= cols; i++) {
                    row.put(meta.getColumnName(i), rs.getObject(i));
                }
                results.add(row);
            }
        }
        return results;
    }

    private List<Map<String, Object>> queryListNoParam(String sql) throws SQLException {
        List<Map<String, Object>> results = new ArrayList<>();

        try (Connection conn = connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            ResultSetMetaData meta = rs.getMetaData();
            int cols = meta.getColumnCount();

            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                for (int i = 1; i <= cols; i++) {
                    row.put(meta.getColumnName(i), rs.getObject(i));
                }
                results.add(row);
            }
        }
        return results;
    }

    // =========================================================================
    // Release Tracking
    // =========================================================================

    public void initializeGlobalSchema() throws SQLException {
        initializeApkSchema();
        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS releases (id INTEGER PRIMARY KEY AUTOINCREMENT, package_name TEXT NOT NULL, version TEXT NOT NULL, channel TEXT NOT NULL, arch TEXT DEFAULT 'universal', url TEXT, is_beta INTEGER DEFAULT 0, source TEXT DEFAULT 'apkpure', first_seen_at INTEGER DEFAULT (strftime('%s', 'now')), UNIQUE(package_name, version, arch))");
            stmt.execute("CREATE TABLE IF NOT EXISTS release_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, package_name TEXT NOT NULL, webhook_url TEXT, channel_filter TEXT DEFAULT 'all', active INTEGER DEFAULT 1, last_check_at INTEGER, created_at INTEGER DEFAULT (strftime('%s', 'now')))");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_releases_pkg ON releases(package_name, version)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_pkg ON release_subscriptions(package_name, active)");
        }
    }

    public boolean saveRelease(String packageName, String version, String channel, String arch, String url, boolean isBeta, String source) throws SQLException {
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement("INSERT OR IGNORE INTO releases (package_name, version, channel, arch, url, is_beta, source) VALUES (?, ?, ?, ?, ?, ?, ?)")) {
            ps.setString(1, packageName); ps.setString(2, version); ps.setString(3, channel);
            ps.setString(4, arch != null ? arch : "universal"); ps.setString(5, url);
            ps.setInt(6, isBeta ? 1 : 0); ps.setString(7, source != null ? source : "apkpure");
            return ps.executeUpdate() > 0;
        }
    }

    public List<Map<String, Object>> getReleases(String packageName, String channel, int limit) throws SQLException {
        String sql = (channel != null && !channel.equals("all"))
            ? "SELECT version, channel, arch, url, is_beta, source, first_seen_at FROM releases WHERE package_name = ? AND channel = ? ORDER BY first_seen_at DESC LIMIT ?"
            : "SELECT version, channel, arch, url, is_beta, source, first_seen_at FROM releases WHERE package_name = ? ORDER BY first_seen_at DESC LIMIT ?";
        List<Map<String, Object>> results = new ArrayList<>();
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, packageName);
            if (channel != null && !channel.equals("all")) { ps.setString(2, channel); ps.setInt(3, limit); }
            else { ps.setInt(2, limit); }
            ResultSet rs = ps.executeQuery();
            ResultSetMetaData meta = rs.getMetaData(); int cols = meta.getColumnCount();
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                for (int i = 1; i <= cols; i++) row.put(meta.getColumnName(i), rs.getObject(i));
                results.add(row);
            }
        }
        return results;
    }

    public Map<String, Map<String, Object>> getLatestReleases(String packageName) throws SQLException {
        Map<String, Map<String, Object>> latest = new HashMap<>();
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement("SELECT version, channel, arch, url, is_beta, first_seen_at FROM releases WHERE package_name = ? AND channel = ? ORDER BY first_seen_at DESC LIMIT 1")) {
            for (String ch : new String[]{"stable", "beta"}) {
                ps.setString(1, packageName); ps.setString(2, ch);
                ResultSet rs = ps.executeQuery();
                if (rs.next()) {
                    Map<String, Object> r = new HashMap<>();
                    r.put("version", rs.getString("version")); r.put("channel", rs.getString("channel"));
                    r.put("arch", rs.getString("arch")); r.put("url", rs.getString("url"));
                    r.put("is_beta", rs.getInt("is_beta")); r.put("first_seen_at", rs.getLong("first_seen_at"));
                    latest.put(ch, r);
                }
            }
        }
        return latest;
    }

    public long createSubscription(String packageName, String webhookUrl, String channelFilter) throws SQLException {
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement("INSERT INTO release_subscriptions (package_name, webhook_url, channel_filter) VALUES (?, ?, ?)", Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, packageName); ps.setString(2, webhookUrl); ps.setString(3, channelFilter != null ? channelFilter : "all");
            ps.executeUpdate();
            ResultSet keys = ps.getGeneratedKeys();
            return keys.next() ? keys.getLong(1) : -1;
        }
    }

    public List<Map<String, Object>> getAllActiveSubscriptions() throws SQLException {
        return queryListNoParam("SELECT id, package_name, webhook_url, channel_filter, last_check_at FROM release_subscriptions WHERE active = 1");
    }

    public void updateSubscriptionLastCheck(long subscriptionId) throws SQLException {
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement("UPDATE release_subscriptions SET last_check_at = strftime('%s', 'now') WHERE id = ?")) {
            ps.setLong(1, subscriptionId); ps.executeUpdate();
        }
    }

    // =========================================================================
    // Data Classes
    // =========================================================================

    public static class ClassData {
        public String name;
        public String packageName;
        public String sourcePath;
        public int methodCount;
        public int failedMethods;
        public boolean decompileFailed;
        public String errorMessage;
        public List<MethodData> methods = new ArrayList<>();
    }

    public static class MethodData {
        public String name;
        public String signature;
        public boolean decompileFailed;
        public String errorMessage;
    }

    public static class MethodCallData {
        public String callerClass;
        public String callerMethod;
        public String callerSignature;
        public String calleeClass;
        public String calleeMethod;
        public String calleeSignature;

        public MethodCallData(String callerClass, String callerMethod, String callerSignature,
                              String calleeClass, String calleeMethod, String calleeSignature) {
            this.callerClass = callerClass;
            this.callerMethod = callerMethod;
            this.callerSignature = callerSignature;
            this.calleeClass = calleeClass;
            this.calleeMethod = calleeMethod;
            this.calleeSignature = calleeSignature;
        }
    }
}
