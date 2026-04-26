package com.maadif.storage;

import com.maadif.model.*;

import java.sql.*;
import java.util.*;

/**
 * SQLite database for storing APK analysis data.
 *
 * Tables:
 *   - apks: APK metadata
 *   - analysis_status: Analysis progress tracking
 *   - java_classes: Decompiled Java classes
 *   - java_methods: Java methods per class
 *   - java_calls: Java callgraph edges
 *   - native_libs: Native .so libraries
 *   - native_functions: Functions per native lib
 *   - native_calls: Native callgraph edges
 */
public class Database {

    private final String dbPath;

    public Database(String dbPath) {
        this.dbPath = dbPath;
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + dbPath);
    }

    /**
     * Create all tables if they don't exist.
     */
    public void initialize() {
        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {

            // APKs table
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS apks (
                    id TEXT PRIMARY KEY,
                    package_name TEXT,
                    version_name TEXT,
                    version_code INTEGER,
                    min_sdk INTEGER,
                    target_sdk INTEGER,
                    uploaded_at INTEGER
                )
            """);

            // Permissions table
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS permissions (
                    apk_id TEXT,
                    permission TEXT,
                    PRIMARY KEY (apk_id, permission)
                )
            """);

            // Components table
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS components (
                    apk_id TEXT,
                    type TEXT,
                    name TEXT,
                    exported INTEGER,
                    PRIMARY KEY (apk_id, type, name)
                )
            """);

            // Analysis status table
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS analysis_status (
                    apk_id TEXT PRIMARY KEY,
                    state TEXT,
                    message TEXT,
                    started_at INTEGER,
                    completed_at INTEGER
                )
            """);

            // Java classes table
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS java_classes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    apk_id TEXT,
                    name TEXT,
                    hash TEXT,
                    UNIQUE(apk_id, name)
                )
            """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_java_classes_apk ON java_classes(apk_id)");

            // Java methods table
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS java_methods (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    apk_id TEXT,
                    class_name TEXT,
                    method_name TEXT,
                    descriptor TEXT,
                    hash TEXT,
                    UNIQUE(apk_id, class_name, method_name, descriptor)
                )
            """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_java_methods_apk ON java_methods(apk_id)");

            // Java calls table (callgraph edges)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS java_calls (
                    apk_id TEXT,
                    caller TEXT,
                    callee TEXT,
                    PRIMARY KEY (apk_id, caller, callee)
                )
            """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_java_calls_apk ON java_calls(apk_id)");

            // Native libs table
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS native_libs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    apk_id TEXT,
                    name TEXT,
                    arch TEXT,
                    UNIQUE(apk_id, name)
                )
            """);

            // Native functions table
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS native_functions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    apk_id TEXT,
                    lib_name TEXT,
                    func_name TEXT,
                    address TEXT,
                    hash TEXT,
                    UNIQUE(apk_id, lib_name, func_name)
                )
            """);

            // Native calls table
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS native_calls (
                    apk_id TEXT,
                    lib_name TEXT,
                    caller TEXT,
                    callee TEXT,
                    PRIMARY KEY (apk_id, lib_name, caller, callee)
                )
            """);

            System.out.println("Database initialized: " + dbPath);

        } catch (SQLException e) {
            throw new RuntimeException("Failed to initialize database", e);
        }
    }

    // -------------------------------------------------------------------------
    // APK Operations
    // -------------------------------------------------------------------------

    public void saveApk(ApkInfo apk) {
        String sql = """
            INSERT OR REPLACE INTO apks
            (id, package_name, version_name, version_code, min_sdk, target_sdk, uploaded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """;

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, apk.id);
            ps.setString(2, apk.packageName);
            ps.setString(3, apk.versionName);
            ps.setInt(4, apk.versionCode);
            ps.setInt(5, apk.minSdk);
            ps.setInt(6, apk.targetSdk);
            ps.setLong(7, apk.uploadedAt);
            ps.executeUpdate();

            // Save permissions
            if (apk.permissions != null) {
                for (String perm : apk.permissions) {
                    savePermission(apk.id, perm);
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to save APK", e);
        }
    }

    public ApkInfo getApk(String id) {
        String sql = "SELECT * FROM apks WHERE id = ?";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                ApkInfo apk = new ApkInfo();
                apk.id = rs.getString("id");
                apk.packageName = rs.getString("package_name");
                apk.versionName = rs.getString("version_name");
                apk.versionCode = rs.getInt("version_code");
                apk.minSdk = rs.getInt("min_sdk");
                apk.targetSdk = rs.getInt("target_sdk");
                apk.uploadedAt = rs.getLong("uploaded_at");
                apk.permissions = getPermissions(id);
                return apk;
            }
            return null;
        } catch (SQLException e) {
            throw new RuntimeException("Failed to get APK", e);
        }
    }

    public List<ApkInfo> listApks() {
        String sql = "SELECT * FROM apks ORDER BY uploaded_at DESC";
        List<ApkInfo> apks = new ArrayList<>();

        try (Connection conn = connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                ApkInfo apk = new ApkInfo();
                apk.id = rs.getString("id");
                apk.packageName = rs.getString("package_name");
                apk.versionName = rs.getString("version_name");
                apk.versionCode = rs.getInt("version_code");
                apk.uploadedAt = rs.getLong("uploaded_at");
                apks.add(apk);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to list APKs", e);
        }

        return apks;
    }

    // -------------------------------------------------------------------------
    // Analysis Status
    // -------------------------------------------------------------------------

    public void setAnalysisStatus(String apkId, String state, String message) {
        String sql = """
            INSERT OR REPLACE INTO analysis_status (apk_id, state, message, started_at, completed_at)
            VALUES (?, ?, ?, ?, ?)
        """;

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, apkId);
            ps.setString(2, state);
            ps.setString(3, message);
            ps.setLong(4, System.currentTimeMillis());
            ps.setLong(5, state.equals("completed") || state.equals("failed")
                ? System.currentTimeMillis() : 0);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to set analysis status", e);
        }
    }

    public AnalysisStatus getAnalysisStatus(String apkId) {
        String sql = "SELECT * FROM analysis_status WHERE apk_id = ?";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, apkId);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                AnalysisStatus status = new AnalysisStatus();
                status.apkId = rs.getString("apk_id");
                status.state = rs.getString("state");
                status.message = rs.getString("message");
                status.startedAt = rs.getLong("started_at");
                status.completedAt = rs.getLong("completed_at");
                return status;
            }
            return null;
        } catch (SQLException e) {
            throw new RuntimeException("Failed to get analysis status", e);
        }
    }

    public void saveAnalysisResult(String apkId, AnalysisResult result) {
        // Result is derived from other tables, nothing extra to save
    }

    public AnalysisResult getAnalysisResult(String apkId) {
        AnalysisResult result = new AnalysisResult();
        result.apkId = apkId;
        result.apkInfo = getApk(apkId);
        result.permissions = getPermissions(apkId);
        result.classCount = countClasses(apkId);
        result.methodCount = countMethods(apkId);
        result.nativeLibCount = countNativeLibs(apkId);
        return result;
    }

    // -------------------------------------------------------------------------
    // Permissions & Components
    // -------------------------------------------------------------------------

    public void savePermission(String apkId, String permission) {
        String sql = "INSERT OR IGNORE INTO permissions (apk_id, permission) VALUES (?, ?)";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, apkId);
            ps.setString(2, permission);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to save permission", e);
        }
    }

    public List<String> getPermissions(String apkId) {
        return queryStringList("SELECT permission FROM permissions WHERE apk_id = ?", apkId);
    }

    public List<String> getComponents(String apkId, String type) {
        return queryStringList(
            "SELECT name FROM components WHERE apk_id = ? AND type = ?",
            apkId, type
        );
    }

    // -------------------------------------------------------------------------
    // Java Classes & Methods
    // -------------------------------------------------------------------------

    public void insertJavaClass(String apkId, String className, String hash) {
        String sql = "INSERT OR REPLACE INTO java_classes (apk_id, name, hash) VALUES (?, ?, ?)";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, apkId);
            ps.setString(2, className);
            ps.setString(3, hash);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to insert class", e);
        }
    }

    public void insertJavaMethod(String apkId, String className, String methodName) {
        String sql = """
            INSERT OR IGNORE INTO java_methods (apk_id, class_name, method_name)
            VALUES (?, ?, ?)
        """;
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, apkId);
            ps.setString(2, className);
            ps.setString(3, methodName);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to insert method", e);
        }
    }

    public Map<String, String> getClassesWithHash(String apkId) {
        Map<String, String> classes = new HashMap<>();
        String sql = "SELECT name, hash FROM java_classes WHERE apk_id = ?";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, apkId);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                classes.put(rs.getString("name"), rs.getString("hash"));
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to get classes", e);
        }
        return classes;
    }

    public List<String> getMethods(String apkId, String className) {
        return queryStringList(
            "SELECT method_name FROM java_methods WHERE apk_id = ? AND class_name = ?",
            apkId, className
        );
    }

    public int countClasses(String apkId) {
        return queryCount("SELECT COUNT(*) FROM java_classes WHERE apk_id = ?", apkId);
    }

    public int countMethods(String apkId) {
        return queryCount("SELECT COUNT(*) FROM java_methods WHERE apk_id = ?", apkId);
    }

    // -------------------------------------------------------------------------
    // Native Libraries & Functions
    // -------------------------------------------------------------------------

    public void insertNativeLib(String apkId, String libName, String arch) {
        String sql = "INSERT OR IGNORE INTO native_libs (apk_id, name, arch) VALUES (?, ?, ?)";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, apkId);
            ps.setString(2, libName);
            ps.setString(3, arch);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to insert native lib", e);
        }
    }

    public List<String> getNativeLibs(String apkId) {
        return queryStringList("SELECT name FROM native_libs WHERE apk_id = ?", apkId);
    }

    public Map<String, String> getNativeFunctionsWithHash(String apkId, String libName) {
        Map<String, String> funcs = new HashMap<>();
        String sql = "SELECT func_name, hash FROM native_functions WHERE apk_id = ? AND lib_name = ?";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, apkId);
            ps.setString(2, libName);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                funcs.put(rs.getString("func_name"), rs.getString("hash"));
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to get native functions", e);
        }
        return funcs;
    }

    public int countNativeLibs(String apkId) {
        return queryCount("SELECT COUNT(*) FROM native_libs WHERE apk_id = ?", apkId);
    }

    // -------------------------------------------------------------------------
    // Callgraph
    // -------------------------------------------------------------------------

    public Set<String> getCallEdges(String apkId) {
        Set<String> edges = new HashSet<>();
        String sql = "SELECT caller, callee FROM java_calls WHERE apk_id = ?";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, apkId);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                edges.add(rs.getString("caller") + " -> " + rs.getString("callee"));
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to get call edges", e);
        }
        return edges;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private List<String> queryStringList(String sql, String... params) {
        List<String> results = new ArrayList<>();
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) {
                ps.setString(i + 1, params[i]);
            }
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                results.add(rs.getString(1));
            }
        } catch (SQLException e) {
            throw new RuntimeException("Query failed", e);
        }
        return results;
    }

    private int queryCount(String sql, String apkId) {
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, apkId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
            return 0;
        } catch (SQLException e) {
            throw new RuntimeException("Count query failed", e);
        }
    }
}
