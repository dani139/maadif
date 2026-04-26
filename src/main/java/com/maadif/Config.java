package com.maadif;

/**
 * Application configuration loaded from environment variables.
 */
public class Config {
    public final String apksDir;
    public final String outputDir;
    public final int port;
    public final String ghidraPath;
    public final String jadxPath;

    public Config(String apksDir, String outputDir, int port, String ghidraPath, String jadxPath) {
        this.apksDir = apksDir;
        this.outputDir = outputDir;
        this.port = port;
        this.ghidraPath = ghidraPath;
        this.jadxPath = jadxPath;
    }

    public static Config load() {
        return new Config(
            getEnv("MAADIF_APKS_DIR", "/workspace/apks"),
            getEnv("MAADIF_OUTPUT_DIR", "/workspace/output"),
            Integer.parseInt(getEnv("MAADIF_PORT", "8080")),
            getEnv("GHIDRA_INSTALL_DIR", "/opt/ghidra"),
            getEnv("JADX_PATH", "/opt/jadx/bin/jadx")
        );
    }

    private static String getEnv(String name, String defaultValue) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            value = System.getProperty(name.toLowerCase().replace('_', '.'), defaultValue);
        }
        return value;
    }
}
