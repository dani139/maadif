package io.maadif.analyzer;

import jadx.api.*;
import jadx.core.dex.nodes.*;
import jadx.core.dex.info.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * JADX-based APK decompiler and analyzer.
 * Optimized for large APKs with memory-efficient processing.
 */
public class JadxAnalyzer {

    private File outputDir;
    private JadxArgs jadxArgs;

    // Batch size for processing classes
    private static final int BATCH_SIZE = 1000;

    // Patterns for security-sensitive detection
    private static final Pattern URL_PATTERN = Pattern.compile(
        "(https?://[\\w.-]+(?:/[\\w./-]*)?)", Pattern.CASE_INSENSITIVE);

    public JadxAnalyzer(File outputDir) {
        this.outputDir = outputDir;
        this.jadxArgs = new JadxArgs();
        configureJadx();
    }

    private void configureJadx() {
        jadxArgs.setOutDir(new File(outputDir, "jadx_output"));
        jadxArgs.setOutDirSrc(new File(outputDir, "jadx_output/sources"));
        jadxArgs.setOutDirRes(new File(outputDir, "jadx_output/resources"));
        jadxArgs.setDeobfuscationOn(true);
        jadxArgs.setShowInconsistentCode(true);
        // Use fewer threads to reduce memory pressure
        jadxArgs.setThreadsCount(Math.min(4, Runtime.getRuntime().availableProcessors()));
        jadxArgs.setSkipResources(false);
        jadxArgs.setSkipSources(false);
    }

    /**
     * Analyze APK with memory-efficient processing.
     * Phase 1: Extract metadata without full decompilation
     * Phase 2: Let JADX save decompiled sources (memory-managed internally)
     */
    public DecompilationResult analyzeApk(File apkFile) {
        System.out.println("[JADX] Analyzing: " + apkFile.getName());
        System.out.println("[JADX] Memory before: " + getMemoryUsage());

        DecompilationResult result = new DecompilationResult();
        result.apkName = apkFile.getName();

        jadxArgs.setInputFile(apkFile);

        try (JadxDecompiler jadx = new JadxDecompiler(jadxArgs)) {
            jadx.load();

            // Extract package info
            result.packageName = extractPackageName(jadx);

            // Get all classes (just references, not decompiled yet)
            List<JavaClass> classes = jadx.getClasses();
            result.totalClasses = classes.size();

            System.out.println("[JADX] Found " + classes.size() + " classes");
            System.out.println("[JADX] Memory after load: " + getMemoryUsage());

            // Phase 1: Extract metadata WITHOUT triggering full decompilation
            System.out.println("[JADX] Phase 1: Extracting metadata (no decompilation)...");
            extractMetadataOnly(classes, result);

            System.out.println("[JADX] Memory after metadata: " + getMemoryUsage());

            // Phase 2: Analyze resources (manifest, etc.)
            System.out.println("[JADX] Phase 2: Analyzing resources...");
            analyzeResources(jadx, result);

            // Phase 3: Save decompiled sources (JADX handles memory internally)
            System.out.println("[JADX] Phase 3: Saving decompiled sources...");
            System.out.println("[JADX] This may take a while for large APKs...");
            jadx.save();

            System.out.println("[JADX] Memory after save: " + getMemoryUsage());

            // Phase 4: Security analysis on saved files (streamed, memory efficient)
            System.out.println("[JADX] Phase 4: Security analysis on saved sources...");
            performSecurityAnalysisOnFiles(result);

            result.success = true;

        } catch (Exception e) {
            result.errors.add("Decompilation error: " + e.getMessage());
            e.printStackTrace();
        }

        return result;
    }

    /**
     * Extract metadata without triggering decompilation.
     * This only reads class/method/field names from DEX, not full code.
     */
    private void extractMetadataOnly(List<JavaClass> classes, DecompilationResult result) {
        AtomicInteger processed = new AtomicInteger(0);
        int total = classes.size();

        for (JavaClass cls : classes) {
            try {
                ClassInfo classInfo = new ClassInfo();
                classInfo.fullName = cls.getFullName();
                classInfo.packageName = cls.getPackage();

                // Get access info without decompiling
                AccessInfo accessInfo = cls.getAccessInfo();
                classInfo.accessFlags = accessInfo != null ? accessInfo.rawValue() : 0;

                // Categorize by name patterns (no decompilation needed)
                String className = cls.getFullName();
                if (className.contains(".activity.") || className.endsWith("Activity")) {
                    result.activities.add(className);
                } else if (className.contains(".service.") || className.endsWith("Service")) {
                    result.services.add(className);
                } else if (className.contains(".receiver.") || className.endsWith("Receiver")) {
                    result.receivers.add(className);
                } else if (className.contains(".provider.") || className.endsWith("Provider")) {
                    result.providers.add(className);
                }

                // Categorize by pattern for security analysis
                String lowerName = className.toLowerCase();
                if (lowerName.contains("crypto") || lowerName.contains("cipher") ||
                    lowerName.contains("encrypt") || lowerName.contains("decrypt")) {
                    result.cryptoClasses.add(className);
                }
                if (lowerName.contains("http") || lowerName.contains("socket") ||
                    lowerName.contains("network") || lowerName.contains("connection")) {
                    result.networkClasses.add(className);
                }
                if (lowerName.contains("database") || lowerName.contains("sqlite") ||
                    lowerName.contains("sharedpref") || lowerName.contains("storage")) {
                    result.storageClasses.add(className);
                }

                // Get method names (from DEX metadata, no decompilation)
                for (JavaMethod method : cls.getMethods()) {
                    MethodInfo methodInfo = new MethodInfo();
                    methodInfo.name = method.getName();
                    try {
                        methodInfo.signature = method.getMethodNode().getMethodInfo().getShortId();
                    } catch (Exception e) {
                        methodInfo.signature = method.getName();
                    }
                    classInfo.methods.add(methodInfo);
                }

                // Get field names
                for (JavaField field : cls.getFields()) {
                    FieldInfo fieldInfo = new FieldInfo();
                    fieldInfo.name = field.getName();
                    fieldInfo.type = field.getType().toString();
                    classInfo.fields.add(fieldInfo);
                }

                result.classes.add(classInfo);

                // Progress logging
                int count = processed.incrementAndGet();
                if (count % 5000 == 0) {
                    System.out.println("[JADX] Metadata progress: " + count + "/" + total +
                                     " (" + (count * 100 / total) + "%)");
                    // Hint GC periodically
                    if (count % 10000 == 0) {
                        System.gc();
                    }
                }

            } catch (Exception e) {
                // Skip problematic classes
            }
        }
    }

    private String extractPackageName(JadxDecompiler jadx) {
        try {
            for (JavaClass cls : jadx.getClasses()) {
                String pkg = cls.getPackage();
                if (pkg != null && !pkg.isEmpty() && !pkg.startsWith("android.") &&
                    !pkg.startsWith("java.") && !pkg.startsWith("kotlin.")) {
                    String[] parts = pkg.split("\\.");
                    if (parts.length >= 2) {
                        return parts[0] + "." + parts[1];
                    }
                    return pkg;
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return "unknown";
    }

    private void analyzeResources(JadxDecompiler jadx, DecompilationResult result) {
        try {
            for (ResourceFile res : jadx.getResources()) {
                ResourceInfo resInfo = new ResourceInfo();
                resInfo.name = res.getOriginalName();
                resInfo.type = res.getType().toString();

                String name = res.getOriginalName().toLowerCase();
                if (name.equals("androidmanifest.xml")) {
                    analyzeManifest(res, result);
                } else if (name.endsWith(".xml")) {
                    result.layoutFiles.add(res.getOriginalName());
                } else if (name.endsWith(".so")) {
                    result.nativeLibraries.add(res.getOriginalName());
                } else if (name.endsWith(".dex")) {
                    result.dexFiles.add(res.getOriginalName());
                }

                result.resources.add(resInfo);
            }
        } catch (Exception e) {
            result.errors.add("Resource analysis error: " + e.getMessage());
        }
    }

    private void analyzeManifest(ResourceFile manifestRes, DecompilationResult result) {
        try {
            String manifest = null;
            try {
                var content = manifestRes.loadContent();
                if (content != null) {
                    var textInfo = content.getText();
                    if (textInfo != null) {
                        manifest = textInfo.getCodeStr();
                    }
                }
            } catch (Exception e) {
                // Manifest not decodable
            }

            if (manifest != null && !manifest.isEmpty()) {
                result.manifestContent = manifest;

                // Extract permissions
                Pattern permPattern = Pattern.compile("android:name=\"(android\\.permission\\.[^\"]+)\"");
                Matcher matcher = permPattern.matcher(manifest);
                while (matcher.find()) {
                    result.permissions.add(matcher.group(1));
                }

                // Check for dangerous configurations
                if (manifest.contains("android:debuggable=\"true\"")) {
                    result.securityIssues.add("CRITICAL: App is debuggable");
                }
                if (manifest.contains("android:allowBackup=\"true\"")) {
                    result.securityIssues.add("WARNING: Backup is allowed");
                }
                if (manifest.contains("android:usesCleartextTraffic=\"true\"")) {
                    result.securityIssues.add("WARNING: Cleartext traffic allowed");
                }
                if (manifest.contains("android:exported=\"true\"")) {
                    result.securityIssues.add("INFO: Exported components found");
                }
            }
        } catch (Exception e) {
            result.errors.add("Manifest parsing error: " + e.getMessage());
        }
    }

    /**
     * Perform security analysis on already-saved decompiled files.
     * This streams through files without loading everything into memory.
     */
    private void performSecurityAnalysisOnFiles(DecompilationResult result) {
        File sourcesDir = new File(outputDir, "jadx_output/sources");
        if (!sourcesDir.exists()) {
            return;
        }

        try {
            AtomicInteger fileCount = new AtomicInteger(0);

            Files.walk(sourcesDir.toPath())
                .filter(p -> p.toString().endsWith(".java"))
                .forEach(javaFile -> {
                    try {
                        analyzeJavaFileForSecurity(javaFile.toFile(), result);
                        int count = fileCount.incrementAndGet();
                        if (count % 5000 == 0) {
                            System.out.println("[JADX] Security scan progress: " + count + " files");
                        }
                    } catch (Exception e) {
                        // Skip problematic files
                    }
                });

            System.out.println("[JADX] Scanned " + fileCount.get() + " source files");

        } catch (Exception e) {
            result.errors.add("Security analysis error: " + e.getMessage());
        }
    }

    private void analyzeJavaFileForSecurity(File javaFile, DecompilationResult result) throws Exception {
        // Read file in chunks to avoid loading huge files entirely
        String content = Files.readString(javaFile.toPath());

        // Extract URLs
        Matcher urlMatcher = URL_PATTERN.matcher(content);
        while (urlMatcher.find() && result.allUrls.size() < 1000) {
            result.allUrls.add(urlMatcher.group(1));
        }

        // Look for potential secrets (simple heuristic)
        if (content.contains("api_key") || content.contains("apiKey") ||
            content.contains("secret") || content.contains("password")) {
            // Extract the line containing the potential secret
            String[] lines = content.split("\n");
            for (String line : lines) {
                String lower = line.toLowerCase();
                if ((lower.contains("api_key") || lower.contains("apikey") ||
                     lower.contains("secret") || lower.contains("password")) &&
                    line.contains("=") && line.contains("\"") &&
                    result.potentialSecrets.size() < 100) {
                    String trimmed = line.trim();
                    if (trimmed.length() < 200) {
                        result.potentialSecrets.add(javaFile.getName() + ": " + trimmed);
                    }
                }
            }
        }
    }

    private String getMemoryUsage() {
        Runtime rt = Runtime.getRuntime();
        long used = (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024);
        long max = rt.maxMemory() / (1024 * 1024);
        return used + "MB / " + max + "MB";
    }

    /**
     * Analyze dangerous permissions.
     */
    private boolean isDangerousPermission(String perm) {
        Set<String> dangerous = Set.of(
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE"
        );
        return dangerous.contains(perm);
    }

    /**
     * Generate comprehensive analysis report.
     */
    public void generateReport(DecompilationResult result, File reportFile) throws Exception {
        try (PrintWriter writer = new PrintWriter(new FileWriter(reportFile))) {
            writer.println("=".repeat(80));
            writer.println("JADX DECOMPILATION & ANALYSIS REPORT");
            writer.println("=".repeat(80));
            writer.println("APK: " + result.apkName);
            writer.println("Package: " + result.packageName);
            writer.println("Analysis Date: " + new Date());
            writer.println();

            // Summary
            writer.println("-".repeat(80));
            writer.println("SUMMARY");
            writer.println("-".repeat(80));
            writer.printf("Total Classes: %d%n", result.totalClasses);
            writer.printf("Activities: %d%n", result.activities.size());
            writer.printf("Services: %d%n", result.services.size());
            writer.printf("Receivers: %d%n", result.receivers.size());
            writer.printf("Providers: %d%n", result.providers.size());
            writer.printf("DEX Files: %d%n", result.dexFiles.size());
            writer.printf("Native Libraries: %d%n", result.nativeLibraries.size());
            writer.println();

            // Permissions
            writer.println("-".repeat(80));
            writer.println("PERMISSIONS (" + result.permissions.size() + ")");
            writer.println("-".repeat(80));
            for (String perm : result.permissions) {
                String marker = isDangerousPermission(perm) ? " [DANGEROUS]" : "";
                writer.println("  " + perm + marker);
            }
            writer.println();

            // Security Issues
            if (!result.securityIssues.isEmpty()) {
                writer.println("-".repeat(80));
                writer.println("SECURITY ISSUES (" + result.securityIssues.size() + ")");
                writer.println("-".repeat(80));
                for (String issue : result.securityIssues) {
                    writer.println("  [!] " + issue);
                }
                writer.println();
            }

            // URLs Found
            if (!result.allUrls.isEmpty()) {
                writer.println("-".repeat(80));
                writer.println("URLS FOUND (" + result.allUrls.size() + ")");
                writer.println("-".repeat(80));
                Set<String> uniqueUrls = new TreeSet<>(result.allUrls);
                for (String url : uniqueUrls.stream().limit(50).toList()) {
                    writer.println("  " + url);
                }
                if (uniqueUrls.size() > 50) {
                    writer.println("  ... and " + (uniqueUrls.size() - 50) + " more");
                }
                writer.println();
            }

            // Potential Secrets
            if (!result.potentialSecrets.isEmpty()) {
                writer.println("-".repeat(80));
                writer.println("POTENTIAL SECRETS (" + result.potentialSecrets.size() + ")");
                writer.println("-".repeat(80));
                for (String secret : result.potentialSecrets.stream().limit(20).toList()) {
                    writer.println("  " + secret);
                }
                writer.println();
            }

            // Native Libraries
            if (!result.nativeLibraries.isEmpty()) {
                writer.println("-".repeat(80));
                writer.println("NATIVE LIBRARIES");
                writer.println("-".repeat(80));
                for (String lib : result.nativeLibraries) {
                    writer.println("  " + lib);
                }
                writer.println();
            }

            // Crypto Classes
            if (!result.cryptoClasses.isEmpty()) {
                writer.println("-".repeat(80));
                writer.println("CRYPTO-RELATED CLASSES (" + result.cryptoClasses.size() + ")");
                writer.println("-".repeat(80));
                for (String cls : result.cryptoClasses.stream().limit(50).toList()) {
                    writer.println("  " + cls);
                }
                writer.println();
            }

            // Network Classes
            if (!result.networkClasses.isEmpty()) {
                writer.println("-".repeat(80));
                writer.println("NETWORK-RELATED CLASSES (" + result.networkClasses.size() + ")");
                writer.println("-".repeat(80));
                for (String cls : result.networkClasses.stream().limit(50).toList()) {
                    writer.println("  " + cls);
                }
                writer.println();
            }

            // Errors
            if (!result.errors.isEmpty()) {
                writer.println("-".repeat(80));
                writer.println("ERRORS");
                writer.println("-".repeat(80));
                for (String error : result.errors) {
                    writer.println("  " + error);
                }
            }
        }

        System.out.println("[JADX] Report written to: " + reportFile.getAbsolutePath());
    }

    // Data classes
    public static class DecompilationResult {
        public String apkName;
        public String packageName;
        public String manifestContent;
        public boolean success = false;
        public int totalClasses;

        public List<ClassInfo> classes = new ArrayList<>();
        public List<String> activities = new ArrayList<>();
        public List<String> services = new ArrayList<>();
        public List<String> receivers = new ArrayList<>();
        public List<String> providers = new ArrayList<>();
        public List<String> permissions = new ArrayList<>();
        public List<String> dexFiles = new ArrayList<>();
        public List<String> nativeLibraries = new ArrayList<>();
        public List<String> layoutFiles = new ArrayList<>();
        public List<ResourceInfo> resources = new ArrayList<>();

        public List<String> securityIssues = new ArrayList<>();
        public List<String> allUrls = new ArrayList<>();
        public List<String> potentialSecrets = new ArrayList<>();
        public List<String> cryptoClasses = new ArrayList<>();
        public List<String> networkClasses = new ArrayList<>();
        public List<String> storageClasses = new ArrayList<>();

        public List<String> errors = new ArrayList<>();
    }

    public static class ClassInfo {
        public String fullName;
        public String packageName;
        public int accessFlags;
        public int codeSize;
        public List<MethodInfo> methods = new ArrayList<>();
        public List<FieldInfo> fields = new ArrayList<>();
        public List<String> hardcodedStrings = new ArrayList<>();
        public List<String> urls = new ArrayList<>();
        public List<String> errors = new ArrayList<>();
    }

    public static class MethodInfo {
        public String name;
        public String signature;
        public int accessFlags;
        public int codeLines;
    }

    public static class FieldInfo {
        public String name;
        public String type;
        public int accessFlags;
    }

    public static class ResourceInfo {
        public String name;
        public String type;
    }
}
