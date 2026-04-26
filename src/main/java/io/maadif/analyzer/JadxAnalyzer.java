package io.maadif.analyzer;

import jadx.api.*;
import jadx.core.dex.nodes.*;
import jadx.core.dex.info.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;

/**
 * JADX-based APK decompiler and analyzer.
 * Uses JADX API for Java source code decompilation and resource extraction.
 */
public class JadxAnalyzer {

    private File outputDir;
    private JadxArgs jadxArgs;

    // Patterns for security-sensitive detection
    private static final Pattern URL_PATTERN = Pattern.compile(
        "(https?://[\\w.-]+(?:/[\\w./-]*)?)", Pattern.CASE_INSENSITIVE);
    private static final Pattern IP_PATTERN = Pattern.compile(
        "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    private static final Pattern API_KEY_PATTERN = Pattern.compile(
        "(?i)(api[_-]?key|apikey|secret[_-]?key|auth[_-]?token|access[_-]?token)\\s*[=:]\\s*[\"']?([\\w-]+)[\"']?");
    private static final Pattern CRYPTO_PATTERN = Pattern.compile(
        "(?i)(AES|DES|RSA|SHA|MD5|HMAC|Cipher|SecretKey|KeyGenerator)");

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
        jadxArgs.setThreadsCount(Runtime.getRuntime().availableProcessors());
        jadxArgs.setSkipResources(false);
        jadxArgs.setSkipSources(false);
    }

    /**
     * Decompile APK and perform comprehensive analysis.
     */
    public DecompilationResult analyzeApk(File apkFile) {
        System.out.println("[JADX] Analyzing: " + apkFile.getName());

        DecompilationResult result = new DecompilationResult();
        result.apkName = apkFile.getName();

        jadxArgs.setInputFile(apkFile);

        try (JadxDecompiler jadx = new JadxDecompiler(jadxArgs)) {
            jadx.load();

            // Extract package info
            result.packageName = extractPackageName(jadx);

            // Get all classes
            List<JavaClass> classes = jadx.getClasses();
            result.totalClasses = classes.size();

            System.out.println("[JADX] Found " + classes.size() + " classes");

            for (JavaClass cls : classes) {
                ClassInfo classInfo = analyzeClass(cls);
                result.classes.add(classInfo);

                // Categorize classes
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
            }

            // Save decompiled sources
            jadx.save();

            // Analyze resources
            analyzeResources(jadx, result);

            // Perform security analysis on decompiled code
            performSecurityAnalysis(result);

            result.success = true;

        } catch (Exception e) {
            result.errors.add("Decompilation error: " + e.getMessage());
            e.printStackTrace();
        }

        return result;
    }

    private String extractPackageName(JadxDecompiler jadx) {
        try {
            for (JavaClass cls : jadx.getClasses()) {
                String pkg = cls.getPackage();
                if (pkg != null && !pkg.isEmpty()) {
                    // Return the root package (first two segments usually)
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

    private ClassInfo analyzeClass(JavaClass cls) {
        ClassInfo info = new ClassInfo();
        info.fullName = cls.getFullName();
        info.packageName = cls.getPackage();
        info.accessFlags = cls.getAccessInfo() != null ? cls.getAccessInfo().rawValue() : 0;

        try {
            String code = cls.getCode();
            info.codeSize = code != null ? code.length() : 0;

            // Extract methods
            for (JavaMethod method : cls.getMethods()) {
                MethodInfo methodInfo = new MethodInfo();
                methodInfo.name = method.getName();
                methodInfo.signature = method.getMethodNode().getMethodInfo().getShortId();
                methodInfo.accessFlags = method.getAccessFlags() != null ? method.getAccessFlags().rawValue() : 0;

                try {
                    String methodCode = method.getCodeStr();
                    if (methodCode != null) {
                        methodInfo.codeLines = methodCode.split("\n").length;
                    }
                } catch (Exception e) {
                    // Method code not available
                }

                info.methods.add(methodInfo);
            }

            // Extract fields
            for (JavaField field : cls.getFields()) {
                FieldInfo fieldInfo = new FieldInfo();
                fieldInfo.name = field.getName();
                fieldInfo.type = field.getType().toString();
                fieldInfo.accessFlags = field.getAccessFlags() != null ? field.getAccessFlags().rawValue() : 0;
                info.fields.add(fieldInfo);
            }

            // Look for strings in code
            if (code != null) {
                extractStringsFromCode(code, info.hardcodedStrings);
                extractUrlsFromCode(code, info.urls);
            }

        } catch (Exception e) {
            info.errors.add(e.getMessage());
        }

        return info;
    }

    private void extractStringsFromCode(String code, List<String> strings) {
        Pattern stringPattern = Pattern.compile("\"([^\"\\\\]*(\\\\.[^\"\\\\]*)*)\"");
        Matcher matcher = stringPattern.matcher(code);
        while (matcher.find() && strings.size() < 50) {
            String str = matcher.group(1);
            if (str.length() > 3 && !str.matches("\\s*")) {
                strings.add(str);
            }
        }
    }

    private void extractUrlsFromCode(String code, List<String> urls) {
        Matcher matcher = URL_PATTERN.matcher(code);
        while (matcher.find()) {
            urls.add(matcher.group(1));
        }
    }

    private void analyzeResources(JadxDecompiler jadx, DecompilationResult result) {
        try {
            for (ResourceFile res : jadx.getResources()) {
                ResourceInfo resInfo = new ResourceInfo();
                resInfo.name = res.getOriginalName();
                resInfo.type = res.getType().toString();

                // Check for interesting resources
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
            // Try to get manifest content
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

    private void performSecurityAnalysis(DecompilationResult result) {
        for (ClassInfo cls : result.classes) {
            // Check for sensitive API usage
            String className = cls.fullName.toLowerCase();

            // Check for crypto operations
            if (className.contains("crypto") || className.contains("cipher") ||
                className.contains("encrypt") || className.contains("decrypt")) {
                result.cryptoClasses.add(cls.fullName);
            }

            // Check for network operations
            if (className.contains("http") || className.contains("socket") ||
                className.contains("network") || className.contains("connection")) {
                result.networkClasses.add(cls.fullName);
            }

            // Check for data storage
            if (className.contains("database") || className.contains("sqlite") ||
                className.contains("sharedpref") || className.contains("storage")) {
                result.storageClasses.add(cls.fullName);
            }

            // Collect all URLs
            result.allUrls.addAll(cls.urls);

            // Check for hardcoded secrets
            for (String str : cls.hardcodedStrings) {
                if (looksLikeSecret(str)) {
                    result.potentialSecrets.add(cls.fullName + ": " + truncate(str, 50));
                }
            }
        }

        // Analyze dangerous permissions
        for (String perm : result.permissions) {
            if (isDangerousPermission(perm)) {
                result.securityIssues.add("DANGEROUS PERMISSION: " + perm);
            }
        }
    }

    private boolean looksLikeSecret(String str) {
        // Check for patterns that look like API keys or secrets
        if (str.length() > 20 && str.matches("[A-Za-z0-9_-]{20,}")) {
            return true;
        }
        if (str.toLowerCase().contains("key") || str.toLowerCase().contains("secret") ||
            str.toLowerCase().contains("token") || str.toLowerCase().contains("password")) {
            return true;
        }
        return false;
    }

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

    private String truncate(String str, int maxLen) {
        return str.length() > maxLen ? str.substring(0, maxLen) + "..." : str;
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
                writer.println("  " + perm);
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

            // Activities
            writer.println("-".repeat(80));
            writer.println("ACTIVITIES");
            writer.println("-".repeat(80));
            for (String activity : result.activities) {
                writer.println("  " + activity);
            }
            writer.println();

            // Services
            if (!result.services.isEmpty()) {
                writer.println("-".repeat(80));
                writer.println("SERVICES");
                writer.println("-".repeat(80));
                for (String service : result.services) {
                    writer.println("  " + service);
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
                writer.println("CRYPTO-RELATED CLASSES");
                writer.println("-".repeat(80));
                for (String cls : result.cryptoClasses) {
                    writer.println("  " + cls);
                }
                writer.println();
            }

            // Network Classes
            if (!result.networkClasses.isEmpty()) {
                writer.println("-".repeat(80));
                writer.println("NETWORK-RELATED CLASSES");
                writer.println("-".repeat(80));
                for (String cls : result.networkClasses.stream().limit(30).toList()) {
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
