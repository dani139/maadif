package com.maadif.model;

import java.util.List;

/**
 * Basic APK metadata extracted from AndroidManifest.xml
 */
public class ApkInfo {
    public String id;              // SHA256 hash
    public String packageName;     // com.example.app
    public String versionName;     // "1.2.3"
    public int versionCode;        // 123
    public int minSdk;
    public int targetSdk;
    public List<String> permissions;
    public long uploadedAt;

    public ApkInfo() {}

    public ApkInfo(String id, String packageName, String versionName, int versionCode) {
        this.id = id;
        this.packageName = packageName;
        this.versionName = versionName;
        this.versionCode = versionCode;
        this.uploadedAt = System.currentTimeMillis();
    }
}
