package com.maadif.model;

import java.util.List;
import java.util.Map;

/**
 * Complete analysis result for an APK.
 */
public class AnalysisResult {
    public String apkId;
    public ApkInfo apkInfo;

    // Component counts
    public int classCount;
    public int methodCount;
    public int nativeLibCount;
    public int nativeFunctionCount;

    // Manifest data
    public List<String> permissions;
    public List<ComponentInfo> activities;
    public List<ComponentInfo> services;
    public List<ComponentInfo> receivers;
    public List<ComponentInfo> providers;

    // Native libraries found
    public List<NativeLibInfo> nativeLibs;

    // Callgraph summary
    public CallgraphSummary javaCallgraph;
    public Map<String, CallgraphSummary> nativeCallgraphs; // per .so file

    public static class ComponentInfo {
        public String name;
        public boolean exported;
        public List<String> intentFilters;
    }

    public static class NativeLibInfo {
        public String name;           // libfoo.so
        public String arch;           // arm64-v8a
        public int functionCount;
        public List<String> exports;  // exported symbols
    }

    public static class CallgraphSummary {
        public int nodeCount;         // functions/methods
        public int edgeCount;         // calls
        public List<String> entryPoints;
        public List<String> mostCalledFunctions;
    }
}
