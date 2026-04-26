package com.maadif.model;

import java.util.List;
import java.util.Map;

/**
 * Result of comparing two APK analyses.
 */
public class DiffResult {
    public String apkId1;
    public String apkId2;
    public String package1;
    public String package2;
    public String version1;
    public String version2;

    // Summary
    public DiffSummary summary;

    // Detailed diffs
    public PermissionDiff permissions;
    public ComponentDiff components;
    public ClassDiff classes;
    public NativeDiff nativeCode;
    public CallgraphDiff callgraph;

    public static class DiffSummary {
        public int addedClasses;
        public int removedClasses;
        public int modifiedClasses;
        public int addedMethods;
        public int removedMethods;
        public int modifiedMethods;
        public int addedNativeFunctions;
        public int removedNativeFunctions;
        public int modifiedNativeFunctions;
        public List<String> addedPermissions;
        public List<String> removedPermissions;
    }

    public static class PermissionDiff {
        public List<String> added;
        public List<String> removed;
        public List<String> unchanged;
    }

    public static class ComponentDiff {
        public List<String> addedActivities;
        public List<String> removedActivities;
        public List<String> addedServices;
        public List<String> removedServices;
        public List<String> addedReceivers;
        public List<String> removedReceivers;
    }

    public static class ClassDiff {
        public List<String> added;
        public List<String> removed;
        public List<ClassChange> modified;

        public static class ClassChange {
            public String className;
            public List<String> addedMethods;
            public List<String> removedMethods;
            public List<String> modifiedMethods;
        }
    }

    public static class NativeDiff {
        public List<String> addedLibs;
        public List<String> removedLibs;
        public Map<String, LibraryDiff> modifiedLibs;

        public static class LibraryDiff {
            public String libName;
            public List<String> addedFunctions;
            public List<String> removedFunctions;
            public List<String> modifiedFunctions;
        }
    }

    public static class CallgraphDiff {
        public List<String> addedEdges;   // "caller -> callee"
        public List<String> removedEdges;
        public List<String> newEntryPoints;
        public List<String> removedEntryPoints;
    }
}
