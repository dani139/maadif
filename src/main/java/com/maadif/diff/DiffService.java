package com.maadif.diff;

import com.maadif.Config;
import com.maadif.model.DiffResult;
import com.maadif.model.DiffResult.*;
import com.maadif.storage.Database;

import java.util.*;

/**
 * Service for comparing two analyzed APKs.
 */
public class DiffService {

    private final Config config;
    private final Database db;

    public DiffService(Config config, Database db) {
        this.config = config;
        this.db = db;
    }

    /**
     * Compare two analyzed APKs and return differences.
     */
    public DiffResult compare(String id1, String id2,
                              boolean diffManifest,
                              boolean diffClasses,
                              boolean diffNative,
                              boolean diffCallgraph) {

        DiffResult result = new DiffResult();
        result.apkId1 = id1;
        result.apkId2 = id2;

        var apk1 = db.getApk(id1);
        var apk2 = db.getApk(id2);

        result.package1 = apk1.packageName;
        result.package2 = apk2.packageName;
        result.version1 = apk1.versionName;
        result.version2 = apk2.versionName;

        result.summary = new DiffSummary();

        if (diffManifest) {
            result.permissions = comparePermissions(id1, id2);
            result.components = compareComponents(id1, id2);
            result.summary.addedPermissions = result.permissions.added;
            result.summary.removedPermissions = result.permissions.removed;
        }

        if (diffClasses) {
            result.classes = compareClasses(id1, id2);
            result.summary.addedClasses = result.classes.added.size();
            result.summary.removedClasses = result.classes.removed.size();
            result.summary.modifiedClasses = result.classes.modified.size();
        }

        if (diffNative) {
            result.nativeCode = compareNativeCode(id1, id2);
        }

        if (diffCallgraph) {
            result.callgraph = compareCallgraphs(id1, id2);
        }

        return result;
    }

    private PermissionDiff comparePermissions(String id1, String id2) {
        Set<String> perms1 = new HashSet<>(db.getPermissions(id1));
        Set<String> perms2 = new HashSet<>(db.getPermissions(id2));

        PermissionDiff diff = new PermissionDiff();
        diff.added = new ArrayList<>();
        diff.removed = new ArrayList<>();
        diff.unchanged = new ArrayList<>();

        for (String p : perms2) {
            if (!perms1.contains(p)) {
                diff.added.add(p);
            } else {
                diff.unchanged.add(p);
            }
        }

        for (String p : perms1) {
            if (!perms2.contains(p)) {
                diff.removed.add(p);
            }
        }

        return diff;
    }

    private ComponentDiff compareComponents(String id1, String id2) {
        ComponentDiff diff = new ComponentDiff();

        diff.addedActivities = listDiff(
            db.getComponents(id1, "activity"),
            db.getComponents(id2, "activity"),
            true
        );
        diff.removedActivities = listDiff(
            db.getComponents(id1, "activity"),
            db.getComponents(id2, "activity"),
            false
        );

        diff.addedServices = listDiff(
            db.getComponents(id1, "service"),
            db.getComponents(id2, "service"),
            true
        );
        diff.removedServices = listDiff(
            db.getComponents(id1, "service"),
            db.getComponents(id2, "service"),
            false
        );

        diff.addedReceivers = listDiff(
            db.getComponents(id1, "receiver"),
            db.getComponents(id2, "receiver"),
            true
        );
        diff.removedReceivers = listDiff(
            db.getComponents(id1, "receiver"),
            db.getComponents(id2, "receiver"),
            false
        );

        return diff;
    }

    private ClassDiff compareClasses(String id1, String id2) {
        ClassDiff diff = new ClassDiff();
        diff.added = new ArrayList<>();
        diff.removed = new ArrayList<>();
        diff.modified = new ArrayList<>();

        Map<String, String> classes1 = db.getClassesWithHash(id1);
        Map<String, String> classes2 = db.getClassesWithHash(id2);

        // Find added classes (in id2 but not in id1)
        for (String className : classes2.keySet()) {
            if (!classes1.containsKey(className)) {
                diff.added.add(className);
            }
        }

        // Find removed classes (in id1 but not in id2)
        for (String className : classes1.keySet()) {
            if (!classes2.containsKey(className)) {
                diff.removed.add(className);
            }
        }

        // Find modified classes (hash changed)
        for (String className : classes1.keySet()) {
            if (classes2.containsKey(className)) {
                String hash1 = classes1.get(className);
                String hash2 = classes2.get(className);
                if (!hash1.equals(hash2)) {
                    ClassDiff.ClassChange change = new ClassDiff.ClassChange();
                    change.className = className;
                    change.addedMethods = getMethodDiff(id1, id2, className, true);
                    change.removedMethods = getMethodDiff(id1, id2, className, false);
                    change.modifiedMethods = getModifiedMethods(id1, id2, className);
                    diff.modified.add(change);
                }
            }
        }

        return diff;
    }

    private NativeDiff compareNativeCode(String id1, String id2) {
        NativeDiff diff = new NativeDiff();
        diff.addedLibs = new ArrayList<>();
        diff.removedLibs = new ArrayList<>();
        diff.modifiedLibs = new HashMap<>();

        Set<String> libs1 = new HashSet<>(db.getNativeLibs(id1));
        Set<String> libs2 = new HashSet<>(db.getNativeLibs(id2));

        for (String lib : libs2) {
            if (!libs1.contains(lib)) {
                diff.addedLibs.add(lib);
            } else {
                // Compare functions in this lib
                NativeDiff.LibraryDiff libDiff = compareLibrary(id1, id2, lib);
                if (!libDiff.addedFunctions.isEmpty() ||
                    !libDiff.removedFunctions.isEmpty() ||
                    !libDiff.modifiedFunctions.isEmpty()) {
                    diff.modifiedLibs.put(lib, libDiff);
                }
            }
        }

        for (String lib : libs1) {
            if (!libs2.contains(lib)) {
                diff.removedLibs.add(lib);
            }
        }

        return diff;
    }

    private NativeDiff.LibraryDiff compareLibrary(String id1, String id2, String libName) {
        NativeDiff.LibraryDiff diff = new NativeDiff.LibraryDiff();
        diff.libName = libName;
        diff.addedFunctions = new ArrayList<>();
        diff.removedFunctions = new ArrayList<>();
        diff.modifiedFunctions = new ArrayList<>();

        Map<String, String> funcs1 = db.getNativeFunctionsWithHash(id1, libName);
        Map<String, String> funcs2 = db.getNativeFunctionsWithHash(id2, libName);

        for (String func : funcs2.keySet()) {
            if (!funcs1.containsKey(func)) {
                diff.addedFunctions.add(func);
            } else if (!funcs1.get(func).equals(funcs2.get(func))) {
                diff.modifiedFunctions.add(func);
            }
        }

        for (String func : funcs1.keySet()) {
            if (!funcs2.containsKey(func)) {
                diff.removedFunctions.add(func);
            }
        }

        return diff;
    }

    private CallgraphDiff compareCallgraphs(String id1, String id2) {
        CallgraphDiff diff = new CallgraphDiff();
        diff.addedEdges = new ArrayList<>();
        diff.removedEdges = new ArrayList<>();

        Set<String> edges1 = db.getCallEdges(id1);
        Set<String> edges2 = db.getCallEdges(id2);

        for (String edge : edges2) {
            if (!edges1.contains(edge)) {
                diff.addedEdges.add(edge);
            }
        }

        for (String edge : edges1) {
            if (!edges2.contains(edge)) {
                diff.removedEdges.add(edge);
            }
        }

        return diff;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private List<String> listDiff(List<String> list1, List<String> list2, boolean added) {
        Set<String> set1 = new HashSet<>(list1);
        Set<String> set2 = new HashSet<>(list2);
        List<String> result = new ArrayList<>();

        if (added) {
            for (String item : set2) {
                if (!set1.contains(item)) result.add(item);
            }
        } else {
            for (String item : set1) {
                if (!set2.contains(item)) result.add(item);
            }
        }

        return result;
    }

    private List<String> getMethodDiff(String id1, String id2, String className, boolean added) {
        List<String> methods1 = db.getMethods(id1, className);
        List<String> methods2 = db.getMethods(id2, className);
        return listDiff(methods1, methods2, added);
    }

    private List<String> getModifiedMethods(String id1, String id2, String className) {
        // Would need method-level hashing to detect modifications
        return new ArrayList<>();
    }
}
