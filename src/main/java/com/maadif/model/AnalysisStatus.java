package com.maadif.model;

/**
 * Status of an ongoing or completed analysis.
 */
public class AnalysisStatus {
    public String apkId;
    public String state;      // "pending", "running", "completed", "failed"
    public String message;
    public long startedAt;
    public long completedAt;

    // Progress tracking
    public int totalSteps;
    public int completedSteps;
    public String currentStep;

    public AnalysisStatus() {}

    public AnalysisStatus(String apkId, String state, String message) {
        this.apkId = apkId;
        this.state = state;
        this.message = message;
        this.startedAt = System.currentTimeMillis();
    }
}
