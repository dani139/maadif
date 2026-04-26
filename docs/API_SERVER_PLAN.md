# MAADIF API Server - Technical Plan

## Overview

REST API server running inside Docker container, providing endpoints for APK analysis with results stored in SQLite database.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Docker Container                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                  Java API Server                           │  │
│  │  (com.sparkjava or Javalin - lightweight, no deps)        │  │
│  │                                                            │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │  │
│  │  │ /analyze    │  │ /native     │  │ /status     │        │  │
│  │  │ /apks       │  │ /analysis/* │  │ /health     │        │  │
│  │  └──────┬──────┘  └──────┬──────┘  └─────────────┘        │  │
│  │         │                │                                 │  │
│  │  ┌──────▼────────────────▼──────┐                         │  │
│  │  │      io.maadif.analyzer      │                         │  │
│  │  │  ApkAnalyzer | JadxAnalyzer  │                         │  │
│  │  │       GhidraAnalyzer         │                         │  │
│  │  └──────────────┬───────────────┘                         │  │
│  │                 │                                          │  │
│  │  ┌──────────────▼───────────────┐                         │  │
│  │  │     SQLite Database          │                         │  │
│  │  │  /workspace/data/maadif.db   │                         │  │
│  │  └──────────────────────────────┘                         │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Mounted Volumes:                                                │
│    /workspace/apks    ← APK files                               │
│    /workspace/output  ← Analysis output                         │
│    /workspace/data    ← SQLite database                         │
└─────────────────────────────────────────────────────────────────┘
```

## API Endpoints

### 1. List Available APKs
```
GET /apks
```
Response:
```json
{
  "apks": [
    {
      "path": "com.whatsapp/whatsapp-2.26.16.73.apk",
      "size": 138347345,
      "name": "whatsapp-2.26.16.73.apk"
    }
  ]
}
```

### 2. Analyze APK
```
POST /analyze
Content-Type: application/json

{
  "apk": "com.whatsapp/whatsapp-2.26.16.73.apk",
  "natives": false,        // optional, default: false (skip native .so analysis)
  "decompile": true        // optional, default: true (save decompiled sources)
}
```
Response:
```json
{
  "id": "abc123",
  "status": "running",
  "message": "Analysis started"
}
```

### 3. Analyze Specific Native Library
```
POST /native
Content-Type: application/json

{
  "apk": "com.whatsapp/whatsapp-2.26.16.73.apk",
  "library": "lib/arm64-v8a/libwhatsapp.so"
}
```
Response:
```json
{
  "id": "def456",
  "status": "running",
  "message": "Native analysis started"
}
```

### 4. Get Analysis Status
```
GET /status/{id}
```
Response:
```json
{
  "id": "abc123",
  "status": "completed",    // pending, running, completed, failed
  "progress": 100,
  "message": "Analysis complete",
  "started_at": 1714142400,
  "completed_at": 1714142650
}
```

### 5. Get Analysis Results
```
GET /analysis/{id}
```
Response:
```json
{
  "id": "abc123",
  "apk": "com.whatsapp/whatsapp-2.26.16.73.apk",
  "package_name": "com.whatsapp",
  "version": "2.26.16.73",
  "total_classes": 76414,
  "permissions": [...],
  "activities": [...],
  "services": [...],
  "native_libraries": [...],
  "security_issues": [...],
  "urls": [...]
}
```

### 6. Health Check
```
GET /health
```
Response:
```json
{
  "status": "ok",
  "tools": {
    "jadx": true,
    "ghidra": true
  }
}
```

## Database Schema

```sql
-- Analysis jobs
CREATE TABLE analysis_jobs (
    id TEXT PRIMARY KEY,
    apk_path TEXT NOT NULL,
    status TEXT DEFAULT 'pending',  -- pending, running, completed, failed
    progress INTEGER DEFAULT 0,
    message TEXT,
    options_json TEXT,              -- JSON of analysis options
    started_at INTEGER,
    completed_at INTEGER,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- APK metadata
CREATE TABLE apk_analysis (
    id TEXT PRIMARY KEY,
    job_id TEXT REFERENCES analysis_jobs(id),
    package_name TEXT,
    version_name TEXT,
    version_code INTEGER,
    min_sdk INTEGER,
    target_sdk INTEGER,
    total_classes INTEGER,
    total_methods INTEGER,
    output_path TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Permissions
CREATE TABLE permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT REFERENCES apk_analysis(id),
    permission TEXT,
    is_dangerous BOOLEAN
);

-- Components (activities, services, receivers, providers)
CREATE TABLE components (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT REFERENCES apk_analysis(id),
    type TEXT,  -- activity, service, receiver, provider
    name TEXT,
    exported BOOLEAN
);

-- Native libraries
CREATE TABLE native_libs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT REFERENCES apk_analysis(id),
    path TEXT,           -- lib/arm64-v8a/libfoo.so
    arch TEXT,           -- arm64-v8a
    size INTEGER,
    function_count INTEGER,
    analyzed BOOLEAN DEFAULT FALSE
);

-- Native functions (for analyzed libs)
CREATE TABLE native_functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lib_id INTEGER REFERENCES native_libs(id),
    name TEXT,
    address TEXT,
    signature TEXT,
    is_export BOOLEAN
);

-- Security findings
CREATE TABLE security_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT REFERENCES apk_analysis(id),
    type TEXT,          -- dangerous_permission, hardcoded_secret, url, etc.
    severity TEXT,      -- info, low, medium, high, critical
    description TEXT,
    location TEXT
);

-- URLs found
CREATE TABLE urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT REFERENCES apk_analysis(id),
    url TEXT,
    source_class TEXT
);

-- Indexes
CREATE INDEX idx_jobs_status ON analysis_jobs(status);
CREATE INDEX idx_analysis_package ON apk_analysis(package_name);
CREATE INDEX idx_native_libs_analysis ON native_libs(analysis_id);
```

## Implementation Plan

### Phase 1: Server Setup (Simple)
1. Create `io.maadif.server.ApiServer` - main server class
2. Use built-in `com.sun.net.httpserver.HttpServer` (no external deps)
3. JSON handling with simple string building (or minimal lib)
4. SQLite via existing JDBC

### Phase 2: Core Endpoints
1. `GET /health` - verify tools available
2. `GET /apks` - list APKs in mounted folder
3. `POST /analyze` - start analysis job (async)
4. `GET /status/{id}` - check job status

### Phase 3: Analysis Integration
1. Wrap existing `ApkAnalyzer` for async execution
2. Store results in database
3. Track progress during analysis

### Phase 4: Native Analysis
1. `POST /native` - analyze specific .so file
2. Extract from APK, run Ghidra analysis
3. Store function data in database

## File Structure

```
src/main/java/io/maadif/
├── analyzer/                    # Existing analyzers
│   ├── ApkAnalyzer.java
│   ├── JadxAnalyzer.java
│   └── GhidraAnalyzer.java
└── server/                      # New API server
    ├── ApiServer.java           # Main server, routes
    ├── Database.java            # SQLite wrapper
    ├── AnalysisJob.java         # Job management
    └── handlers/
        ├── HealthHandler.java
        ├── ApkHandler.java
        ├── AnalyzeHandler.java
        ├── NativeHandler.java
        └── StatusHandler.java
```

## Running

```bash
# Start server on port 8080
docker run -d \
  -p 8080:8080 \
  -v "$PWD/apks:/workspace/apks" \
  -v "$PWD/output:/workspace/output" \
  -v "$PWD/data:/workspace/data" \
  -v "$PWD:/workspace/code" \
  maadif \
  bash -c "cd /workspace/code && bash build.sh && java -cp 'target/*:/opt/jadx/lib/*:/opt/ghidra/...' io.maadif.server.ApiServer"

# Or via run-server.sh script
docker run -d -p 8080:8080 -v ... maadif bash run-server.sh
```

## Key Decisions

1. **No external HTTP framework** - Use JDK's built-in HttpServer
   - Zero dependencies
   - Compiles with same build.sh
   - Simple and reliable

2. **Async analysis** - Jobs run in background threads
   - Immediate response with job ID
   - Poll /status/{id} for progress

3. **SQLite** - Already available in container
   - JDBC driver (sqlite-jdbc) added to classpath
   - Simple file-based persistence

4. **No APK upload** - Use mounted /workspace/apks
   - Simpler for now
   - Can add upload later if needed
