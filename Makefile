# =============================================================================
# MAADIF - Makefile
# =============================================================================
# Simple commands for building and running the APK analysis system
# =============================================================================

.PHONY: build run stop logs shell clean test help

# Default target
help:
	@echo "MAADIF - Mobile Application Analysis & Diff Framework"
	@echo ""
	@echo "Commands:"
	@echo "  make build     - Build Docker image"
	@echo "  make run       - Start API server (foreground)"
	@echo "  make start     - Start API server (background)"
	@echo "  make stop      - Stop API server"
	@echo "  make logs      - View server logs"
	@echo "  make shell     - Open interactive shell in container"
	@echo "  make clean     - Remove Docker image and build artifacts"
	@echo "  make test      - Run a test analysis"
	@echo ""
	@echo "API Endpoints:"
	@echo "  GET  http://localhost:8080/health"
	@echo "  GET  http://localhost:8080/apks"
	@echo "  POST http://localhost:8080/apks/upload"
	@echo "  POST http://localhost:8080/apks/{id}/analyze"
	@echo "  GET  http://localhost:8080/apks/{id}/status"
	@echo "  GET  http://localhost:8080/diff/{id1}/{id2}"

# Build the Docker image
build:
	docker compose build

# Run API server in foreground
run: build
	docker compose up

# Run API server in background
start: build
	docker compose up -d
	@echo "API server started at http://localhost:8080"
	@echo "Run 'make logs' to view logs"

# Stop the server
stop:
	docker compose down

# View logs
logs:
	docker compose logs -f

# Open interactive shell
shell:
	docker compose run --rm maadif /bin/bash

# Clean up
clean:
	docker compose down --rmi local -v
	rm -rf build/ .gradle/

# Test: upload and analyze a sample APK
test:
	@echo "Checking API health..."
	@curl -s http://localhost:8080/health | jq .
	@echo ""
	@echo "Listing APKs..."
	@curl -s http://localhost:8080/apks | jq .

# Build Java locally (without Docker)
local-build:
	gradle build --no-daemon

# Run Java locally (without Docker)
local-run:
	gradle run --no-daemon
