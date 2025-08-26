# Secure Media Encoding Server - Enhanced Makefile Command Panel
# Author: Lorenzo Albanese (alblor)

.PHONY: help build up down cleanup docs test test-quick test-unit test-encryption test-manual test-automated test-api test-docs test-prepare test-all logs shell client-shell secure-build secure-up secure-down secure-logs secure-shell

# Default target
help:
	@echo "🔒 Secure Media Encoding Server - Command Panel"
	@echo "Author: Lorenzo Albanese (alblor)"
	@echo ""
	@echo "🔐 Primary Ultra-Secure Zero-Trust Environment:"
	@echo "  secure-build    Build ultra-secure Alpine containers"
	@echo "  secure-up       Start zero-trust environment (RAM + encrypted swap)"
	@echo "  secure-down     Stop secure environment"
	@echo "  secure-logs     Show secure environment logs"
	@echo "  secure-shell    Access secure container (non-root)"
	@echo ""
	@echo "🧹 Maintenance:"
	@echo "  cleanup         Clean up containers, volumes, and test data (results too)"
	@echo ""
	@echo "📚 Documentation:"
	@echo "  docs            Show API documentation access points and examples"
	@echo ""
	@echo "🧪 Testing Commands (Secure Environment):"
	@echo "  test-all        🎯 MAIN: Complete test suite (unit + integration + prep)"
	@echo "  test            🚀 FAST: All tests (assumes data ready)"
	@echo "  test-quick      ⚡ QUICK: Unit tests only (17 tests)"
	@echo ""
	@echo "🔍 Individual Test Suites:"
	@echo "  test-unit       Unit tests (17 tests) in secure container"
	@echo "  test-encryption Encryption stub validation"
	@echo "  test-manual     Manual mode with real media files"
	@echo "  test-automated  Automated mode with real media files"
	@echo "  test-api        API endpoint comprehensive testing"
	@echo "  test-docs       Documentation API validation (9 endpoints)"
	@echo "  test-prepare    Generate test data only"

# Note: Development environment removed - use secure-* commands for production

# Enhanced cleanup (renamed from clean)
cleanup:
	@echo "🧹 Cleaning up containers, volumes, and test data..."
	docker compose -f docker-compose.secure.yml down -v
	docker system prune -f
	@echo "Cleaning all test results and output files..."
	rm -rf tests/results/*
	@echo "Cleaning any temporary test artifacts..."
	find . -name "*_encrypted.enc" -type f -delete 2>/dev/null || true
	find . -name "*_decrypted.*" -type f -delete 2>/dev/null || true
	find . -name "*_result.mp4" -type f -delete 2>/dev/null || true
	find . -name "api_test_result_*.mp4" -type f -delete 2>/dev/null || true
	@echo "✅ Cleanup complete - starting with fresh environment!"

# Show API Documentation access points and examples
docs:
	@echo "📚 Secure Media Encoding Server - API Documentation"
	@echo "Author: Lorenzo Albanese (alblor)"
	@echo ""
	@echo "🌐 DOCUMENTATION ACCESS POINTS:"
	@echo "  📖 Complete API Documentation: http://localhost:8000/v1/docs"
	@echo "  🚀 System Overview & Quick Start: http://localhost:8000/v1/docs/overview"
	@echo "  🔐 Dual-Mode Encryption Guide: http://localhost:8000/v1/docs/modes"
	@echo "  📊 API Endpoints Reference: http://localhost:8000/v1/docs/endpoints"
	@echo "  🔑 Authentication Guide: http://localhost:8000/v1/docs/auth"
	@echo "  💡 Workflow Examples: http://localhost:8000/v1/docs/examples"
	@echo "  ❌ Error Reference: http://localhost:8000/v1/docs/errors"
	@echo "  🛠️ Client Tools Guide: http://localhost:8000/v1/docs/tools"
	@echo ""
	@echo "🧪 TESTING DOCUMENTATION:"
	@echo "  make test-docs     # Test all 9 documentation endpoints (auto-discovery)"
	@echo ""
	@echo "📋 QUICK EXAMPLES:"
	@echo '  curl http://localhost:8000/v1/docs | jq                    # Documentation index'
	@echo '  curl http://localhost:8000/v1/docs/modes | jq              # Encryption modes'
	@echo '  curl http://localhost:8000/v1/docs/examples | jq           # Workflow examples'
	@echo '  curl http://localhost:8000/v1/docs/endpoints/submit_job | jq # Job submission docs'
	@echo ""
	@echo "💻 BROWSER ACCESS:"
	@echo "  Open your browser to http://localhost:8000/v1/docs for JSON"
	@echo "  Use 'jq' for pretty formatting or build a frontend interface"
	@echo ""
	@echo "⚠️  REQUIREMENT: Run 'make secure-up' first to start the API server"

# Test data preparation
test-prepare:
	@echo "🔧 Preparing test environment..."
	@echo "Generating test data..."
	python tests/scripts/generate_test_data.py
	@echo "Test environment ready!"

# Unit tests (existing 17 tests) - SECURE ENVIRONMENT PRIMARY
test-unit:
	@echo "🧪 Running Unit Tests (17 tests) in Secure Environment..."
	docker compose -f docker-compose.secure.yml exec secure-encoding-api python -m pytest /app/tests/unit/ -v

# Fast encryption/decryption stub testing
test-encryption:
	@echo "🔐 Running Encryption Stub Tests..."
	python tests/integration/test_encryption_stubs.py

# Manual mode simulation testing
test-manual:
	@echo "🎬 Running Manual Mode Tests..."
	python tests/integration/test_manual_mode.py

# Automated mode simulation testing  
test-automated:
	@echo "🔒 Running Automated Mode Tests..."
	python tests/integration/test_automated_mode.py

# Complete API endpoint simulation
test-api:
	@echo "🌐 Running API Endpoint Tests..."
	python tests/integration/test_api_endpoints.py

# Documentation API validation
test-docs:
	@echo "📚 Running Documentation API Tests..."
	python tests/integration/test_documentation_api.py

# Complete test suite with preparation (MAIN COMMAND)
test-all: test-prepare test
	@echo ""
	@echo "🎉 Complete Test Suite Finished!"
	@echo "All test data generated and all scenarios tested"

# Run ALL tests (unit + real-world scenarios) - assumes data ready
test: test-unit test-encryption test-manual test-automated test-api test-docs
	@echo ""
	@echo "📊 All Testing Complete!"
	@echo "Check tests/results/ for detailed reports"

# Quick unit tests only
test-quick: test-unit
	@echo ""
	@echo "⚡ Quick Unit Testing Complete!"
	@echo "17/17 unit tests validated"

# Ultra-Secure Environment Commands

# Build ultra-secure containers
secure-build:
	@echo "🔐 Building ultra-secure Alpine containers..."
	docker compose -f docker-compose.secure.yml build

# Start zero-trust environment 
secure-up:
	@echo "🔒 Starting Ultra-Secure Zero-Trust Environment..."
	@echo "⚡ RAM-only processing for files <4GB"
	@echo "🔐 Encrypted swap emulation for files >4GB"
	@echo "🛡️  Maximum Docker security enabled"
	docker compose -f docker-compose.secure.yml up -d
	@echo ""
	@echo "🔒 Secure API available at: http://localhost:8000"
	@echo "🛡️  Zero-trust media processing active"
	@echo "💾 All data confined to RAM + encrypted swap"

# Stop secure environment
secure-down:
	@echo "🔐 Stopping secure environment..."
	docker compose -f docker-compose.secure.yml down
	@echo "🧹 All temporary data automatically purged from memory"

# Show secure environment logs
secure-logs:
	@echo "🔍 Secure environment logs:"
	docker compose -f docker-compose.secure.yml logs -f

# Access secure container shell
secure-shell:
	@echo "🔐 Accessing secure container (non-root user)..."
	docker compose -f docker-compose.secure.yml exec secure-encoding-api sh


# Show logs
# Note: Use secure-logs and secure-shell for production environment access
	@echo ""
	@echo "🚀 Secure Media Encoding Server is running!"
	@echo ""
	@echo "📖 API Documentation: http://localhost:8000/api/docs"
	@echo "🔍 Health Check: http://localhost:8000/health"
	@echo "📊 Service Info: http://localhost:8000/"
	@echo ""
	@echo "🧪 Testing Commands:"
	@echo "  make test-all    - Run complete test suite"
	@echo "  make test        - Run all tests (assumes data ready)"
	@echo "  make test-unit   - Run unit tests only"
	@echo "Author: Lorenzo Albanese (alblor)"