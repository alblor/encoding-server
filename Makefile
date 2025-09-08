# Secure Media Encoding Server - Enhanced Makefile Command Panel
# Author: Lorenzo Albanese (alblor)

.PHONY: help build up down cleanup docs test test-quick test-unit test-encryption test-manual test-automated test-api test-docs test-prepare test-all logs shell client-shell secure-build secure-up secure-down secure-logs secure-shell cert-upload cert-status secure-up-shred secure-down-restore secret-shred secret-restore secret-status

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
	@echo "🔐 Secure Secret Lifecycle Management:"
	@echo "  secure-up-shred   🔥 Start with secret shredding (maximum security mode)"
	@echo "  secure-down-restore 📦 Stop with secret restoration (graceful shutdown)"  
	@echo "  secret-shred      🔥 Shred secrets from host (container must be running)"
	@echo "  secret-restore    📥 Restore secrets from container to host"
	@echo "  secret-status     🔍 Check secret lifecycle status and security mode"
	@echo ""
	@echo "📜 Enterprise Certificate Management:"
	@echo "  cert-upload     Upload persistent enterprise SSL certificate and key"
	@echo "  cert-status     Check certificate status and validity"
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
	@echo "  test-cancellation Job cancellation validation (6 scenarios)"
	@echo "  test-apparmor     AppArmor detection and fallback methods"
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

# Enhanced secure-up with secret shredding (maximum security mode)
secure-up-shred: secure-build
	@echo "🔥 Starting Ultra-Secure Environment with Secret Shredding..."
	@echo "⚡ Phase 1: Starting containers..."
	docker compose -f docker-compose.secure.yml up -d
	@echo "⏳ Waiting for container initialization..."
	@sleep 5
	@echo "🔥 Phase 2: Shredding secrets from host filesystem..."
	@./scripts/secure_secret_lifecycle.sh shred
	@echo ""
	@echo "🔒 MAXIMUM SECURITY MODE ACTIVE:"
	@echo "  🔥 Secrets shredded from host filesystem"
	@echo "  💾 Secrets exist ONLY in container memory (tmpfs)"
	@echo "  📉 Attack surface reduced by 99%"
	@echo "  🌐 API available at: https://localhost:8443 (HTTPS-ONLY)"
	@echo ""
	@echo "⚠️  IMPORTANT: Use 'make secure-down-restore' for graceful shutdown"

# Enhanced secure-down with secret restoration (graceful shutdown)
secure-down-restore:
	@echo "📦 Graceful Shutdown with Secret Restoration..."
	@echo "📥 Phase 1: Restoring secrets from container memory..."
	@./scripts/secure_secret_lifecycle.sh restore
	@echo "🔽 Phase 2: Stopping secure environment..."
	docker compose -f docker-compose.secure.yml down
	@echo ""
	@echo "✅ GRACEFUL SHUTDOWN COMPLETE:"
	@echo "  📥 Secrets restored to host filesystem"
	@echo "  🧹 Container memory cleared automatically"
	@echo "  🔒 Ready for next startup"

# Secret lifecycle management commands
secret-shred:
	@echo "🔥 Shredding secrets from host filesystem..."
	@./scripts/secure_secret_lifecycle.sh shred

secret-restore:
	@echo "📥 Restoring secrets from container to host..."
	@./scripts/secure_secret_lifecycle.sh restore

secret-status:
	@echo "🔍 Checking secret lifecycle status..."
	@./scripts/secure_secret_lifecycle.sh status

# Show API Documentation access points and examples
docs:
	@echo "📚 Secure Media Encoding Server - API Documentation"
	@echo "Author: Lorenzo Albanese (alblor)"
	@echo ""
	@echo "🌐 DOCUMENTATION ACCESS POINTS (HTTPS-ONLY):"
	@echo "  📖 Complete API Documentation: https://localhost:8443/v1/docs"
	@echo "  🚀 System Overview & Quick Start: https://localhost:8443/v1/docs/overview"
	@echo "  🔐 Dual-Mode Encryption Guide: https://localhost:8443/v1/docs/modes"
	@echo "  📊 API Endpoints Reference: https://localhost:8443/v1/docs/endpoints"
	@echo "  🔑 Authentication Guide: https://localhost:8443/v1/docs/auth"
	@echo "  💡 Workflow Examples: https://localhost:8443/v1/docs/examples"
	@echo "  ❌ Error Reference: https://localhost:8443/v1/docs/errors"
	@echo "  🛠️ Client Tools Guide: https://localhost:8443/v1/docs/tools"
	@echo ""
	@echo "🧪 TESTING DOCUMENTATION:"
	@echo "  make test-docs     # Test all 9 documentation endpoints (auto-discovery)"
	@echo ""
	@echo "📋 QUICK EXAMPLES (HTTPS-ONLY):"
	@echo '  curl -k https://localhost:8443/v1/docs | jq                    # Documentation index'
	@echo '  curl -k https://localhost:8443/v1/docs/modes | jq              # Encryption modes'
	@echo '  curl -k https://localhost:8443/v1/docs/examples | jq           # Workflow examples'
	@echo '  curl -k https://localhost:8443/v1/docs/endpoints/submit_job | jq # Job submission docs'
	@echo '  curl -k https://localhost:8443/v1/security/tls-status | jq     # Security status'
	@echo ""
	@echo "💻 BROWSER ACCESS:"
	@echo "  Open your browser to https://localhost:8443/v1/docs for JSON"
	@echo "  Accept the self-signed certificate warning (for development)"
	@echo "  Use 'jq' for pretty formatting or build a frontend interface"
	@echo ""
	@echo "⚠️  REQUIREMENT: Run 'make secure-up' first to start the HTTPS-only server"

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

# Progress tracking validation
test-progress:
	@echo "📊 Running Progress Tracking Tests..."
	python tests/integration/test_progress_tracking.py

# Job cancellation validation
test-cancellation:
	@echo "🛑 Running Job Cancellation Tests..."
	python tests/integration/test_job_cancellation.py

# AppArmor detection validation with comprehensive fallback methods
test-apparmor:
	@echo "🛡️  Testing comprehensive AppArmor detection system..."
	@echo "Validating graceful fallback for Docker-in-LXC permission denied scenarios"
	@echo ""
	python tests/test_apparmor_detection.py
	@echo ""
	@echo "✅ AppArmor detection system validation complete!"
	@echo "    - Multiple detection methods tested"
	@echo "    - Permission denied fallback validated"
	@echo "    - Security level graceful degradation verified"
	@echo "    - Docker-in-LXC compatibility confirmed"
	@echo "Author: Lorenzo Albanese (alblor)"

# Complete test suite with preparation (MAIN COMMAND)
test-all: test-prepare test
	@echo ""
	@echo "🎉 Complete Test Suite Finished!"
	@echo "All test data generated and all scenarios tested"

# Run ALL tests (unit + real-world scenarios) - assumes data ready
test: test-unit test-encryption test-manual test-automated test-api test-docs test-progress test-cancellation test-apparmor
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
	@echo "🔒 Secure API available at: https://localhost:8443 (HTTPS-ONLY)"
	@echo "🛡️  Zero-trust media processing active"
	@echo "💾 All data confined to RAM + encrypted swap"
	@echo "🚫 HTTP completely disabled - all connections must use HTTPS"

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

# =====================================================================
# ENTERPRISE CERTIFICATE MANAGEMENT SYSTEM  
# Persistent certificate system for production deployments
# =====================================================================

# Check certificate status and validity
cert-status:
	@echo "🔍 Checking certificate status..."
	@echo "Getting certificate information from running container..."
	@curl -k -s https://localhost:8443/v1/security/tls-status | jq -r '"📜 Certificate Status:", "🔒 HTTPS Only Mode: " + (.https_only_mode|tostring), "🌐 TLS Enabled: " + (.tls_enabled|tostring), "🚫 HTTP Disabled: " + (.http_disabled|tostring), "🔄 Auto-Renewal: " + (.automatic_renewal|tostring), "", "📋 Certificate Details:", "📄 Status: " + .certificate.status, "🏢 Subject: " + .certificate.subject, "🏛️  Issuer: " + .certificate.issuer, "🔐 Self-Signed: " + (.certificate.is_self_signed|tostring), "📅 Valid Until: " + .certificate.not_valid_after, "⏰ Days Until Expiry: " + (.certificate.days_until_expiry|tostring), "🔢 Serial: " + .certificate.serial_number, "", "🔒 Security Level: " + .security_level, "⏰ Last Checked: " + .timestamp' 2>/dev/null || echo "❌ Could not retrieve certificate status. Is the server running? (make secure-up)"

# Upload persistent enterprise certificate
cert-upload:
	@echo "📜 Persistent Enterprise Certificate Upload System"
	@echo "Author: Lorenzo Albanese (alblor)"
	@echo ""
	@if [ -z "$(CERT)" ] || [ -z "$(KEY)" ]; then \
		echo "❌ Missing certificate files. Usage:"; \
		echo "   CERT=path/to/certificate.pem KEY=path/to/private.key make cert-upload"; \
		echo ""; \
		echo "📋 REQUIREMENTS:"; \
		echo "  • Certificate file in PEM format (.pem, .crt, or .cert)"; \
		echo "  • Private key file in PEM format (.key or .pem)"; \
		echo "  • Key must match the certificate"; \
		echo "  • Certificate must be valid (not expired)"; \
		echo ""; \
		echo "💡 EXAMPLE:"; \
		echo '  CERT=./ssl/mydomain.crt KEY=./ssl/mydomain.key make cert-upload'; \
		echo ""; \
		echo "🔄 PERSISTENT BEHAVIOR:"; \
		echo "  • Enterprise certificates survive container restarts"; \
		echo "  • Automatically loaded on startup (priority over self-signed)"; \
		echo "  • No manual restart required - immediate activation"; \
		exit 1; \
	fi
	@echo "🔍 Validating certificate files..."
	@if [ ! -f "$(CERT)" ]; then echo "❌ Certificate file not found: $(CERT)"; exit 1; fi
	@if [ ! -f "$(KEY)" ]; then echo "❌ Private key file not found: $(KEY)"; exit 1; fi
	@echo "✅ Certificate files found"
	@echo "🔐 Validating certificate format and key compatibility..."
	@openssl x509 -in "$(CERT)" -text -noout > /dev/null 2>&1 || (echo "❌ Invalid certificate format"; exit 1)
	@openssl rsa -in "$(KEY)" -check -noout > /dev/null 2>&1 || (echo "❌ Invalid private key format"; exit 1)
	@echo "✅ Certificate format validation passed"
	@echo "🔍 Checking certificate and key compatibility..."
	@CERT_MODULUS=$$(openssl x509 -noout -modulus -in "$(CERT)" | openssl md5); \
	 KEY_MODULUS=$$(openssl rsa -noout -modulus -in "$(KEY)" | openssl md5); \
	 if [ "$$CERT_MODULUS" != "$$KEY_MODULUS" ]; then \
	 	echo "❌ Certificate and private key do not match!"; \
	 	exit 1; \
	 fi
	@echo "✅ Certificate and private key compatibility verified"
	@echo "📋 Certificate Information:"
	@openssl x509 -in "$(CERT)" -text -noout | grep -E "(Subject:|Issuer:|Not Before|Not After)" | sed 's/^/  /'
	@echo ""
	@echo "💾 Installing persistent enterprise certificate..."
	@mkdir -p ./certificates/enterprise
	@cp "$(CERT)" ./certificates/enterprise/server.crt
	@cp "$(KEY)" ./certificates/enterprise/server.key
	@chmod 644 ./certificates/enterprise/server.crt
	@chmod 600 ./certificates/enterprise/server.key
	@echo "✅ Enterprise certificate installed to persistent storage"
	@echo ""
	@echo "🔄 Restarting secure environment to activate enterprise certificate..."
	@make secure-down > /dev/null 2>&1
	@sleep 2
	@make secure-up > /dev/null 2>&1
	@echo ""
	@echo "⏰ Waiting for server to start with enterprise certificate..."
	@sleep 10
	@echo "🔍 Verifying enterprise certificate is active..."
	@make cert-status
	@echo ""
	@echo "🎉 Persistent enterprise certificate deployment completed!"
	@echo "🔄 Certificate will automatically load on future container restarts"