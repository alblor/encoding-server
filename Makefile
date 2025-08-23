# Secure Media Encoding Server - Makefile
# Author: Lorenzo Albanese (alblor)

.PHONY: help build up down test clean logs shell client-shell

# Default target
help:
	@echo "Secure Media Encoding Server - Development Commands"
	@echo "Author: Lorenzo Albanese (alblor)"
	@echo ""
	@echo "Available commands:"
	@echo "  build       Build all Docker containers"
	@echo "  up          Start the development environment"
	@echo "  down        Stop the development environment"
	@echo "  test        Run the test suite"
	@echo "  clean       Clean up containers and volumes"
	@echo "  logs        Show container logs"
	@echo "  shell       Open shell in API container"
	@echo "  client-shell Open shell in client tools container"
	@echo "  encrypt     Example: encrypt a test file"
	@echo "  decrypt     Example: decrypt a test file"

# Build all containers
build:
	@echo "Building Docker containers..."
	docker compose -f docker-compose.dev.yml build

# Start development environment
up:
	@echo "Starting Secure Media Encoding Server..."
	docker compose -f docker-compose.dev.yml up -d
	@echo "API available at: http://localhost:8000"
	@echo "API Documentation: http://localhost:8000/api/docs"

# Stop development environment
down:
	@echo "Stopping development environment..."
	docker compose -f docker-compose.dev.yml down

# Run tests
test:
	@echo "Running test suite..."
	docker compose -f docker-compose.dev.yml exec encoding-api python -m pytest /app/tests/ -v

# Clean up everything
clean:
	@echo "Cleaning up containers and volumes..."
	docker compose -f docker-compose.dev.yml down -v
	docker system prune -f

# Show logs
logs:
	docker compose -f docker-compose.dev.yml logs -f

# Open shell in API container
shell:
	docker compose -f docker-compose.dev.yml exec encoding-api bash

# Open shell in client tools container
client-shell:
	docker compose -f docker-compose.dev.yml run --rm test-client bash

# Example: encrypt a test file (requires test media)
encrypt:
	@echo "Example encryption (requires test media file):"
	@echo "docker-compose -f docker-compose.dev.yml run --rm test-client python encrypt_media.py /test-input/sample.mp4 --output /test-output/encrypted.enc"

# Example: decrypt a test file
decrypt:
	@echo "Example decryption:"
	@echo "docker-compose -f docker-compose.dev.yml run --rm test-client python decrypt_media.py /test-output/encrypted.enc --output /test-output/decrypted.mp4"

# Development helpers
dev-setup: build
	@echo "Setting up development environment..."
	mkdir -p test-data test-media test-results
	@echo "Development environment ready!"

# Quick start for new developers
quickstart: dev-setup up
	@echo ""
	@echo "🚀 Secure Media Encoding Server is running!"
	@echo ""
	@echo "📖 API Documentation: http://localhost:8000/api/docs"
	@echo "🔍 Health Check: http://localhost:8000/health"
	@echo "📊 Service Info: http://localhost:8000/"
	@echo ""
	@echo "🔧 Development Commands:"
	@echo "  make logs        - View container logs"
	@echo "  make shell       - Access API container"
	@echo "  make client-shell - Access client tools"
	@echo "  make test        - Run test suite"
	@echo ""
	@echo "Author: Lorenzo Albanese (alblor)"