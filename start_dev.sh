#!/bin/bash
# Secure Media Encoding Server - Development Startup Script
# Author: Lorenzo Albanese (alblor)

set -e

echo "🚀 Starting Secure Media Encoding Server Development Environment"
echo "Author: Lorenzo Albanese (alblor)"
echo "Architecture: Proxmox-optimized secure media encoding"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Error: docker-compose is not installed. Please install Docker Compose."
    exit 1
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p test-data test-media test-results logs

# Build containers
echo "🔨 Building Docker containers..."
docker-compose -f docker-compose.dev.yml build

# Start services
echo "🏃 Starting services..."
docker-compose -f docker-compose.dev.yml up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 5

# Check service health
echo "🔍 Checking service health..."
if curl -f -s http://localhost:8000/health > /dev/null; then
    echo "✅ API service is healthy"
else
    echo "⚠️  API service may still be starting..."
fi

echo ""
echo "🎉 Development environment is ready!"
echo ""
echo "📖 API Documentation: http://localhost:8000/api/docs"
echo "🔍 Health Check: http://localhost:8000/health"
echo "📊 Service Info: http://localhost:8000/"
echo ""
echo "🔧 Useful Commands:"
echo "  make logs        - View container logs"
echo "  make shell       - Access API container"
echo "  make client-shell - Access client tools"
echo "  make test        - Run test suite"
echo "  make down        - Stop environment"
echo ""
echo "🔐 Encryption Modes:"
echo "  - Automated: User sends/receives unencrypted data, server handles encryption"
echo "  - Manual: Client pre-encrypts data using provided tools"
echo ""
echo "📝 Example API Usage:"
echo "  # Submit encoding job (automated mode)"
echo "  curl -X POST http://localhost:8000/v1/jobs \\"
echo "    -F 'file=@video.mp4' \\"
echo "    -F 'params={\"video_codec\":\"libx264\",\"audio_codec\":\"copy\"}' \\"
echo "    -F 'encryption_mode=automated'"
echo ""
echo "  # Check job status"
echo "  curl http://localhost:8000/v1/jobs/{job_id}"
echo ""
echo "Ready to build secure media encoding solutions! 🎬🔒"