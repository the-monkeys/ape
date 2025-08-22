# A.P.E. Makefile

.PHONY: help build run test clean deps docker-build docker-run docker-stop

# Default target
help:
	@echo "🦍 A.P.E. - Authorized Primate Encryption"
	@echo ""
	@echo "Available commands:"
	@echo "  build       - Build the A.P.E. binary"
	@echo "  run         - Run A.P.E. locally"
	@echo "  test        - Run tests"
	@echo "  clean       - Clean build artifacts"
	@echo "  deps        - Download and tidy dependencies"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run  - Run with Docker Compose"
	@echo "  docker-stop - Stop Docker Compose"
	@echo "  create-role - Create a sample AppRole"

# Build the application
build:
	@echo "🔨 Building A.P.E..."
	go build -o bin/ape main.go

# Run the application locally
run:
	@echo "🚀 Starting A.P.E. server..."
	go run main.go -config config.yaml

# Run tests
test:
	@echo "🧪 Running tests..."
	go test -v ./...

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	rm -rf bin/
	rm -rf logs/

# Download and tidy dependencies
deps:
	@echo "📦 Downloading dependencies..."
	go mod download
	go mod tidy

# Docker commands
docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t ape:latest .

docker-run:
	@echo "🐳 Starting A.P.E. with Docker Compose..."
	docker-compose up -d

docker-stop:
	@echo "🛑 Stopping Docker Compose..."
	docker-compose down

# Create a sample AppRole for testing
create-role:
	@echo "🔑 Creating sample AppRole..."
	@echo "First, make sure A.P.E. is running, then run:"
	@echo 'curl -X POST http://localhost:8080/v1/auth/approle/role/sample-app \'
	@echo '     -H "Content-Type: application/json" \'
	@echo '     -d "{"description": "Sample application role", "policies": ["read-secrets"]}"'
