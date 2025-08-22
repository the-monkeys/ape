# A.P.E. - Authorized Primate Encryption

**A.P.E.** is a secure secrets management and encryption service built with Go and PostgreSQL. It provides secure storage, retrieval, and management of sensitive data with JWT-based authentication and role-based access control.

## Features

- **Secrets Management**: Secure storage and retrieval of sensitive data
- **JWT Authentication**: Token-based authentication with configurable TTL
- **AppRole Authentication**: Machine-to-machine authentication support
- **Encryption**: AES-GCM encryption for stored secrets
- **Role-based Access Control**: Fine-grained access policies
- **Audit Logging**: Comprehensive logging of all operations
- **REST API**: Full REST API with OpenAPI/Swagger documentation
- **Auto-opening Documentation**: Swagger UI opens automatically on server start

## Prerequisites

- **Go**: 1.24.4 or later
- **PostgreSQL**: 15 or later
- **Docker & Docker Compose**: For running PostgreSQL locally

## Local Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/the-monkeys/ape.git
cd ape
```

### 2. Start PostgreSQL Database

```bash
# Start PostgreSQL using Docker Compose
docker-compose -f docker-compose-db.yaml up -d

# Verify database is running
docker-compose -f docker-compose-db.yaml ps
```

### 3. Install Dependencies

```bash
# Download Go modules
go mod download
```

### 4. Configure the Application

The default configuration in `config.yaml` is ready for local development:

```yaml
server:
  host: "localhost"
  port: 8080

database:
  host: "localhost"
  port: 5432
  name: "ape_db"
  user: "ape_user"
  password: "ape_password"
```

> **Note**: Change the `jwt_secret` and `encryption_key` in production!

### 5. Run the Application

```bash
# Start the server
go run main.go

# The server will start on http://localhost:8080
# Swagger UI will automatically open in your default browser at:
# http://localhost:8080/docs/swagger
```

### 6. API Documentation

Once the server is running, you can access:

- **Swagger UI**: http://localhost:8080/docs/swagger (opens automatically)
- **OpenAPI JSON**: http://localhost:8080/docs/openapi.json
- **Health Check**: http://localhost:8080/health

## API Usage

### Authentication

```bash
# AppRole login
curl -X POST http://localhost:8080/v1/auth/approle/login \
  -H "Content-Type: application/json" \
  -d '{"role_id": "your_role_id", "secret_id": "your_secret_id"}'
```

### Secret Operations

```bash
# Create a secret (requires authentication)
curl -X POST http://localhost:8080/v1/secret/data/myapp/database \
  -H "Authorization: Bearer <your_jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{"data": {"username": "dbuser", "password": "secret123"}}'

# Retrieve a secret
curl -X GET http://localhost:8080/v1/secret/data/myapp/database \
  -H "Authorization: Bearer <your_jwt_token>"
```

## Development Commands

```bash
# Run with custom config
go run main.go -config custom-config.yaml

# Build the application
go build -o ape main.go

# Run tests
go test ./...

# Stop the database
docker-compose -f docker-compose-db.yaml down
```

## Configuration

Key configuration options in `config.yaml`:

- `server.host/port`: Server binding address
- `database.*`: PostgreSQL connection settings
- `security.jwt_secret`: JWT signing key (change in production!)
- `security.encryption_key`: Data encryption key (change in production!)
- `security.token_ttl`: JWT token time-to-live
- `logging.level`: Log level (debug, info, warn, error)

## Project Structure

```
ape/
├── main.go                     # Application entry point
├── config.yaml                 # Configuration file
├── api/openapi.yaml           # OpenAPI specification
├── internal/
│   ├── server/                # HTTP server setup
│   ├── handlers/              # HTTP request handlers
│   ├── middleware/            # HTTP middleware
│   ├── auth/                  # Authentication logic
│   ├── crypto/                # Encryption services
│   ├── database/              # Database interface & implementation
│   ├── models/                # Data models
│   └── config/                # Configuration handling
└── docker-compose-db.yaml     # PostgreSQL setup
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.