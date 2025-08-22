# A.P.E. Go Implementation

This directory contains the Go implementation of A.P.E. (Authorized Primate Encryption) - a production-ready secrets management and encryption service.

## 🚀 Quick Start

### Prerequisites

- Go 1.24.4 or later
- PostgreSQL 12 or later
- Docker (optional)

### 1. Setup Database

```bash
# Using Docker (recommended for development)
docker run --name ape-postgres -e POSTGRES_DB=ape_secrets -e POSTGRES_USER=ape_user -e POSTGRES_PASSWORD=ape_password -p 5432:5432 -d postgres:15-alpine

# Or use the init script with your existing PostgreSQL
psql -f scripts/init.sql
```

### 2. Configure A.P.E.

Edit `config.yaml` to match your environment:

```yaml
database:
  host: "localhost"
  port: 5432
  name: "ape_secrets"
  user: "ape_user"
  password: "ape_password"

security:
  jwt_secret: "your-super-secret-jwt-key-change-this-in-production"
  encryption_key: "32-byte-encryption-key-change-me!!"
```

### 3. Install Dependencies

```bash
go mod download
```

### 4. Run A.P.E.

```bash
# Build and run
make build
./bin/ape -config config.yaml

# Or run directly
make run
```

### 5. Test the API

```bash
# Make the test script executable and run it
chmod +x scripts/test.sh
./scripts/test.sh
```

## 🐳 Docker Quick Start

```bash
# Start everything with Docker Compose
make docker-run

# Stop everything
make docker-stop
```

## 📖 API Usage

### 1. Create an AppRole

```bash
curl -X POST http://localhost:8080/v1/auth/approle/role/myapp \
  -H "Content-Type: application/json" \
  -d '{
    "description": "My application role",
    "policies": ["read-secrets", "write-secrets"]
  }'
```

### 2. Authenticate

```bash
curl -X POST http://localhost:8080/v1/auth/approle/login \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": "your_role_id",
    "secret_id": "your_secret_id"
  }'
```

### 3. Store a Secret

```bash
curl -X POST http://localhost:8080/v1/secret/data/myapp/database \
  -H "Content-Type: application/json" \
  -H "X-Ape-Token: your_token" \
  -d '{
    "data": {
      "username": "db_user",
      "password": "secret_password",
      "host": "localhost",
      "port": 5432
    }
  }'
```

### 4. Retrieve a Secret

```bash
curl -X GET http://localhost:8080/v1/secret/data/myapp/database \
  -H "X-Ape-Token: your_token"
```

## 🏗️ Architecture

```
├── cmd/                    # Application entrypoints
├── internal/
│   ├── auth/              # JWT token management
│   ├── config/            # Configuration management
│   ├── crypto/            # Encryption/decryption services
│   ├── database/          # Database interface and implementations
│   ├── handlers/          # HTTP handlers
│   ├── middleware/        # HTTP middleware
│   ├── models/           # Data models
│   └── server/           # HTTP server setup
├── scripts/              # Utility scripts
├── config.yaml          # Configuration file
├── docker-compose.yml   # Docker Compose setup
└── Dockerfile           # Docker image definition
```

## 🔒 Security Features

- **AES-GCM Encryption**: Sensitive secret values are encrypted at rest
- **JWT Authentication**: Secure token-based authentication
- **AppRole Authentication**: Role-based access for applications
- **Audit Logging**: Complete audit trail of all operations
- **Token TTL**: Configurable token expiration
- **Secret Versioning**: Multiple versions of secrets maintained
- **Database Security**: Prepared statements prevent SQL injection

## 🔧 Configuration

All configuration is handled through `config.yaml`:

```yaml
server:
  host: "localhost"
  port: 8080
  read_timeout: 30s
  write_timeout: 30s

database:
  host: "localhost"
  port: 5432
  name: "ape_secrets"
  user: "ape_user"
  password: "ape_password"
  sslmode: "disable"
  max_open_conns: 25
  max_idle_conns: 25

security:
  jwt_secret: "your-jwt-secret"
  encryption_key: "32-byte-encryption-key-change-me!!"
  token_ttl: "1h"
  secret_ttl: "24h"

logging:
  level: "info"
  format: "json"
  file: "logs/ape.log"

audit:
  enabled: true
  file: "logs/audit.log"
```

## 🧪 Testing

```bash
# Run unit tests
make test

# Run integration tests with test script
./scripts/test.sh

# Manual testing with curl
curl http://localhost:8080/v1/health
```

## 📊 Database Schema

The service automatically creates the following tables:

- `app_roles` - Application roles and credentials
- `secrets` - Encrypted secrets with versioning
- `tokens` - Authentication tokens
- `audit_logs` - Audit trail
- `policies` - Access control policies (future)

## 🚢 Deployment

### Production Checklist

1. **Change Default Secrets**:
   - Generate secure `jwt_secret`
   - Generate secure `encryption_key` (32 bytes)
   - Use strong database passwords

2. **Database Security**:
   - Enable SSL (`sslmode: require`)
   - Use dedicated database user
   - Regular backups

3. **Network Security**:
   - Use HTTPS in production
   - Firewall rules
   - VPN/private networks

4. **Monitoring**:
   - Health check endpoint: `/v1/health`
   - Audit logs in `logs/audit.log`
   - Application logs in `logs/ape.log`

### Docker Production

```bash
# Build production image
docker build -t ape:production .

# Run with production config
docker run -d -p 8080:8080 \
  -v /path/to/prod-config.yaml:/root/config.yaml \
  -v /path/to/logs:/root/logs \
  ape:production
```

## 🛠️ Development

### Adding New Features

1. **Database Changes**: Update models in `internal/models/`
2. **API Endpoints**: Add handlers in `internal/handlers/`
3. **Business Logic**: Add services in appropriate packages
4. **Tests**: Add tests alongside your code

### Make Commands

```bash
make help          # Show available commands
make build         # Build the application
make run           # Run locally
make test          # Run tests
make clean         # Clean build artifacts
make deps          # Download dependencies
make docker-build  # Build Docker image
make docker-run    # Start with Docker Compose
make docker-stop   # Stop Docker Compose
```

## 🔍 Troubleshooting

### Common Issues

1. **Database Connection Failed**:
   - Check PostgreSQL is running
   - Verify connection details in config.yaml
   - Check network connectivity

2. **Authentication Errors**:
   - Verify AppRole exists
   - Check role_id and secret_id are correct
   - Ensure token hasn't expired

3. **Encryption Errors**:
   - Verify encryption_key is exactly 32 bytes
   - Check for key changes between restarts

### Logs

```bash
# Application logs
tail -f logs/ape.log

# Audit logs
tail -f logs/audit.log

# Docker logs
docker-compose logs -f ape
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

A.P.E. is released under the **Primate Public License**. See the `LICENSE` file for details.
