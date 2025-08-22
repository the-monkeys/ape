package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	_ "github.com/lib/pq"

	"github.com/the-monkeys/ape/internal/config"
	"github.com/the-monkeys/ape/internal/models"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(cfg *config.DatabaseConfig) (*PostgresStore, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SSLMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConn)
	db.SetMaxIdleConns(cfg.MaxIdleConn)
	db.SetConnMaxLifetime(time.Hour)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &PostgresStore{db: db}

	if err := store.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return store, nil
}

func (s *PostgresStore) createTables() error {
	queries := []string{
		`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`,

		`CREATE TABLE IF NOT EXISTS app_roles (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			role_id VARCHAR(255) UNIQUE NOT NULL,
			secret_id VARCHAR(255) NOT NULL,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			policies TEXT[], -- Array of policy names
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS secrets (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			path VARCHAR(512) NOT NULL,
			data JSONB NOT NULL,
			version INTEGER NOT NULL DEFAULT 1,
			created_by VARCHAR(255) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			expires_at TIMESTAMP WITH TIME ZONE,
			encrypted BOOLEAN DEFAULT FALSE,
			UNIQUE(path, version)
		);`,

		`CREATE TABLE IF NOT EXISTS tokens (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			token VARCHAR(512) UNIQUE NOT NULL,
			role_id VARCHAR(255) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			is_revoked BOOLEAN DEFAULT FALSE
		);`,

		`CREATE TABLE IF NOT EXISTS audit_logs (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			action VARCHAR(255) NOT NULL,
			resource VARCHAR(512),
			role_id VARCHAR(255),
			success BOOLEAN NOT NULL,
			message TEXT,
			ip_address INET,
			user_agent TEXT,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS policies (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			name VARCHAR(255) UNIQUE NOT NULL,
			description TEXT,
			rules JSONB NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,

		`CREATE INDEX IF NOT EXISTS idx_secrets_path ON secrets(path);`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token);`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_role_id ON audit_logs(role_id);`,
	}

	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %s, error: %w", query, err)
		}
	}

	return nil
}

// AppRole operations
func (s *PostgresStore) CreateAppRole(ctx context.Context, role *models.AppRole) error {
	query := `
		INSERT INTO app_roles (role_id, secret_id, name, description, policies, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id`

	role.ID = uuid.New()
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()

	err := s.db.QueryRowContext(ctx, query,
		role.RoleID, role.SecretID, role.Name, role.Description,
		pq.Array(role.Policies), role.CreatedAt, role.UpdatedAt).Scan(&role.ID)

	if err != nil {
		return fmt.Errorf("failed to create app role: %w", err)
	}

	return nil
}

func (s *PostgresStore) GetAppRoleByRoleID(ctx context.Context, roleID string) (*models.AppRole, error) {
	query := `
		SELECT id, role_id, secret_id, name, description, policies, created_at, updated_at
		FROM app_roles WHERE role_id = $1`

	role := &models.AppRole{}
	err := s.db.QueryRowContext(ctx, query, roleID).Scan(
		&role.ID, &role.RoleID, &role.SecretID, &role.Name,
		&role.Description, pq.Array(&role.Policies), &role.CreatedAt, &role.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("app role not found")
		}
		return nil, fmt.Errorf("failed to get app role: %w", err)
	}

	return role, nil
}

func (s *PostgresStore) UpdateAppRole(ctx context.Context, role *models.AppRole) error {
	query := `
		UPDATE app_roles 
		SET secret_id = $2, name = $3, description = $4, policies = $5, updated_at = $6
		WHERE role_id = $1`

	role.UpdatedAt = time.Now()

	_, err := s.db.ExecContext(ctx, query,
		role.RoleID, role.SecretID, role.Name, role.Description,
		pq.Array(role.Policies), role.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to update app role: %w", err)
	}

	return nil
}

func (s *PostgresStore) DeleteAppRole(ctx context.Context, roleID string) error {
	query := `DELETE FROM app_roles WHERE role_id = $1`

	_, err := s.db.ExecContext(ctx, query, roleID)
	if err != nil {
		return fmt.Errorf("failed to delete app role: %w", err)
	}

	return nil
}

// Secret operations
func (s *PostgresStore) CreateSecret(ctx context.Context, secret *models.Secret) error {
	// Get the latest version for this path
	var maxVersion int
	versionQuery := `SELECT COALESCE(MAX(version), 0) FROM secrets WHERE path = $1`
	err := s.db.QueryRowContext(ctx, versionQuery, secret.Path).Scan(&maxVersion)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to get max version: %w", err)
	}

	secret.Version = maxVersion + 1
	secret.ID = uuid.New()
	secret.CreatedAt = time.Now()
	secret.UpdatedAt = time.Now()

	dataJSON, err := json.Marshal(secret.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}

	query := `
		INSERT INTO secrets (id, path, data, version, created_by, created_at, updated_at, expires_at, encrypted)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err = s.db.ExecContext(ctx, query,
		secret.ID, secret.Path, dataJSON, secret.Version,
		secret.CreatedBy, secret.CreatedAt, secret.UpdatedAt, secret.ExpiresAt, secret.Encrypted)

	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	return nil
}

func (s *PostgresStore) GetSecret(ctx context.Context, path string) (*models.Secret, error) {
	query := `
		SELECT id, path, data, version, created_by, created_at, updated_at, expires_at, encrypted
		FROM secrets 
		WHERE path = $1 
		ORDER BY version DESC 
		LIMIT 1`

	return s.scanSecret(ctx, query, path)
}

func (s *PostgresStore) GetSecretVersion(ctx context.Context, path string, version int) (*models.Secret, error) {
	query := `
		SELECT id, path, data, version, created_by, created_at, updated_at, expires_at, encrypted
		FROM secrets 
		WHERE path = $1 AND version = $2`

	return s.scanSecret(ctx, query, path, version)
}

func (s *PostgresStore) scanSecret(ctx context.Context, query string, args ...interface{}) (*models.Secret, error) {
	secret := &models.Secret{}
	var dataJSON []byte

	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&secret.ID, &secret.Path, &dataJSON, &secret.Version,
		&secret.CreatedBy, &secret.CreatedAt, &secret.UpdatedAt, &secret.ExpiresAt, &secret.Encrypted)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("secret not found")
		}
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if err := json.Unmarshal(dataJSON, &secret.Data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret data: %w", err)
	}

	return secret, nil
}

func (s *PostgresStore) UpdateSecret(ctx context.Context, secret *models.Secret) error {
	return s.CreateSecret(ctx, secret) // Creates a new version
}

func (s *PostgresStore) DeleteSecret(ctx context.Context, path string) error {
	query := `DELETE FROM secrets WHERE path = $1`

	_, err := s.db.ExecContext(ctx, query, path)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	return nil
}

func (s *PostgresStore) ListSecrets(ctx context.Context, pathPrefix string) ([]*models.Secret, error) {
	query := `
		SELECT DISTINCT ON (path) id, path, data, version, created_by, created_at, updated_at, expires_at, encrypted
		FROM secrets 
		WHERE path LIKE $1 
		ORDER BY path, version DESC`

	rows, err := s.db.QueryContext(ctx, query, pathPrefix+"%")
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	defer rows.Close()

	var secrets []*models.Secret
	for rows.Next() {
		secret := &models.Secret{}
		var dataJSON []byte

		err := rows.Scan(
			&secret.ID, &secret.Path, &dataJSON, &secret.Version,
			&secret.CreatedBy, &secret.CreatedAt, &secret.UpdatedAt, &secret.ExpiresAt, &secret.Encrypted)

		if err != nil {
			return nil, fmt.Errorf("failed to scan secret: %w", err)
		}

		if err := json.Unmarshal(dataJSON, &secret.Data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal secret data: %w", err)
		}

		secrets = append(secrets, secret)
	}

	return secrets, nil
}

// Token operations
func (s *PostgresStore) CreateToken(ctx context.Context, token *models.Token) error {
	query := `
		INSERT INTO tokens (id, token, role_id, created_at, expires_at, is_revoked)
		VALUES ($1, $2, $3, $4, $5, $6)`

	token.ID = uuid.New()
	token.CreatedAt = time.Now()

	_, err := s.db.ExecContext(ctx, query,
		token.ID, token.Token, token.RoleID, token.CreatedAt, token.ExpiresAt, token.IsRevoked)

	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}

	return nil
}

func (s *PostgresStore) GetToken(ctx context.Context, tokenString string) (*models.Token, error) {
	query := `
		SELECT id, token, role_id, created_at, expires_at, is_revoked
		FROM tokens 
		WHERE token = $1 AND is_revoked = FALSE AND expires_at > NOW()`

	token := &models.Token{}
	err := s.db.QueryRowContext(ctx, query, tokenString).Scan(
		&token.ID, &token.Token, &token.RoleID, &token.CreatedAt, &token.ExpiresAt, &token.IsRevoked)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("token not found or expired")
		}
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	return token, nil
}

func (s *PostgresStore) RevokeToken(ctx context.Context, tokenString string) error {
	query := `UPDATE tokens SET is_revoked = TRUE WHERE token = $1`

	_, err := s.db.ExecContext(ctx, query, tokenString)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	return nil
}

func (s *PostgresStore) CleanupExpiredTokens(ctx context.Context) error {
	query := `DELETE FROM tokens WHERE expires_at < NOW()`

	_, err := s.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	return nil
}

// Audit operations
func (s *PostgresStore) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	query := `
		INSERT INTO audit_logs (id, action, resource, role_id, success, message, ip_address, user_agent, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	log.ID = uuid.New()
	log.CreatedAt = time.Now()

	_, err := s.db.ExecContext(ctx, query,
		log.ID, log.Action, log.Resource, log.RoleID, log.Success,
		log.Message, log.IPAddress, log.UserAgent, log.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

func (s *PostgresStore) GetAuditLogs(ctx context.Context, limit, offset int, filters map[string]interface{}) ([]*models.AuditLog, error) {
	query := `
		SELECT id, action, resource, role_id, success, message, ip_address, user_agent, created_at
		FROM audit_logs 
		ORDER BY created_at DESC 
		LIMIT $1 OFFSET $2`

	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.AuditLog
	for rows.Next() {
		log := &models.AuditLog{}
		err := rows.Scan(
			&log.ID, &log.Action, &log.Resource, &log.RoleID, &log.Success,
			&log.Message, &log.IPAddress, &log.UserAgent, &log.CreatedAt)

		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}

		logs = append(logs, log)
	}

	return logs, nil
}

// Policy operations (basic implementation)
func (s *PostgresStore) CreatePolicy(ctx context.Context, policy *models.Policy) error {
	query := `
		INSERT INTO policies (id, name, description, rules, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	policy.ID = uuid.New()
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	_, err := s.db.ExecContext(ctx, query,
		policy.ID, policy.Name, policy.Description, policy.Rules, policy.CreatedAt, policy.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	return nil
}

func (s *PostgresStore) GetPolicy(ctx context.Context, name string) (*models.Policy, error) {
	query := `
		SELECT id, name, description, rules, created_at, updated_at
		FROM policies WHERE name = $1`

	policy := &models.Policy{}
	err := s.db.QueryRowContext(ctx, query, name).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policy.Rules, &policy.CreatedAt, &policy.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("policy not found")
		}
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	return policy, nil
}

func (s *PostgresStore) UpdatePolicy(ctx context.Context, policy *models.Policy) error {
	query := `
		UPDATE policies 
		SET description = $2, rules = $3, updated_at = $4
		WHERE name = $1`

	policy.UpdatedAt = time.Now()

	_, err := s.db.ExecContext(ctx, query, policy.Name, policy.Description, policy.Rules, policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	return nil
}

func (s *PostgresStore) DeletePolicy(ctx context.Context, name string) error {
	query := `DELETE FROM policies WHERE name = $1`

	_, err := s.db.ExecContext(ctx, query, name)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	return nil
}

func (s *PostgresStore) ListPolicies(ctx context.Context) ([]*models.Policy, error) {
	query := `
		SELECT id, name, description, rules, created_at, updated_at
		FROM policies ORDER BY name`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.Policy
	for rows.Next() {
		policy := &models.Policy{}
		err := rows.Scan(
			&policy.ID, &policy.Name, &policy.Description, &policy.Rules, &policy.CreatedAt, &policy.UpdatedAt)

		if err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}

		policies = append(policies, policy)
	}

	return policies, nil
}

// Health check and cleanup
func (s *PostgresStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}
