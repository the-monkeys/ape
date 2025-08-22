package database

import (
	"context"

	"github.com/the-monkeys/ape/internal/models"
)

// Store defines the database operations interface
type Store interface {
	// AppRole operations
	CreateAppRole(ctx context.Context, role *models.AppRole) error
	GetAppRoleByRoleID(ctx context.Context, roleID string) (*models.AppRole, error)
	UpdateAppRole(ctx context.Context, role *models.AppRole) error
	DeleteAppRole(ctx context.Context, roleID string) error

	// Secret operations
	CreateSecret(ctx context.Context, secret *models.Secret) error
	GetSecret(ctx context.Context, path string) (*models.Secret, error)
	GetSecretVersion(ctx context.Context, path string, version int) (*models.Secret, error)
	UpdateSecret(ctx context.Context, secret *models.Secret) error
	DeleteSecret(ctx context.Context, path string) error
	ListSecrets(ctx context.Context, pathPrefix string) ([]*models.Secret, error)

	// Token operations
	CreateToken(ctx context.Context, token *models.Token) error
	GetToken(ctx context.Context, tokenString string) (*models.Token, error)
	RevokeToken(ctx context.Context, tokenString string) error
	CleanupExpiredTokens(ctx context.Context) error

	// Audit operations
	CreateAuditLog(ctx context.Context, log *models.AuditLog) error
	GetAuditLogs(ctx context.Context, limit, offset int, filters map[string]interface{}) ([]*models.AuditLog, error)

	// Policy operations
	CreatePolicy(ctx context.Context, policy *models.Policy) error
	GetPolicy(ctx context.Context, name string) (*models.Policy, error)
	UpdatePolicy(ctx context.Context, policy *models.Policy) error
	DeletePolicy(ctx context.Context, name string) error
	ListPolicies(ctx context.Context) ([]*models.Policy, error)

	// Health check
	Ping(ctx context.Context) error
	Close() error
}
