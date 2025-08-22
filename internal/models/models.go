package models

import (
	"time"

	"github.com/google/uuid"
)

// AppRole represents an application role for authentication
type AppRole struct {
	ID          uuid.UUID `json:"id" db:"id"`
	RoleID      string    `json:"role_id" db:"role_id"`
	SecretID    string    `json:"secret_id" db:"secret_id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	Policies    []string  `json:"policies" db:"policies"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Secret represents a stored secret
type Secret struct {
	ID        uuid.UUID              `json:"id" db:"id"`
	Path      string                 `json:"path" db:"path"`
	Data      map[string]interface{} `json:"data" db:"data"`
	Version   int                    `json:"version" db:"version"`
	CreatedBy string                 `json:"created_by" db:"created_by"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`
	ExpiresAt *time.Time             `json:"expires_at" db:"expires_at"`
	Encrypted bool                   `json:"encrypted" db:"encrypted"`
}

// Token represents an authentication token
type Token struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Token     string    `json:"token" db:"token"`
	RoleID    string    `json:"role_id" db:"role_id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	IsRevoked bool      `json:"is_revoked" db:"is_revoked"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Action    string    `json:"action" db:"action"`
	Resource  string    `json:"resource" db:"resource"`
	RoleID    string    `json:"role_id" db:"role_id"`
	Success   bool      `json:"success" db:"success"`
	Message   string    `json:"message" db:"message"`
	IPAddress string    `json:"ip_address" db:"ip_address"`
	UserAgent string    `json:"user_agent" db:"user_agent"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Policy represents an access control policy
type Policy struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	Rules       string    `json:"rules" db:"rules"` // JSON string of policy rules
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}
