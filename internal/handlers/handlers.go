package handlers

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/the-monkeys/ape/internal/auth"
	"github.com/the-monkeys/ape/internal/crypto"
	"github.com/the-monkeys/ape/internal/database"
	"github.com/the-monkeys/ape/internal/models"
)

type Handler struct {
	store         database.Store
	tokenService  *auth.TokenService
	cryptoService *crypto.Service
}

type AppRoleLoginRequest struct {
	RoleID   string `json:"role_id" binding:"required"`
	SecretID string `json:"secret_id" binding:"required"`
}

type AppRoleLoginResponse struct {
	Auth TokenData `json:"auth"`
}

type TokenData struct {
	ClientToken   string `json:"client_token"`
	TokenType     string `json:"token_type"`
	LeaseDuration int    `json:"lease_duration"`
}

type SecretRequest struct {
	Data map[string]interface{} `json:"data"`
}

type SecretResponse struct {
	Data SecretData `json:"data"`
}

type SecretData struct {
	Data          map[string]interface{} `json:"data"`
	Version       int                    `json:"version"`
	CreatedTime   time.Time              `json:"created_time"`
	LeaseDuration int                    `json:"lease_duration,omitempty"`
}

type ErrorResponse struct {
	Errors []string `json:"errors"`
}

func NewHandler(store database.Store, tokenService *auth.TokenService, cryptoService *crypto.Service) *Handler {
	return &Handler{
		store:         store,
		tokenService:  tokenService,
		cryptoService: cryptoService,
	}
}

// AppRole Authentication
func (h *Handler) AppRoleLogin(c *gin.Context) {
	var req AppRoleLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, "Invalid request format")
		return
	}

	// Get the app role from database
	appRole, err := h.store.GetAppRoleByRoleID(c.Request.Context(), req.RoleID)
	if err != nil {
		h.auditLog(c, "auth.login", req.RoleID, false, "App role not found")
		h.errorResponse(c, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Verify secret_id
	if appRole.SecretID != req.SecretID {
		h.auditLog(c, "auth.login", req.RoleID, false, "Invalid secret_id")
		h.errorResponse(c, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Generate JWT token
	tokenString, expiresAt, err := h.tokenService.GenerateToken(req.RoleID)
	if err != nil {
		h.auditLog(c, "auth.login", req.RoleID, false, "Failed to generate token")
		h.errorResponse(c, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	// Store token in database
	token := &models.Token{
		Token:     tokenString,
		RoleID:    req.RoleID,
		ExpiresAt: expiresAt,
		IsRevoked: false,
	}

	if err := h.store.CreateToken(c.Request.Context(), token); err != nil {
		log.Printf("Failed to store token in database: %v", err)
		// Continue anyway, token is still valid via JWT
	}

	leaseDuration := int(time.Until(expiresAt).Seconds())

	h.auditLog(c, "auth.login", req.RoleID, true, "Successful authentication")

	c.JSON(http.StatusOK, AppRoleLoginResponse{
		Auth: TokenData{
			ClientToken:   tokenString,
			TokenType:     "Bearer",
			LeaseDuration: leaseDuration,
		},
	})
}

// Secret Operations
func (h *Handler) CreateSecret(c *gin.Context) {
	path := c.Param("path")
	if path == "" {
		h.errorResponse(c, http.StatusBadRequest, "Secret path is required")
		return
	}

	// Remove leading slash if present
	path = strings.TrimPrefix(path, "/")

	var req SecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, "Invalid request format")
		return
	}

	claims := h.getClaimsFromContext(c)
	if claims == nil {
		h.errorResponse(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Encrypt sensitive data
	sensitiveKeys := []string{"password", "secret", "key", "token", "credential"}
	encryptedData, err := h.cryptoService.EncryptMap(req.Data, sensitiveKeys)
	if err != nil {
		h.auditLog(c, "secret.create", path, false, "Failed to encrypt secret data")
		h.errorResponse(c, http.StatusInternalServerError, "Failed to encrypt secret data")
		return
	}

	secret := &models.Secret{
		Path:      path,
		Data:      encryptedData,
		CreatedBy: claims.RoleID,
		Encrypted: true,
	}

	if err := h.store.CreateSecret(c.Request.Context(), secret); err != nil {
		h.auditLog(c, "secret.create", path, false, "Failed to create secret")
		h.errorResponse(c, http.StatusInternalServerError, "Failed to create secret")
		return
	}

	h.auditLog(c, "secret.create", path, true, "Secret created successfully")

	c.JSON(http.StatusOK, SecretResponse{
		Data: SecretData{
			Data:        req.Data, // Return original unencrypted data
			Version:     secret.Version,
			CreatedTime: secret.CreatedAt,
		},
	})
}

func (h *Handler) GetSecret(c *gin.Context) {
	path := c.Param("path")
	if path == "" {
		h.errorResponse(c, http.StatusBadRequest, "Secret path is required")
		return
	}

	// Remove leading slash if present
	path = strings.TrimPrefix(path, "/")

	claims := h.getClaimsFromContext(c)
	if claims == nil {
		h.errorResponse(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Get version if specified
	versionStr := c.Query("version")
	var secret *models.Secret
	var err error

	if versionStr != "" {
		version, parseErr := strconv.Atoi(versionStr)
		if parseErr != nil {
			h.errorResponse(c, http.StatusBadRequest, "Invalid version parameter")
			return
		}
		secret, err = h.store.GetSecretVersion(c.Request.Context(), path, version)
	} else {
		secret, err = h.store.GetSecret(c.Request.Context(), path)
	}

	if err != nil {
		h.auditLog(c, "secret.read", path, false, "Secret not found")
		h.errorResponse(c, http.StatusNotFound, "Secret not found")
		return
	}

	// Decrypt sensitive data
	sensitiveKeys := []string{"password", "secret", "key", "token", "credential"}
	decryptedData, err := h.cryptoService.DecryptMap(secret.Data, sensitiveKeys)
	if err != nil {
		h.auditLog(c, "secret.read", path, false, "Failed to decrypt secret data")
		h.errorResponse(c, http.StatusInternalServerError, "Failed to decrypt secret data")
		return
	}

	h.auditLog(c, "secret.read", path, true, "Secret retrieved successfully")

	c.JSON(http.StatusOK, SecretResponse{
		Data: SecretData{
			Data:        decryptedData,
			Version:     secret.Version,
			CreatedTime: secret.CreatedAt,
		},
	})
}

func (h *Handler) DeleteSecret(c *gin.Context) {
	path := c.Param("path")
	if path == "" {
		h.errorResponse(c, http.StatusBadRequest, "Secret path is required")
		return
	}

	// Remove leading slash if present
	path = strings.TrimPrefix(path, "/")

	claims := h.getClaimsFromContext(c)
	if claims == nil {
		h.errorResponse(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if err := h.store.DeleteSecret(c.Request.Context(), path); err != nil {
		h.auditLog(c, "secret.delete", path, false, "Failed to delete secret")
		h.errorResponse(c, http.StatusInternalServerError, "Failed to delete secret")
		return
	}

	h.auditLog(c, "secret.delete", path, true, "Secret deleted successfully")
	c.JSON(http.StatusNoContent, nil)
}

func (h *Handler) ListSecrets(c *gin.Context) {
	pathPrefix := c.Query("path")
	if pathPrefix == "" {
		pathPrefix = ""
	}

	claims := h.getClaimsFromContext(c)
	if claims == nil {
		h.errorResponse(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	secrets, err := h.store.ListSecrets(c.Request.Context(), pathPrefix)
	if err != nil {
		h.auditLog(c, "secret.list", pathPrefix, false, "Failed to list secrets")
		h.errorResponse(c, http.StatusInternalServerError, "Failed to list secrets")
		return
	}

	// Only return paths, not the actual secret data
	var paths []string
	for _, secret := range secrets {
		paths = append(paths, secret.Path)
	}

	h.auditLog(c, "secret.list", pathPrefix, true, "Secrets listed successfully")

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"keys": paths,
		},
	})
}

// AppRole Management
func (h *Handler) CreateAppRole(c *gin.Context) {
	roleName := c.Param("role_name")
	if roleName == "" {
		h.errorResponse(c, http.StatusBadRequest, "Role name is required")
		return
	}

	var req struct {
		Description string   `json:"description"`
		Policies    []string `json:"policies"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, "Invalid request format")
		return
	}

	// Generate role_id and secret_id
	roleID, err := crypto.GenerateRandomString(32)
	if err != nil {
		h.errorResponse(c, http.StatusInternalServerError, "Failed to generate role ID")
		return
	}

	secretID, err := crypto.GenerateRandomString(32)
	if err != nil {
		h.errorResponse(c, http.StatusInternalServerError, "Failed to generate secret ID")
		return
	}

	appRole := &models.AppRole{
		RoleID:      roleID,
		SecretID:    secretID,
		Name:        roleName,
		Description: req.Description,
		Policies:    req.Policies,
	}

	if err := h.store.CreateAppRole(c.Request.Context(), appRole); err != nil {
		h.errorResponse(c, http.StatusInternalServerError, "Failed to create app role")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"role_id":   roleID,
			"secret_id": secretID,
		},
	})
}

// Health Check
func (h *Handler) Health(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if err := h.store.Ping(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "unhealthy",
			"error":  "database connection failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
		"time":   time.Now().UTC(),
	})
}

// Helper methods
func (h *Handler) errorResponse(c *gin.Context, statusCode int, message string) {
	c.JSON(statusCode, ErrorResponse{
		Errors: []string{message},
	})
}

func (h *Handler) getClaimsFromContext(c *gin.Context) *auth.Claims {
	if claims, exists := c.Get("claims"); exists {
		if authClaims, ok := claims.(*auth.Claims); ok {
			return authClaims
		}
	}
	return nil
}

func (h *Handler) auditLog(c *gin.Context, action, resource string, success bool, message string) {
	claims := h.getClaimsFromContext(c)
	roleID := ""
	if claims != nil {
		roleID = claims.RoleID
	}

	auditLog := &models.AuditLog{
		Action:    action,
		Resource:  resource,
		RoleID:    roleID,
		Success:   success,
		Message:   message,
		IPAddress: c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
	}

	// Log async to avoid blocking request
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := h.store.CreateAuditLog(ctx, auditLog); err != nil {
			log.Printf("Failed to create audit log: %v", err)
		}
	}()
}
