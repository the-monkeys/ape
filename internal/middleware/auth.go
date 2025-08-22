package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/the-monkeys/ape/internal/auth"
	"github.com/the-monkeys/ape/internal/database"
)

func AuthMiddleware(tokenService *auth.TokenService, store database.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth for health check and app role login
		if c.Request.URL.Path == "/v1/health" || c.Request.URL.Path == "/v1/auth/approle/login" {
			c.Next()
			return
		}

		// Get token from header
		authHeader := c.GetHeader("X-Ape-Token")
		if authHeader == "" {
			authHeader = c.GetHeader("Authorization")
			if authHeader != "" {
				// Remove "Bearer " prefix if present
				authHeader = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"errors": []string{"Missing authentication token"},
			})
			c.Abort()
			return
		}

		// Validate JWT token
		claims, err := tokenService.ValidateToken(authHeader)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"errors": []string{"Invalid or expired token"},
			})
			c.Abort()
			return
		}

		// Optional: Check if token exists in database and is not revoked
		// This adds extra security but requires database call
		if store != nil {
			token, err := store.GetToken(c.Request.Context(), authHeader)
			if err != nil || token.IsRevoked {
				c.JSON(http.StatusUnauthorized, gin.H{
					"errors": []string{"Token revoked or not found"},
				})
				c.Abort()
				return
			}
		}

		// Store claims in context for handlers to use
		c.Set("claims", claims)
		c.Next()
	}
}

// CORSMiddleware adds CORS headers
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, X-Ape-Token, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// LoggingMiddleware logs request details
func LoggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return ""
	})
}
