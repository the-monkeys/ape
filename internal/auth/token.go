package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenService struct {
	secret []byte
	ttl    time.Duration
}

type Claims struct {
	RoleID string `json:"role_id"`
	jwt.RegisteredClaims
}

func NewTokenService(secret string, ttl time.Duration) *TokenService {
	return &TokenService{
		secret: []byte(secret),
		ttl:    ttl,
	}
}

// GenerateToken creates a new JWT token for the given role
func (ts *TokenService) GenerateToken(roleID string) (string, time.Time, error) {
	expiresAt := time.Now().Add(ts.ttl)

	claims := &Claims{
		RoleID: roleID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "ape-service",
			Subject:   roleID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(ts.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, expiresAt, nil
}

// ValidateToken validates a JWT token and returns the claims
func (ts *TokenService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ts.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// RefreshToken creates a new token with extended expiry (if the current token is still valid)
func (ts *TokenService) RefreshToken(tokenString string) (string, time.Time, error) {
	claims, err := ts.ValidateToken(tokenString)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("cannot refresh invalid token: %w", err)
	}

	return ts.GenerateToken(claims.RoleID)
}
