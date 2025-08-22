package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

type Service struct {
	key []byte
}

func NewService(keyString string) (*Service, error) {
	if len(keyString) < 16 {
		return nil, fmt.Errorf("encryption key must be at least 16 characters")
	}

	// Derive a proper 32-byte key using PBKDF2
	key := pbkdf2.Key([]byte(keyString), []byte("ape-salt"), 4096, 32, sha256.New)

	return &Service{key: key}, nil
}

// Encrypt encrypts plaintext using AES-GCM
func (s *Service) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-GCM
func (s *Service) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], string(data[nonceSize:])
	plaintext, err := gcm.Open(nil, nonce, []byte(ciphertext), nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// EncryptMap encrypts sensitive values in a map
func (s *Service) EncryptMap(data map[string]interface{}, sensitiveKeys []string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for key, value := range data {
		if s.isSensitiveKey(key, sensitiveKeys) {
			if strValue, ok := value.(string); ok {
				encrypted, err := s.Encrypt(strValue)
				if err != nil {
					return nil, fmt.Errorf("failed to encrypt key %s: %w", key, err)
				}
				result[key] = encrypted
			} else {
				result[key] = value
			}
		} else {
			result[key] = value
		}
	}

	return result, nil
}

// DecryptMap decrypts sensitive values in a map
func (s *Service) DecryptMap(data map[string]interface{}, sensitiveKeys []string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for key, value := range data {
		if s.isSensitiveKey(key, sensitiveKeys) {
			if strValue, ok := value.(string); ok {
				decrypted, err := s.Decrypt(strValue)
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt key %s: %w", key, err)
				}
				result[key] = decrypted
			} else {
				result[key] = value
			}
		} else {
			result[key] = value
		}
	}

	return result, nil
}

func (s *Service) isSensitiveKey(key string, sensitiveKeys []string) bool {
	for _, sensitiveKey := range sensitiveKeys {
		if key == sensitiveKey {
			return true
		}
	}
	return false
}

// GenerateRandomString generates a cryptographically secure random string
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}
