package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/the-monkeys/ape/internal/auth"
	"github.com/the-monkeys/ape/internal/config"
	"github.com/the-monkeys/ape/internal/crypto"
	"github.com/the-monkeys/ape/internal/database"
	"github.com/the-monkeys/ape/internal/handlers"
	"github.com/the-monkeys/ape/internal/middleware"
)

type Server struct {
	config        *config.Config
	store         database.Store
	tokenService  *auth.TokenService
	cryptoService *crypto.Service
	handler       *handlers.Handler
	httpServer    *http.Server
}

func New(cfg *config.Config) (*Server, error) {
	// Initialize database
	store, err := database.NewPostgresStore(&cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize crypto service
	cryptoService, err := crypto.NewService(cfg.Security.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize crypto service: %w", err)
	}

	// Initialize token service
	tokenService := auth.NewTokenService(cfg.Security.JWTSecret, cfg.Security.TokenTTL)

	// Initialize handlers
	handler := handlers.NewHandler(store, tokenService, cryptoService)

	return &Server{
		config:        cfg,
		store:         store,
		tokenService:  tokenService,
		cryptoService: cryptoService,
		handler:       handler,
	}, nil
}

func (s *Server) setupRoutes() *gin.Engine {
	// Set gin mode
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()

	// Middleware
	r.Use(middleware.CORSMiddleware())
	r.Use(middleware.LoggingMiddleware())
	r.Use(gin.Recovery())

	// Health check (no auth required)
	r.GET("/v1/health", s.handler.Health)

	// Auth routes (no auth required)
	auth := r.Group("/v1/auth")
	{
		auth.POST("/approle/login", s.handler.AppRoleLogin)
	}

	// Protected routes (require authentication)
	api := r.Group("/v1")
	api.Use(middleware.AuthMiddleware(s.tokenService, s.store))
	{
		// Secret operations
		secretData := api.Group("/secret/data")
		{
			secretData.POST("/*path", s.handler.CreateSecret)
			secretData.GET("/*path", s.handler.GetSecret)
			secretData.DELETE("/*path", s.handler.DeleteSecret)
		}

		// Secret metadata operations
		secretMeta := api.Group("/secret/metadata")
		{
			secretMeta.GET("", s.handler.ListSecrets)
		}

		// AppRole management (admin operations)
		appRoles := api.Group("/auth/approle/role")
		{
			appRoles.POST("/:role_name", s.handler.CreateAppRole)
		}
	}

	return r
}

func (s *Server) Start() error {
	router := s.setupRoutes()

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port),
		Handler:      router,
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
	}

	// Start cleanup routine for expired tokens
	go s.cleanupRoutine()

	log.Printf("🦍 A.P.E. server starting on %s:%d", s.config.Server.Host, s.config.Server.Port)
	log.Printf("🔐 Database: %s:%d/%s", s.config.Database.Host, s.config.Database.Port, s.config.Database.Name)
	log.Printf("🛡️  Security: Encryption enabled, Token TTL: %v", s.config.Security.TokenTTL)

	// Start server in a goroutine
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Server shutting down...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
		return err
	}

	// Close database connection
	if err := s.store.Close(); err != nil {
		log.Printf("Failed to close database connection: %v", err)
	}

	log.Println("✅ Server gracefully stopped")
	return nil
}

func (s *Server) Stop() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// cleanupRoutine runs periodically to clean up expired tokens
func (s *Server) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := s.store.CleanupExpiredTokens(ctx); err != nil {
				log.Printf("Failed to cleanup expired tokens: %v", err)
			}
			cancel()
		}
	}
}
