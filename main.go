package main

import (
	"flag"
	"log"

	"github.com/the-monkeys/ape/internal/config"
	"github.com/the-monkeys/ape/internal/server"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create and start server
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
