package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Security SecurityConfig `mapstructure:"security"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Audit    AuditConfig    `mapstructure:"audit"`
}

type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

type DatabaseConfig struct {
	Host        string `mapstructure:"host"`
	Port        int    `mapstructure:"port"`
	Name        string `mapstructure:"name"`
	User        string `mapstructure:"user"`
	Password    string `mapstructure:"password"`
	SSLMode     string `mapstructure:"sslmode"`
	MaxOpenConn int    `mapstructure:"max_open_conns"`
	MaxIdleConn int    `mapstructure:"max_idle_conns"`
}

type SecurityConfig struct {
	JWTSecret     string        `mapstructure:"jwt_secret"`
	EncryptionKey string        `mapstructure:"encryption_key"`
	TokenTTL      time.Duration `mapstructure:"token_ttl"`
	SecretTTL     time.Duration `mapstructure:"secret_ttl"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	File   string `mapstructure:"file"`
}

type AuditConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	File    string `mapstructure:"file"`
}

func Load(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	// Set defaults
	viper.SetDefault("server.host", "localhost")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
