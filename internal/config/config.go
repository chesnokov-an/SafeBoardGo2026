// Package config loads service settings from a YAML file and environment
// variables. Environment variables take precedence.
package config

import (
	"log"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

// HTTPConfig holds HTTP server timeouts and the request body limit.
type HTTPConfig struct {
	Address           string        `yaml:"address" env:"API_ADDRESS" env-default:"localhost:8080"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout" env:"API_READ_HEADER_TIMEOUT" env-default:"5s"`
	ReadTimeout       time.Duration `yaml:"read_timeout" env:"API_READ_TIMEOUT" env-default:"10s"`
	WriteTimeout      time.Duration `yaml:"write_timeout" env:"API_WRITE_TIMEOUT" env-default:"10s"`
	IdleTimeout       time.Duration `yaml:"idle_timeout" env:"API_IDLE_TIMEOUT" env-default:"60s"`
	ShutdownTimeout   time.Duration `yaml:"shutdown_timeout" env:"API_SHUTDOWN_TIMEOUT" env-default:"8s"`
	BodyLimit         int64         `yaml:"body_limit" env:"BODY_LIMIT" env-default:"1048576"`
}

// Config is the root service configuration.
type Config struct {
	HTTPConfig HTTPConfig `yaml:"api_server"`
	LogLevel   string     `yaml:"log_level" env:"LOG_LEVEL" env-default:"DEBUG"`
}

// MustLoad reads the configuration and terminates the process on error.
func MustLoad(configPath string) Config {
	var cfg Config
	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		log.Fatalf("cannot read config %q: %s", configPath, err)
	}
	return cfg
}
