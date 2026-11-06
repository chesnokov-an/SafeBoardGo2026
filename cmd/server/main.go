// Command server runs the threat exchange HTTP service.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/chesnokov-an/SafeBoardGo2026/internal/api"
	"github.com/chesnokov-an/SafeBoardGo2026/internal/config"
	"github.com/chesnokov-an/SafeBoardGo2026/internal/storage"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "cmd/server/config.yaml", "server configuration file")
	flag.Parse()

	cfg := config.MustLoad(configPath)
	log := MustMakeLogger(cfg.LogLevel)

	if err := run(cfg, log); err != nil {
		log.Error("server failed", "error", err)
		os.Exit(1)
	}
}

// run starts the HTTP server and shuts it down gracefully on SIGINT or SIGTERM.
func run(cfg config.Config, log *slog.Logger) error {
	log.Info("starting server")
	log.Debug("debug messages are enabled")

	store := storage.NewMemory()
	handler := api.New(store, cfg.HTTPConfig.BodyLimit, log)

	server := http.Server{
		Addr:              cfg.HTTPConfig.Address,
		ReadHeaderTimeout: cfg.HTTPConfig.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPConfig.ReadTimeout,
		WriteTimeout:      cfg.HTTPConfig.WriteTimeout,
		IdleTimeout:       cfg.HTTPConfig.IdleTimeout,
		Handler:           handler.Routes(),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server failed: %w", err)
		}
	case <-ctx.Done():
		stop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTPConfig.ShutdownTimeout)
		defer cancel()
		log.Debug("shutting down server")
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		//nolint:errcheck
		<-errCh
	}
	return nil
}

// MustMakeLogger returns a text logger for the given level and panics on an
// unknown level.
func MustMakeLogger(logLevel string) *slog.Logger {
	var level slog.Level
	switch logLevel {
	case "DEBUG":
		level = slog.LevelDebug
	case "INFO":
		level = slog.LevelInfo
	case "ERROR":
		level = slog.LevelError
	default:
		panic("unknown log level: " + logLevel)
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level, AddSource: true})
	return slog.New(handler)
}
