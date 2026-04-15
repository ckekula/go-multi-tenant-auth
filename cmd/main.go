package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"go-multi-tenant-auth/internal/handlers"
	"go-multi-tenant-auth/internal/services"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg := services.Config{
		ZitadelDomain: requireEnv("ZITADEL_DOMAIN"),
		ClientID:      requireEnv("ZITADEL_CLIENT_ID"),
		Port:          getEnv("PORT", "8080"),
	}

	// Bootstrap JWKS fetcher (uses discovery endpoint internally)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authSvc, err := services.NewAuthService(ctx, cfg, logger)
	if err != nil {
		logger.Error("failed to initialise auth service", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	handlers.Register(mux, authSvc, logger)

	addr := ":" + cfg.Port
	logger.Info("server starting", "addr", addr)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("required environment variable not set", "key", key)
		os.Exit(1)
	}
	return v
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
