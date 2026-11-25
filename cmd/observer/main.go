package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/elematte/observer/internal/config"
	"github.com/elematte/observer/internal/crypto"
	"github.com/elematte/observer/internal/db"
	"github.com/elematte/observer/internal/retention"
	"github.com/elematte/observer/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	box, err := crypto.NewBox(cfg.MasterKey)
	if err != nil {
		log.Fatalf("master key error: %v", err)
	}

	store, err := db.Open(cfg.DBPath, box)
	if err != nil {
		log.Fatalf("database error: %v", err)
	}
	defer store.Close()

	retDefaults := db.RetentionSettings{
		RetentionDays:          cfg.RetentionDays,
		HeartbeatRetentionDays: cfg.HeartbeatRetentionDays,
	}
	retWorker := retention.NewWorker(store, retDefaults, cfg.RetentionInterval)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go retWorker.Run(ctx)

	srv := server.New(cfg, store, retWorker)
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("observer listening on %s (forward_auth=%v, retention=%dd/%dd)",
			cfg.ListenAddr, cfg.TrustForwardAuth, cfg.RetentionDays, cfg.HeartbeatRetentionDays)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down observer...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("http shutdown error: %v", err)
	}
}
