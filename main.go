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
	"time"

	"cloud.google.com/go/datastore"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/token-exchange/internal/auth"
	"github.com/m-lab/token-exchange/internal/handler"
	"github.com/m-lab/token-exchange/store"
)

const (
	jwkPrivKeyPath   = "/secrets/jwk-priv.json"
	defaultNamespace = "autojoin"
)

var (
	flagPort      = flag.Int("port", 8080, "Port to listen on")
	flagKeyPath   = flag.String("private-key-path", jwkPrivKeyPath, "Path to private key")
	flagNamespace = flag.String("namespace", defaultNamespace, "Datastore namespace")
	flagProjectID = flag.String("project-id", "mlab-sandbox", "Google Cloud project ID")
)

func main() {
	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not parse env args")

	// On Cloud Run, the port is injected via the environment variable PORT.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	slog.Info("Starting token exchange server...")

	jwtSigner := rtx.ValueOrDie(auth.NewJWTSigner(*flagKeyPath))
	slog.Info("JWT signer initialized successfully")

	// Initialize Datastore client
	dsClient, err := datastore.NewClient(context.Background(), *flagProjectID)
	rtx.Must(err, "Failed to initialize Datastore client")
	defer dsClient.Close()

	dsManager := store.NewDatastoreManager(dsClient, *flagProjectID)

	mux := http.NewServeMux()

	// Register handlers
	exchangeHandler := handler.NewExchangeHandler(jwtSigner, dsManager)
	jwksHandler := handler.NewJWKSHandler(jwtSigner)

	mux.HandleFunc("POST /v0/token", exchangeHandler.Exchange)
	mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler.ServeJWKS)

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		slog.Warn("Received shutdown signal, gracefully shutting down...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			slog.Error("Shutdown() error", "err", err)
		}
	}()

	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		slog.Error("ListenAndServe() error", "err", err)
	}
	slog.Info("Server stopped")
}
