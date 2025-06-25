package main

import (
	"context"
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
	"github.com/m-lab/go/httpx"
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
	port      = flag.Int("port", 8080, "Port to listen on")
	keyPath   = flag.String("private-key-path", jwkPrivKeyPath, "Path to private key")
	namespace = flag.String("namespace", defaultNamespace, "Datastore namespace")
	projectID = flag.String("project-id", "mlab-sandbox", "Google Cloud project ID")
)

func main() {
	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not parse env args")

	slog.Info("Starting token exchange server...")

	jwtSigner := rtx.ValueOrDie(auth.NewJWTSigner(*keyPath))
	slog.Info("JWT signer initialized successfully")

	// Initialize Datastore client
	dsClient, err := datastore.NewClient(context.Background(), *projectID)
	rtx.Must(err, "Failed to initialize Datastore client")
	defer dsClient.Close()

	dsManager := store.NewDatastoreManager(dsClient, *projectID, *namespace)

	mux := http.NewServeMux()

	// Register handlers
	exchangeHandler := handler.NewExchangeHandler(jwtSigner, dsManager)
	jwksHandler := handler.NewJWKSHandler(jwtSigner)

	mux.HandleFunc("POST /v0/token/autojoin", exchangeHandler.Exchange)
	mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler.ServeJWKS)

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: mux,
	}

	rtx.Must(httpx.ListenAndServeAsync(server), "Failed to start server")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	slog.Warn("Received shutdown signal, gracefully shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Shutdown() error", "err", err)
	}
}
