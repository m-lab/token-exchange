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
	jwkPrivKeyPath    = "/secrets/jwk-priv.json"
	defaultPlatformNS = "platform-credentials"
	defaultProjectID  = "mlab-sandbox"
)

// TODO(bassosimone): figure out the intended deployment model. The command line flags allows
// to specify a single namespace (`platform-credentials` by default) and a single project ID
// (`mlab-sandbox`). We specified these flags when `main.go` was meant to only support the
// autojoin use case however now we have two use cases. I suspect a single project ID is 100%
// fine, but I am missing information about what we're using namespaces for.
var (
	port      = flag.Int("port", 8080, "Port to listen on")
	keyPath   = flag.String("private-key-path", jwkPrivKeyPath, "Path to private key")
	namespace = flag.String("platform-ns", defaultPlatformNS,
		"Datastore namespace for platform credentials")
	projectID = flag.String("project-id", defaultProjectID, "Google Cloud project ID")
)

func main() {
	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not parse env args")

	slog.Info("Starting token exchange server...")

	jwtSigner := rtx.ValueOrDie(auth.NewJWTSigner(*keyPath))
	slog.Info("JWT signer initialized successfully")

	// Initialize Datastore client
	// TODO(bassosimone): we can use rtx.ValueOrDie here
	dsClient, err := datastore.NewClient(context.Background(), *projectID)
	rtx.Must(err, "Failed to initialize Datastore client")
	defer dsClient.Close()

	// Datastore managers for autojoin and client integration registration
	autojoinManager := store.NewDatastoreManager(dsClient, *projectID, *namespace)
	integrationManager := store.NewIntegrationManager(dsClient, *projectID, *namespace)

	mux := http.NewServeMux()

	// Register handlers
	exchangeHandler := handler.NewExchangeHandler(jwtSigner, autojoinManager)
	jwksHandler := handler.NewJWKSHandler(jwtSigner)
	integrationHandler := handler.NewIntegrationHandler(jwtSigner, integrationManager)

	mux.HandleFunc("POST /v0/token/autojoin", exchangeHandler.Exchange)
	mux.HandleFunc("POST /v0/token/integration", integrationHandler.Exchange)
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
	// TODO(bassosimone): consider using signal.NotifyContext
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
