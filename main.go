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
	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/token-exchange/internal/auth"
	"github.com/m-lab/token-exchange/internal/handler"
	"github.com/m-lab/token-exchange/metrics"
	"github.com/m-lab/token-exchange/store"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	jwkPrivKeyPath      = "/secrets/jwk-priv.json"
	autojoinNS          = "platform-credentials"
	defaultProjectID    = "mlab-sandbox"
	clientIntegrationNS = "client-integration"
)

// TODO(bassosimone): consider renaming -platform-ns to -autojoin-ns in a future PR
// to better reflect its purpose (autojoin credentials vs. client-integration credentials).
var (
	port              = flag.Int("port", 8080, "Port to listen on")
	keyPath           = flag.String("private-key-path", jwkPrivKeyPath, "Path to private key")
	platformNamespace = flag.String("platform-ns", autojoinNS,
		"Datastore namespace for platform credentials (used for autojoin)")
	clientIntegrationNamespace = flag.String("client-integration-ns", clientIntegrationNS,
		"Datastore namespace for client-integration credentials")
	projectID = flag.String("project-id", defaultProjectID, "Google Cloud project ID")
)

func main() {
	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not parse env args")

	prometheusx.MustServeMetrics()

	slog.Info("Starting token exchange server...")

	jwtSigner := rtx.ValueOrDie(auth.NewJWTSigner(*keyPath))
	slog.Info("JWT signer initialized successfully")

	// Initialize Datastore client
	// TODO(bassosimone): we can use [rtx.ValueOrDie] here
	dsClient, err := datastore.NewClient(context.Background(), *projectID)
	rtx.Must(err, "Failed to initialize Datastore client")
	defer dsClient.Close()

	// Datastore managers for autojoin and client integration registration
	autojoinManager := store.NewAutojoinManager(dsClient, *projectID, *platformNamespace)
	clientIntegrationManager := store.NewClientIntegrationManager(dsClient, *projectID, *clientIntegrationNamespace)

	mux := http.NewServeMux()

	// Register handlers
	exchangeHandler := handler.NewAutojoinHandler(jwtSigner, autojoinManager)
	jwksHandler := handler.NewJWKSHandler(jwtSigner)
	integrationHandler := handler.NewClientIntegrationHandler(jwtSigner, clientIntegrationManager)

	// Wrap handlers with promhttp instrumentation.
	autojoinHandler := promhttp.InstrumentHandlerDuration(
		metrics.AutojoinRequestDuration,
		promhttp.InstrumentHandlerCounter(
			metrics.AutojoinRequestsTotal,
			http.HandlerFunc(exchangeHandler.Exchange),
		),
	)
	integrationInstrumented := promhttp.InstrumentHandlerDuration(
		metrics.IntegrationRequestDuration,
		promhttp.InstrumentHandlerCounter(
			metrics.IntegrationRequestsTotal,
			http.HandlerFunc(integrationHandler.Exchange),
		),
	)

	mux.Handle("POST /v0/token/autojoin", autojoinHandler)
	mux.Handle("POST /v0/token/integration", integrationInstrumented)
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
	// TODO(bassosimone): consider using [signal.NotifyContext]
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
