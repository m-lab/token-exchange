package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/token-exchange/internal/auth"
	"github.com/m-lab/token-exchange/internal/handler"
	"github.com/m-lab/token-exchange/store"
)

const (
	jwkPrivKeyPath   = "/secrets/jwk-priv.json"
	defaultNamespace = "autojoin"
)

func main() {
	log.Printf("Starting token exchange service...")

	// On Cloud Run, the port is injected via the environment variable PORT.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Port set to: %s", port)

	// Initialize JWT signer
	keyPath := os.Getenv("PRIVATE_KEY_PATH")
	if keyPath == "" {
		keyPath = jwkPrivKeyPath
	}
	log.Printf("Using private key from: %s", keyPath)

	jwtSigner, err := auth.NewJWTSigner(keyPath)
	if err != nil {
		log.Fatalf("Failed to initialize JWT signer: %v", err)
	}
	log.Printf("JWT signer initialized successfully")

	// Initialize Datastore client
	projectID := os.Getenv("PROJECT_ID")
	if projectID == "" {
		log.Fatal("PROJECT_ID environment variable is required")
	}

	dsClient, err := datastore.NewClient(context.Background(), projectID)
	rtx.Must(err, "Failed to initialize Datastore client")
	defer dsClient.Close()

	dsManager := store.NewDatastoreManager(dsClient, projectID)

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
		log.Printf("Received shutdown signal, gracefully shutting down...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}()

	log.Printf("Server starting on port %s", port)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}
	log.Printf("Server stopped")
}
