// create-integration creates a new client integration and API key in Datastore.
//
// Usage:
//
//	go run ./cmd/create-integration -project=mlab-sandbox -integration-id=my-integration
//	go run ./cmd/create-integration -project=mlab-sandbox -integration-id=my-integration -description="Production key"
//	go run ./cmd/create-integration -project=mlab-sandbox -integration-id=my-integration -key-id=ki_custom -description="Custom key ID"
package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"cloud.google.com/go/datastore"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/token-exchange/store"
)

var (
	project       = flag.String("project", "", "Google Cloud project ID (required)")
	namespace     = flag.String("namespace", "client-integration", "Datastore namespace")
	integrationID = flag.String("integration-id", "", "Integration ID (required)")
	keyID         = flag.String("key-id", "", "Key ID (auto-generated if not provided)")
	description   = flag.String("description", "", "Human-readable description for the API key")
)

func main() {
	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not parse env args")

	// Validate required flags
	if *project == "" {
		log.Fatal("Error: -project is required")
	}
	if *integrationID == "" {
		log.Fatal("Error: -integration-id is required")
	}

	ctx := context.Background()

	// Initialize Datastore client
	client, err := datastore.NewClient(ctx, *project)
	rtx.Must(err, "Failed to initialize Datastore client")
	defer client.Close()

	// Create manager
	manager := store.NewClientIntegrationManager(client, *project, *namespace)

	// Create integration
	log.Printf("Creating integration '%s' in project '%s', namespace '%s'...", *integrationID, *project, *namespace)
	err = manager.CreateIntegration(ctx, *integrationID)
	rtx.Must(err, "Failed to create integration")
	log.Printf("Integration created successfully")

	// Create API key
	log.Printf("Creating API key...")
	result, err := manager.CreateAPIKey(ctx, *integrationID, *keyID, *description)
	rtx.Must(err, "Failed to create API key")

	// Print result
	fmt.Println()
	fmt.Println("=== API Key Created ===")
	fmt.Printf("Integration ID: %s\n", result.IntegrationID)
	fmt.Printf("Key ID:         %s\n", result.KeyID)
	fmt.Printf("API Key:        %s\n", result.APIKey)
	fmt.Println()
	fmt.Println("IMPORTANT: Save the API key now. It cannot be retrieved later.")
}
