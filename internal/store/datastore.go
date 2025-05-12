package store

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/datastore"
)

const (
	OrgKind    = "Organization"
	APIKeyKind = "APIKey"
)

type DatastoreClientAPI interface {
	GetAll(ctx context.Context, q *datastore.Query, dst interface{}) ([]*datastore.Key, error)
}

type DatastoreClient struct {
	client    DatastoreClientAPI
	namespace string
}

type Organization struct {
	Name                  string    `datastore:"name"`
	Email                 string    `datastore:"email"`
	CreatedAt             time.Time `datastore:"created_at"`
	ProbabilityMultiplier *float64  `datastore:"probability_multiplier"`
}

type APIKey struct {
	CreatedAt time.Time `datastore:"created_at"`
	Key       string    `datastore:"key"`
}

// datastoreClientWrapper wraps *datastore.Client to implement DatastoreClientAPI.
type datastoreClientWrapper struct {
	*datastore.Client
}

func (w *datastoreClientWrapper) GetAll(ctx context.Context, q *datastore.Query, dst interface{}) ([]*datastore.Key, error) {
	return w.Client.GetAll(ctx, q, dst)
}

// NewDatastoreClient creates a new DatastoreClient instance.
func NewDatastoreClient(ctx context.Context, projectID, namespace string) (*DatastoreClient, error) {
	client, err := datastore.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to create datastore client: %w", err)
	}

	return &DatastoreClient{
		client:    &datastoreClientWrapper{client},
		namespace: namespace,
	}, nil
}

// NewDatastoreClientWithAPI allows injecting a custom DatastoreClientAPI (for testing).
func NewDatastoreClientWithAPI(api DatastoreClientAPI, namespace string) *DatastoreClient {
	return &DatastoreClient{
		client:    api,
		namespace: namespace,
	}
}

// VerifyAPIKey verifies the given API key and returns the organization ID.
func (d *DatastoreClient) VerifyAPIKey(ctx context.Context, apiKey string) (string, error) {
	q := datastore.NewQuery(APIKeyKind).
		Namespace(d.namespace).
		FilterField("key", "=", apiKey).Limit(1)

	var apiKeys []APIKey
	keys, err := d.client.GetAll(ctx, q, &apiKeys)
	if err != nil {
		return "", fmt.Errorf("failed to query API key: %w", err)
	}

	if len(keys) == 0 {
		return "", fmt.Errorf("invalid API key")
	}

	// Get the organization ID from the parent key
	orgID := keys[0].Parent.Name

	return orgID, nil
}

// Close closes the DatastoreClient instance.
// Only works if the underlying client is a real *datastore.Client.
func (d *DatastoreClient) Close() error {
	if c, ok := d.client.(*datastoreClientWrapper); ok {
		return c.Client.Close()
	}
	return nil
}
