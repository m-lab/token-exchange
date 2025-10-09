package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"golang.org/x/crypto/bcrypt"
)

// TODO(bassosimone): We will need to ensure that the kinds I am
// introducing here do not conflict with anything else we might be
// using within the same datastore namespace. (Obviously, if we
// choose to use a distinct namespace, the problem is void.)

// Enumerate the integration-related kinds we use in datastore.
//
// Multiple API keys exist for a single integration.
const (
	IntegrationMetaKind   = "IntegrationMeta"
	IntegrationAPIKeyKind = "IntegrationAPIKey"
)

// Enumerate the possible statuses of an integration.
const (
	IntegrationStatusActive = "active"
)

// Enumerate the possible statuses of an API key.
const (
	IntegrationAPIKeyStatus = "active"
)

// IntegrationMeta represents a datastore entity for storing integration metadata.
type IntegrationMeta struct {
	IntID        string    `datastore:"int_id"`       // Integration ID
	Name         string    `datastore:"name"`         // Integration name
	Email        string    `datastore:"email"`        // Contact email
	Organization string    `datastore:"organization"` // Organization name
	CreatedAt    time.Time `datastore:"created_at"`   // Creation timestamp
	Status       string    `datastore:"status"`       // active, suspended, etc.
}

// IntegrationAPIKey represents a datastore entity for storing integration API key metadata.
type IntegrationAPIKey struct {
	IntID       string    `datastore:"int_id"`      // Foreign key to Integration
	KeyID       string    `datastore:"key_id"`      // The ki_<key_id> portion of the API key
	KeyHash     string    `datastore:"key_hash"`    // bcrypt hash of the key_secret
	CreatedAt   time.Time `datastore:"created_at"`  // Creation timestamp
	Description string    `datastore:"description"` // Human-readable description
	Status      string    `datastore:"status"`      // active, revoked, etc.
}

// IntegrationManager maintains state for managing integrations and API keys in datastore.
type IntegrationManager struct {
	client    DatastoreClient
	project   string
	namespace string
}

// NewIntegrationManager creates a new IntegrationManager instance.
func NewIntegrationManager(client DatastoreClient, project, ns string) *IntegrationManager {
	return &IntegrationManager{
		client:    client,
		project:   project,
		namespace: ns,
	}
}

// ValidateKey validates an integration API key using bcrypt comparison.
//
// This method is thread safe.
//
// The API key format is: `mlabk.ki_<keyId>.<keySecret>`.
func (m *IntegrationManager) ValidateKey(ctx context.Context, apiKey string) (string, error) {
	// Parse the API key to extract the keyId and the keySecret
	const apiKeyPrefix = "mlabk.ki_"
	if !strings.HasPrefix(apiKey, apiKeyPrefix) {
		return "", fmt.Errorf("%w: missing apiKeyPrefix", ErrInvalidKey)
	}
	apiKey = strings.TrimPrefix(apiKey, apiKeyPrefix)
	apiKeyID, apiKeySecret, found := strings.Cut(apiKey, ".")
	if !found {
		return "", fmt.Errorf("%w: cannot split ID and secret", ErrInvalidKey)
	}

	// Perform O(1) direct lookup using NameKey. This assumes CreateAPIKey uses
	// NameKey(IntegrationAPIKeyKind, apiKeyID, nil) which enforces uniqueness.
	key := datastore.NameKey(IntegrationAPIKeyKind, apiKeyID, nil)
	key.Namespace = m.namespace

	var entity IntegrationAPIKey
	if err := m.client.Get(ctx, key, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return "", ErrInvalidKey
		}
		return "", fmt.Errorf("cannot Get from datastore: %w", err)
	}

	// Reject keys whose status is not active
	if entity.Status != IntegrationStatusActive {
		return "", fmt.Errorf("%w: the key is not active", ErrInvalidKey)
	}

	// Map the key secret to the stored key secret hash
	if err := bcrypt.CompareHashAndPassword([]byte(entity.KeyHash), []byte(apiKeySecret)); err != nil {
		return "", fmt.Errorf("compring secret and hash failed: %w", err)
	}

	// Obtain the integration ID
	intID := entity.IntID

	// TODO(bassosimone): should we check whether the organization is active or
	// should we implement organization state transition to also disable the keys
	// to avoid too many operations inside the "hot" HTTP handler?

	// Our job here is done! ⛵🌕
	return intID, nil
}

// TODO(bassosimone): Implement CRUD operations for integration management.
//
// IMPORTANT: CreateAPIKey MUST use NameKey(IntegrationAPIKeyKind, keyID, nil) for O(1) lookups.
// ValidateKey assumes this pattern. Example:
//   key := datastore.NameKey(IntegrationAPIKeyKind, keyID, nil)
//   key.Namespace = m.namespace
//   _, err := m.client.Put(ctx, key, &IntegrationAPIKey{...})
//
// Note: All Create/Update/Delete operations should validate inputs and handle
// use datastore transactions where needed.
