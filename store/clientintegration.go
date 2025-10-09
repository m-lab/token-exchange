// clientintegration.go - datastore interface for client-integration.

package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"golang.org/x/crypto/bcrypt"
)

// Enumerate the client-integration-related kinds we use in datastore.
//
// Multiple API keys exist for a single integration.
const (
	clientIntegrationMetaKind   = "IntegrationMeta"
	clientIntegrationAPIKeyKind = "IntegrationAPIKey"
)

// Enumerate the possible statuses of an API key.
const (
	clientIntegrationAPIKeyStatusActive = "active"
)

/*-
Design: Client Integration API Key Structure

API keys use a hierarchical format that encodes both the integration ID and key ID:

  mlabk.cii_<integrationID>.ki_<keyID>.<keySecret>

This format enables O(1) datastore lookups by constructing a parent-child key hierarchy:

- Parent: NameKey(IntegrationMeta, integrationID)

- Child:  NameKey(IntegrationAPIKey, keyID, parent)

Benefits:

- O(1) lookup in the hot path (ValidateKey)

- No need to store IDs redundantly in entity fields

- Natural cascade deletion via datastore ancestry

Trade-offs:

- Create/Update/Delete operations are slightly more complex

- Requires parsing the full API key format on every validation

This differs from the autojoin pattern (see autojoin.go) which uses
flat keys with query-based lookup.
*/

// clientIntegrationMeta represents a datastore entity for storing integration metadata.
type clientIntegrationMeta struct {
	Name         string    `datastore:"name"`         // Integration name
	Email        string    `datastore:"email"`        // Contact email
	Organization string    `datastore:"organization"` // Organization name
	CreatedAt    time.Time `datastore:"created_at"`   // Creation timestamp
	Status       string    `datastore:"status"`       // active, suspended, etc.
}

// clientIntegrationAPIKey represents a datastore entity for storing integration API key metadata.
type clientIntegrationAPIKey struct {
	KeyHash     string    `datastore:"key_hash"`    // bcrypt hash of the key_secret
	CreatedAt   time.Time `datastore:"created_at"`  // Creation timestamp
	Description string    `datastore:"description"` // Human-readable description
	Status      string    `datastore:"status"`      // active, revoked, etc.
}

// ClientIntegrationManager maintains state for managing client
// integrations and API keys in datastore.
type ClientIntegrationManager struct {
	client    DatastoreClient
	project   string
	namespace string
}

// NewClientIntegrationManager creates a new [*ClientIntegrationManager] instance.
func NewClientIntegrationManager(client DatastoreClient, project, ns string) *ClientIntegrationManager {
	return &ClientIntegrationManager{
		client:    client,
		project:   project,
		namespace: ns,
	}
}

// parseAPIKey parses the API key according to its format.
func parseAPIKey(apiKey string) (integrationID string, keyID string, keySecret string, err error) {
	// Defense in depth: reject excessively long API keys to prevent DoS via large strings.
	// Expected format: "mlabk.cii_<integrationID>.ki_<keyID>.<keySecret>"
	// Reasonable max: prefix(6) + cii_(4) + id(64) + dot(1) + ki_(3) + id(64) + dot(1) + secret(72) = ~215 bytes
	const maxAPIKeyLen = 256
	if len(apiKey) > maxAPIKeyLen {
		return "", "", "", fmt.Errorf("%w: API key too long (max %d bytes)", ErrInvalidKey, maxAPIKeyLen)
	}

	// "mlabk.cii_<integrationID>.ki_<keyID>.<keySecret>" => "cii_<integrationID>.ki_<keyID>.<keySecret>".
	const apiKeyPrefix = "mlabk."
	if !strings.HasPrefix(apiKey, apiKeyPrefix) {
		return "", "", "", fmt.Errorf("%w: missing apiKeyPrefix", ErrInvalidKey)
	}
	apiKey = strings.TrimPrefix(apiKey, apiKeyPrefix)

	// "cii_<integrationID>.ki_<keyID>.<keySecret>" => ("cii_<integrationID>", "ki_<keyID>", "<keySecret>").
	// Use SplitN to stop scanning after finding 3 dots (DoS prevention).
	entries := strings.SplitN(apiKey, ".", 4)
	if len(entries) != 3 {
		return "", "", "", fmt.Errorf("%w: expected 3 entries, got %d", ErrInvalidKey, len(entries))
	}

	// "cii_<integrationID>" => "<integrationID>"
	const integrationIDPrefix = "cii_"
	if !strings.HasPrefix(entries[0], integrationIDPrefix) {
		return "", "", "", fmt.Errorf("%w: missing integrationIDPrefix", ErrInvalidKey)
	}
	integrationID = strings.TrimPrefix(entries[0], integrationIDPrefix)
	if integrationID == "" {
		return "", "", "", fmt.Errorf("%w: integrationID cannot be empty", ErrInvalidKey)
	}

	// "ki_<keyID>" => "<keyID>"
	const keyIDPrefix = "ki_"
	if !strings.HasPrefix(entries[1], keyIDPrefix) {
		return "", "", "", fmt.Errorf("%w: missing keyIDPrefix", ErrInvalidKey)
	}
	keyID = strings.TrimPrefix(entries[1], keyIDPrefix)
	if keyID == "" {
		return "", "", "", fmt.Errorf("%w: keyID cannot be empty", ErrInvalidKey)
	}

	// "<keySecret>"
	keySecret = entries[2]
	if keySecret == "" {
		return "", "", "", fmt.Errorf("%w: keySecret cannot be empty", ErrInvalidKey)
	}

	// Defense in depth: enforce bcrypt's 72-byte password limit.
	// See golang.org/x/crypto/bcrypt documentation:
	// - GenerateFromPassword rejects passwords >72 bytes with ErrPasswordTooLong
	// - CompareHashAndPassword silently truncates to 72 bytes for compatibility
	// Reference: https://pkg.go.dev/golang.org/x/crypto/bcrypt
	// See also: https://github.com/golang/go/issues/36546
	const maxKeySecretLen = 72
	if len(keySecret) > maxKeySecretLen {
		return "", "", "", fmt.Errorf("%w: keySecret exceeds bcrypt limit (%d bytes)", ErrInvalidKey, maxKeySecretLen)
	}
	return
}

// ValidateKey validates an integration API key using bcrypt comparison.
//
// This method is thread safe.
//
// The return value consists of client-integration ID, key ID, and an error.
func (m *ClientIntegrationManager) ValidateKey(ctx context.Context, apiKey string) (string, string, error) {
	// Parse the API key to extract the integrationID, the keyID and the keySecret
	integrationID, keyID, keySecret, err := parseAPIKey(apiKey)
	if err != nil {
		return "", "", err
	}

	// Perform O(1) direct lookup using NameKey and nested key
	parentKey := datastore.NameKey(clientIntegrationMetaKind, integrationID, nil)
	parentKey.Namespace = m.namespace
	key := datastore.NameKey(clientIntegrationAPIKeyKind, keyID, parentKey)
	key.Namespace = m.namespace
	var entity clientIntegrationAPIKey
	if err := m.client.Get(ctx, key, &entity); err != nil {
		return "", "", fmt.Errorf("%w: cannot Get from datastore: %w", ErrInvalidKey, err)
	}

	// Reject keys whose status is not active
	//
	// Assumption: setting an organization as inactive implies setting all its keys
	// as inactive, therefore we don't need further checks here
	if entity.Status != clientIntegrationAPIKeyStatusActive {
		return "", "", fmt.Errorf("%w: the key is not active", ErrInvalidKey)
	}

	// Map the key secret to the stored key secret hash
	if err := bcrypt.CompareHashAndPassword([]byte(entity.KeyHash), []byte(keySecret)); err != nil {
		return "", "", fmt.Errorf("comparing secret and hash failed: %w", err)
	}

	// My job here is done! ⛵🌕
	//
	// https://knowyourmeme.com/memes/my-job-here-is-done-but-you-didnt-do-anything
	return integrationID, keyID, nil
}
