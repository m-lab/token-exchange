// clientintegration.go - datastore interface for client-integration.

package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
)

// Enumerate the client-integration-related kinds we use in datastore.
//
// Multiple API keys exist for a single integration.
const (
	clientIntegrationMetaKind   = "IntegrationMeta"
	clientIntegrationAPIKeyKind = "IntegrationAPIKey"
)

// Exported constants for API key format prefixes.
const (
	ClientIntegrationAPIKeyPrefix = "mlabk."
	ClientIntegrationIDPrefix     = "cii_"
	ClientIntegrationKeyIDPrefix  = "ki_"
)

// Enumerate the possible statuses of an API key.
const (
	clientIntegrationAPIKeyStatusActive = "active"
)

// Function variables for testing - allows mocking random generation.
var (
	generateKeyIDFunc  = GenerateKeyID
	generateAPIKeyFunc = GenerateAPIKey
	randRead           = rand.Read
)

/*-
Design: Client Integration API Key Structure

API keys use a hierarchical format that encodes both the integration ID and key ID:

  mlabk.cii_<integrationID>.ki_<keyID>.<keySecret>

This format enables O(1) datastore lookups by constructing a parent-child key hierarchy:

- Parent: NameKey(IntegrationMeta, integrationID)

- Child:  NameKey(IntegrationAPIKey, keyID, parent)

The `keySecret` is compared to the corresponding SHA256 stored in the datastore.

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

// clientIntegrationAPIKey represents a datastore entity for storing integration API key metadata.
type clientIntegrationAPIKey struct {
	KeyHash     string    `datastore:"key_hash"`    // SHA-256 hash of the key_secret (hex-encoded)
	CreatedAt   time.Time `datastore:"created_at"`  // Creation timestamp
	Description string    `datastore:"description"` // Human-readable description
	Status      string    `datastore:"status"`      // active, revoked, etc.
	Tier        int       `datastore:"tier"`        // Service tier (0 = default)
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
	// Defense in depth: enforce limits to prevent DoS via large strings.
	// Group all consts at the top for visibility and consistency.
	const (
		apiKeyPrefix        = "mlabk."
		integrationIDPrefix = "cii_"
		keyIDPrefix         = "ki_"
		maxIntegrationIDLen = 64  // Reasonable max for human-readable IDs
		maxKeyIDLen         = 64  // Reasonable max for human-readable IDs
		maxKeySecretLen     = 128 // base64-encoded random bytes (96 bytes = 768 bits entropy)
	)

	// Calculate maximum API key length based on format: "mlabk.cii_<integrationID>.ki_<keyID>.<keySecret>"
	// len("mlabk.") + len("cii_") + maxIntegrationIDLen + len(".") + len("ki_") + maxKeyIDLen + len(".") + maxKeySecretLen
	// = 6 + 4 + 64 + 1 + 3 + 64 + 1 + 128 = 271 bytes (use 300 for headroom)
	const maxAPIKeyLen = 300
	if len(apiKey) > maxAPIKeyLen {
		return "", "", "", fmt.Errorf("%w: API key too long (max %d bytes)", ErrInvalidKey, maxAPIKeyLen)
	}

	// "mlabk.cii_<integrationID>.ki_<keyID>.<keySecret>" => "cii_<integrationID>.ki_<keyID>.<keySecret>".
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
	if !strings.HasPrefix(entries[0], integrationIDPrefix) {
		return "", "", "", fmt.Errorf("%w: missing integrationIDPrefix", ErrInvalidKey)
	}
	integrationID = strings.TrimPrefix(entries[0], integrationIDPrefix)
	if integrationID == "" {
		return "", "", "", fmt.Errorf("%w: integrationID cannot be empty", ErrInvalidKey)
	}
	if len(integrationID) > maxIntegrationIDLen {
		return "", "", "", fmt.Errorf("%w: integrationID too long (max %d bytes)", ErrInvalidKey, maxIntegrationIDLen)
	}

	// "ki_<keyID>"
	if !strings.HasPrefix(entries[1], keyIDPrefix) {
		return "", "", "", fmt.Errorf("%w: missing keyIDPrefix", ErrInvalidKey)
	}
	keyID = entries[1]
	if len(keyID) <= len(keyIDPrefix) {
		return "", "", "", fmt.Errorf("%w: keyID cannot be empty", ErrInvalidKey)
	}
	if len(keyID) > maxKeyIDLen {
		return "", "", "", fmt.Errorf("%w: keyID too long (max %d bytes)", ErrInvalidKey, maxKeyIDLen)
	}

	// "<keySecret>"
	keySecret = entries[2]
	if keySecret == "" {
		return "", "", "", fmt.Errorf("%w: keySecret cannot be empty", ErrInvalidKey)
	}
	if len(keySecret) > maxKeySecretLen {
		return "", "", "", fmt.Errorf("%w: keySecret too long (max %d bytes)", ErrInvalidKey, maxKeySecretLen)
	}
	return
}

// ValidateKey validates an integration API key using SHA-256 hash comparison.
//
// This method is thread safe.
//
// The return value consists of client-integration ID, key ID, tier, and an error.
func (m *ClientIntegrationManager) ValidateKey(ctx context.Context, apiKey string) (string, string, int, error) {
	// Parse the API key to extract the integrationID, the keyID and the keySecret
	integrationID, keyID, keySecret, err := parseAPIKey(apiKey)
	if err != nil {
		return "", "", 0, err
	}

	// Perform O(1) direct lookup using NameKey and nested key
	parentKey := datastore.NameKey(clientIntegrationMetaKind, integrationID, nil)
	parentKey.Namespace = m.namespace
	key := datastore.NameKey(clientIntegrationAPIKeyKind, keyID, parentKey)
	key.Namespace = m.namespace
	var entity clientIntegrationAPIKey
	if err := m.client.Get(ctx, key, &entity); err != nil {
		return "", "", 0, fmt.Errorf("%w: cannot Get from datastore: %w", ErrInvalidKey, err)
	}

	// Reject keys whose status is not active
	//
	// Assumption: setting an organization as inactive implies setting all its keys
	// as inactive, therefore we don't need further checks here
	if entity.Status != clientIntegrationAPIKeyStatusActive {
		return "", "", 0, fmt.Errorf("%w: the key is not active", ErrInvalidKey)
	}

	// Compute SHA-256 hash of the provided key secret
	hash := sha256.Sum256([]byte(keySecret))
	computedHash := hex.EncodeToString(hash[:])

	// Compare with stored hash using constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(computedHash), []byte(entity.KeyHash)) != 1 {
		return "", "", 0, fmt.Errorf("%w: secret does not match stored hash", ErrInvalidKey)
	}

	// My job here is done! ⛵🌕
	return integrationID, keyID, entity.Tier, nil
}

// GenerateKeyID generates a random key ID in the format "ki_" + 16 hex characters.
func GenerateKeyID() (string, error) {
	b := make([]byte, 8) // 8 bytes = 16 hex characters
	_, err := randRead(b)
	if err != nil {
		return "", err
	}
	return ClientIntegrationKeyIDPrefix + hex.EncodeToString(b), nil
}

// FormatAPIKey formats an API key from its components.
func FormatAPIKey(integrationID, keyID, keySecret string) string {
	return ClientIntegrationAPIKeyPrefix +
		ClientIntegrationIDPrefix + integrationID + "." +
		keyID + "." + keySecret
}

// CreateAPIKeyResult holds the result of creating an API key.
type CreateAPIKeyResult struct {
	IntegrationID string
	KeyID         string
	APIKey        string
}

// clientIntegrationMeta represents a datastore entity for storing integration metadata.
type clientIntegrationMeta struct {
	CreatedAt   time.Time `datastore:"created_at"`
	Description string    `datastore:"description"`
}

// CreateIntegration creates a new integration entity in Datastore.
func (m *ClientIntegrationManager) CreateIntegration(ctx context.Context, integrationID, description string) error {
	key := datastore.NameKey(clientIntegrationMetaKind, integrationID, nil)
	key.Namespace = m.namespace
	meta := &clientIntegrationMeta{
		CreatedAt:   time.Now().UTC(),
		Description: description,
	}
	_, err := m.client.Put(ctx, key, meta)
	return err
}

// CreateAPIKey creates a new API key for an integration in Datastore.
// If keyID is empty, a random key ID will be generated.
// The tier parameter specifies the service tier (0 = default).
// Returns the integration ID, key ID, and the full API key string.
func (m *ClientIntegrationManager) CreateAPIKey(ctx context.Context, integrationID, keyID, description string, tier int) (*CreateAPIKeyResult, error) {
	// Generate key ID if not provided
	if keyID == "" {
		var err error
		keyID, err = generateKeyIDFunc()
		if err != nil {
			return nil, fmt.Errorf("failed to generate key ID: %w", err)
		}
	}

	// Generate the key secret
	keySecret, err := generateAPIKeyFunc()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key secret: %w", err)
	}

	// Compute SHA-256 hash of the key secret
	hash := sha256.Sum256([]byte(keySecret))
	keyHash := hex.EncodeToString(hash[:])

	// Create parent key for the integration
	parentKey := datastore.NameKey(clientIntegrationMetaKind, integrationID, nil)
	parentKey.Namespace = m.namespace

	// Create the API key entity key
	apiKeyKey := datastore.NameKey(clientIntegrationAPIKeyKind, keyID, parentKey)
	apiKeyKey.Namespace = m.namespace

	// Create the API key entity
	entity := &clientIntegrationAPIKey{
		KeyHash:     keyHash,
		CreatedAt:   time.Now().UTC(),
		Description: description,
		Status:      clientIntegrationAPIKeyStatusActive,
		Tier:        tier,
	}

	// Store in Datastore
	_, err = m.client.Put(ctx, apiKeyKey, entity)
	if err != nil {
		return nil, fmt.Errorf("failed to store API key: %w", err)
	}

	// Format the full API key
	apiKey := FormatAPIKey(integrationID, keyID, keySecret)

	return &CreateAPIKeyResult{
		IntegrationID: integrationID,
		KeyID:         keyID,
		APIKey:        apiKey,
	}, nil
}
