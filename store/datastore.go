package store

// TODO(bassosimone): Why is this package public? Who is importing it? Locate
// does not seem to import this package. Maybe someone else?

// TODO(bassosimone): Most of this file should be refactored to `autojoin.go` and
// only truly shared structures should stay in `datastore.go`.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"cloud.google.com/go/datastore"
)

// TODO(bassosimone): while we cannot rename the keys we should
// prefix these variables with `Autojoin`.
const OrgKind = "Organization"
const APIKeyKind = "APIKey"

var (
	// ErrInvalidKey is returned when the API key is not found in Datastore
	ErrInvalidKey = errors.New("invalid API key")
)

// DatastoreClient is an interface for interacting with Datastore.
type DatastoreClient interface {
	Put(ctx context.Context, key *datastore.Key, src any) (*datastore.Key, error)
	Get(ctx context.Context, key *datastore.Key, dst any) error
	GetAll(ctx context.Context, q *datastore.Query, dst any) ([]*datastore.Key, error)
}

// TODO(bassosimone): the types below this point should be refactored
// to have the `Autojoin` prefix for clarity.

// Organization represents a Datastore entity for storing organization metadata.
type Organization struct {
	Name                  string    `datastore:"name"`
	Email                 string    `datastore:"email"`
	CreatedAt             time.Time `datastore:"created_at"`
	ProbabilityMultiplier *float64  `datastore:"probability_multiplier"`
}

// TODO(bassosimone): I wonder whether we should upgrade this implementation
// to use use bcrypt for autojoin or whether we don't care.

// APIKey represents a Datastore entity for storing API key metadata.
type APIKey struct {
	CreatedAt time.Time `datastore:"created_at"`
	Key       string    `datastore:"key"`
}

// DatastoreOrgManager maintains state for managing organizations and API keys in Datastore.
type DatastoreOrgManager struct {
	client    DatastoreClient
	project   string
	namespace string
}

// NewDatastoreManager creates a new DatastoreOrgManager instance.
func NewDatastoreManager(client DatastoreClient, project, ns string) *DatastoreOrgManager {
	return &DatastoreOrgManager{
		client:    client,
		project:   project,
		namespace: ns,
	}
}

// CreateOrganization creates a new organization entity in Datastore.
func (d *DatastoreOrgManager) CreateOrganization(ctx context.Context, name, email string) error {
	key := datastore.NameKey(OrgKind, name, nil)
	key.Namespace = d.namespace
	prob := 1.0
	org := &Organization{
		Name:                  name,
		Email:                 email,
		CreatedAt:             time.Now().UTC(),
		ProbabilityMultiplier: &prob,
	}

	_, err := d.client.Put(ctx, key, org)
	return err
}

// GetOrganization retrieves an organization by its name.
func (d *DatastoreOrgManager) GetOrganization(ctx context.Context, orgName string) (*Organization, error) {
	key := datastore.NameKey(OrgKind, orgName, nil)
	key.Namespace = d.namespace

	var org Organization
	err := d.client.Get(ctx, key, &org)
	if err != nil {
		return nil, err
	}

	return &org, nil
}

// CreateAPIKeyWithValue creates a new API key as a child entity of the organization.
func (d *DatastoreOrgManager) CreateAPIKeyWithValue(ctx context.Context, org, value string) (string, error) {
	parentKey := datastore.NameKey(OrgKind, org, nil)
	parentKey.Namespace = d.namespace

	// Use the generated string as the key name
	key := datastore.NameKey(APIKeyKind, value, parentKey)
	key.Namespace = d.namespace

	apiKey := &APIKey{
		CreatedAt: time.Now().UTC(),
		Key:       value,
	}

	resKey, err := d.client.Put(ctx, key, apiKey)
	if err != nil {
		return "", err
	}

	return resKey.Name, nil
}

// GetAPIKeys retrieves all API keys for an organization
func (d *DatastoreOrgManager) GetAPIKeys(ctx context.Context, org string) ([]string, error) {
	parentKey := datastore.NameKey(OrgKind, org, nil)
	parentKey.Namespace = d.namespace

	q := datastore.NewQuery(APIKeyKind).
		Namespace(d.namespace).
		Ancestor(parentKey).
		KeysOnly()

	keys, err := d.client.GetAll(ctx, q, nil)
	if err != nil {
		return nil, err
	}

	apiKeys := make([]string, len(keys))
	for i, key := range keys {
		apiKeys[i] = key.Name
	}

	return apiKeys, nil
}

// ValidateKey checks if the API key exists and returns the associated organization name.
func (d *DatastoreOrgManager) ValidateKey(ctx context.Context, key string) (string, error) {
	// TODO(bassosimone): Discuss design regarding API key structure and JWT size constraints.
	//
	// Three options for API key storage:
	//
	// 1. Current design: Parent-child NameKey(APIKeyKind, value, parentKey)
	//
	// - Pro: Cascade deletes, natural organization hierarchy, per-org key namespacing
	//
	// - Con: ValidateKey must query (~slow) since parent is unknown
	//
	// 2. Flat design (see store/integration.go): NameKey(kind, keyID, nil) + store parent ID in entity
	//
	// - Pro: O(1) Get() for validation (hot path optimization)
	//
	// - Con: Deletion requires query, requires globally unique keys (vs per-org uniqueness)
	//
	// 3. Scoped keys: Encode parent in API key format, e.g., "{orgName}.{keyValue}"
	//
	// - Pro: O(1) for both validation and deletion (best of both worlds)
	//
	// - Con: Exposes internal entity relationships, longer API key format
	//
	// Related design question: JWT size and query parameter limits.
	//
	// JWTs are passed as query parameters to Locate service. URL length limits (~2KB safe) constrain
	// what claims we include. JWT size is determined by:
	//
	// - Claims: int_id vs org_id (similar size), jti (unique token ID), aud, iat, exp
	//
	// - Signature: Algorithm choice (ES256 smaller than RS256)
	//
	// Note: API key length doesn't affect JWT size (keys aren't in JWT), but does affect token
	// exchange request size. Typical JWTs are 200-600 bytes base64 encoded, unlikely to hit URL
	// limits, but worth measuring actual sizes.
	//
	// This pull request uses option (2) for integration and autojoin uses (1).
	//
	// Also, autojoin should probably use `.Limit(2)` to catch duplicate keys across orgs,
	// since query by field (not datastore key) could theoretically return multiple results.
	//
	// Should we:
	//
	// a) Unify on one pattern?
	//
	// b) Keep different patterns based on usage (autojoin vs integration validation frequency)?
	//
	// c) Consider option (3) for better performance with acceptable trade-offs?

	q := datastore.NewQuery(APIKeyKind).
		Namespace(d.namespace).
		FilterField("key", "=", key).Limit(1)

	var keys []*datastore.Key
	var entities []APIKey
	keys, err := d.client.GetAll(ctx, q, &entities)
	if err != nil {
		return "", err
	}
	if len(keys) == 0 {
		return "", ErrInvalidKey
	}

	// Get the parent (organization) key from the first result
	orgKey := keys[0].Parent
	if orgKey == nil {
		return "", errors.New("API key has no parent organization")
	}

	return orgKey.Name, nil
}

// GenerateAPIKey generates a random string to be used as API key.
func GenerateAPIKey() (string, error) {
	b := make([]byte, 32) // 256 bits of randomness
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
