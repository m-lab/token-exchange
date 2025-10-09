// autojoin.go - datastore interface for autojoin.

package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"cloud.google.com/go/datastore"
)

// Constants specific to the autojoin token-exchange.
const (
	AutojoinOrgKind    = "Organization"
	AutojoinAPIKeyKind = "APIKey"
)

// AutojoinOrganization represents a Datastore entity for storing organization metadata.
type AutojoinOrganization struct {
	Name                  string    `datastore:"name"`
	Email                 string    `datastore:"email"`
	CreatedAt             time.Time `datastore:"created_at"`
	ProbabilityMultiplier *float64  `datastore:"probability_multiplier"`
}

// TODO(bassosimone,robertodauria): discuss whether we want to upgrade
// this implementation to using bcrypt in the future.

// AutojoinAPIKey represents a Datastore entity for storing API key metadata.
type AutojoinAPIKey struct {
	CreatedAt time.Time `datastore:"created_at"`
	Key       string    `datastore:"key"`
}

// AutojoinManager maintains state for managing organizations and API keys
// in Datastore in the context of the autojoin API.
type AutojoinManager struct {
	client    DatastoreClient
	project   string
	namespace string
}

// NewAutojoinManager creates a new [*AutojoinManager] instance.
func NewAutojoinManager(client DatastoreClient, project, ns string) *AutojoinManager {
	return &AutojoinManager{
		client:    client,
		project:   project,
		namespace: ns,
	}
}

// CreateOrganization creates a new organization entity in Datastore.
func (d *AutojoinManager) CreateOrganization(ctx context.Context, name, email string) error {
	key := datastore.NameKey(AutojoinOrgKind, name, nil)
	key.Namespace = d.namespace
	prob := 1.0
	org := &AutojoinOrganization{
		Name:                  name,
		Email:                 email,
		CreatedAt:             time.Now().UTC(),
		ProbabilityMultiplier: &prob,
	}

	_, err := d.client.Put(ctx, key, org)
	return err
}

// GetOrganization retrieves an organization by its name.
func (d *AutojoinManager) GetOrganization(ctx context.Context, orgName string) (*AutojoinOrganization, error) {
	key := datastore.NameKey(AutojoinOrgKind, orgName, nil)
	key.Namespace = d.namespace

	var org AutojoinOrganization
	err := d.client.Get(ctx, key, &org)
	if err != nil {
		return nil, err
	}

	return &org, nil
}

// CreateAPIKeyWithValue creates a new API key as a child entity of the organization.
func (d *AutojoinManager) CreateAPIKeyWithValue(ctx context.Context, org, value string) (string, error) {
	parentKey := datastore.NameKey(AutojoinOrgKind, org, nil)
	parentKey.Namespace = d.namespace

	// Use the generated string as the key name
	key := datastore.NameKey(AutojoinAPIKeyKind, value, parentKey)
	key.Namespace = d.namespace

	apiKey := &AutojoinAPIKey{
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
func (d *AutojoinManager) GetAPIKeys(ctx context.Context, org string) ([]string, error) {
	parentKey := datastore.NameKey(AutojoinOrgKind, org, nil)
	parentKey.Namespace = d.namespace

	q := datastore.NewQuery(AutojoinAPIKeyKind).
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
func (d *AutojoinManager) ValidateKey(ctx context.Context, key string) (string, error) {
	// TODO(bassosimone,robertodauria): consider using `.Limit(2)` to catch the case where multiple
	// keys exist or using the approach used by the [*ClientIntegrationManager].
	q := datastore.NewQuery(AutojoinAPIKeyKind).
		Namespace(d.namespace).
		FilterField("key", "=", key).Limit(1)

	var keys []*datastore.Key
	var entities []AutojoinAPIKey
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
