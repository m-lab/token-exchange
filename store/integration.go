package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"golang.org/x/crypto/bcrypt"
)

const (
	IntegratorKind        = "Integrator"
	IntegrationAPIKeyKind = "IntegrationAPIKey"
	APIKeyPrefix          = "mlabk"
)

var (
	// ErrInvalidIntegrationKey is returned when the integration API key is not found or invalid
	ErrInvalidIntegrationKey = errors.New("invalid integration API key")
	// ErrMalformedKey is returned when the API key format is incorrect
	ErrMalformedKey = errors.New("malformed API key")
	// ErrIntegratorNotFound is returned when the integrator is not found
	ErrIntegratorNotFound = errors.New("integrator not found")
	// ErrIntegratorSuspended is returned when the integrator is suspended
	ErrIntegratorSuspended = errors.New("integrator suspended")
	// ErrAPIKeyRevoked is returned when the API key is revoked
	ErrAPIKeyRevoked = errors.New("API key revoked")
)

// Integrator represents a Datastore entity for storing integrator metadata.
type Integrator struct {
	IntID        string    `datastore:"int_id"`
	Name         string    `datastore:"name"`
	Email        string    `datastore:"email"`
	Organization string    `datastore:"organization"`
	CreatedAt    time.Time `datastore:"created_at"`
	Status       string    `datastore:"status"` // "active" or "suspended"
}

// IntegrationAPIKey represents a Datastore entity for storing integration API key metadata.
type IntegrationAPIKey struct {
	IntID       string    `datastore:"int_id"`
	KeyID       string    `datastore:"key_id"`
	KeyHash     string    `datastore:"key_hash"`
	CreatedAt   time.Time `datastore:"created_at"`
	Description string    `datastore:"description"`
	Status      string    `datastore:"status"` // "active" or "revoked"
}

// IntegrationManager maintains state for managing integrators and their API keys in Datastore.
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

// CreateIntegrator creates a new integrator entity in Datastore.
func (m *IntegrationManager) CreateIntegrator(ctx context.Context, intID, name, email, organization string) error {
	key := datastore.NameKey(IntegratorKind, intID, nil)
	key.Namespace = m.namespace

	integrator := &Integrator{
		IntID:        intID,
		Name:         name,
		Email:        email,
		Organization: organization,
		CreatedAt:    time.Now().UTC(),
		Status:       "active",
	}

	_, err := m.client.Put(ctx, key, integrator)
	return err
}

// GetIntegrator retrieves an integrator by its int_id.
func (m *IntegrationManager) GetIntegrator(ctx context.Context, intID string) (*Integrator, error) {
	key := datastore.NameKey(IntegratorKind, intID, nil)
	key.Namespace = m.namespace

	var integrator Integrator
	err := m.client.Get(ctx, key, &integrator)
	if err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, ErrIntegratorNotFound
		}
		return nil, err
	}

	return &integrator, nil
}

// CreateAPIKey creates a new integration API key for an integrator.
func (m *IntegrationManager) CreateAPIKey(ctx context.Context, intID, description string) (string, error) {
	// Generate key_id and key_secret
	keyID, err := generateKeyID()
	if err != nil {
		return "", fmt.Errorf("failed to generate key ID: %w", err)
	}

	keySecret, err := generateKeySecret()
	if err != nil {
		return "", fmt.Errorf("failed to generate key secret: %w", err)
	}

	// Hash the secret
	keyHash, err := bcrypt.GenerateFromPassword([]byte(keySecret), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash key secret: %w", err)
	}

	// Store the API key
	key := datastore.NameKey(IntegrationAPIKeyKind, keyID, nil)
	key.Namespace = m.namespace

	apiKey := &IntegrationAPIKey{
		IntID:       intID,
		KeyID:       keyID,
		KeyHash:     string(keyHash),
		CreatedAt:   time.Now().UTC(),
		Description: description,
		Status:      "active",
	}

	_, err = m.client.Put(ctx, key, apiKey)
	if err != nil {
		return "", err
	}

	// Return the full API key in the format: prefix.key_id.key_secret
	fullKey := fmt.Sprintf("%s.%s.%s", APIKeyPrefix, keyID, keySecret)
	return fullKey, nil
}

// ValidateKey validates an integration API key and returns the integrator ID and key ID.
func (m *IntegrationManager) ValidateKey(ctx context.Context, apiKey string) (string, string, error) {
	// Parse the API key
	keyID, keySecret, err := parseAPIKey(apiKey)
	if err != nil {
		return "", "", err
	}

	// Look up the API key by key_id
	key := datastore.NameKey(IntegrationAPIKeyKind, keyID, nil)
	key.Namespace = m.namespace

	var storedKey IntegrationAPIKey
	err = m.client.Get(ctx, key, &storedKey)
	if err != nil {
		if err == datastore.ErrNoSuchEntity {
			return "", "", ErrInvalidIntegrationKey
		}
		return "", "", err
	}

	// Check if the API key is revoked
	if storedKey.Status != "active" {
		return "", "", ErrAPIKeyRevoked
	}

	// Verify the secret
	err = bcrypt.CompareHashAndPassword([]byte(storedKey.KeyHash), []byte(keySecret))
	if err != nil {
		return "", "", ErrInvalidIntegrationKey
	}

	// Check if the integrator is active
	integrator, err := m.GetIntegrator(ctx, storedKey.IntID)
	if err != nil {
		return "", "", err
	}

	if integrator.Status != "active" {
		return "", "", ErrIntegratorSuspended
	}

	return storedKey.IntID, storedKey.KeyID, nil
}

// parseAPIKey parses an API key in the format "prefix.key_id.key_secret" and returns key_id and key_secret.
func parseAPIKey(apiKey string) (string, string, error) {
	parts := strings.Split(apiKey, ".")
	if len(parts) != 3 {
		return "", "", ErrMalformedKey
	}

	prefix, keyID, keySecret := parts[0], parts[1], parts[2]
	if prefix != APIKeyPrefix {
		return "", "", ErrMalformedKey
	}

	if keyID == "" || keySecret == "" {
		return "", "", ErrMalformedKey
	}

	return keyID, keySecret, nil
}

// generateKeyID generates a random key ID.
func generateKeyID() (string, error) {
	b := make([]byte, 8) // 64 bits
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return "ki_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// generateKeySecret generates a random key secret.
func generateKeySecret() (string, error) {
	b := make([]byte, 32) // 256 bits
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
