package store

import (
	"context"
	"testing"

	"cloud.google.com/go/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// fakeFlexibleDatastore implements [DatastoreClient] using a function-based pattern
// that allows tests to (1) define exactly the behavior they need and (2) embed
// assertions into tested functions through the `t` field.
type fakeFlexibleDatastore struct {
	t   *testing.T
	get func(*testing.T, context.Context, *datastore.Key, any) error
}

var _ DatastoreClient = &fakeFlexibleDatastore{}

func (f *fakeFlexibleDatastore) Get(ctx context.Context, key *datastore.Key, dst any) error {
	if f.get == nil {
		f.t.Fatal("fakeFlexibleDatastore.get not set")
	}
	return f.get(f.t, ctx, key, dst)
}

func (f *fakeFlexibleDatastore) Put(ctx context.Context, key *datastore.Key, src any) (*datastore.Key, error) {
	f.t.Fatal("fakeFlexibleDatastore.Put not implemented")
	return nil, nil
}

func (f *fakeFlexibleDatastore) GetAll(ctx context.Context, q *datastore.Query, dst any) ([]*datastore.Key, error) {
	f.t.Fatal("fakeFlexibleDatastore.GetAll not implemented")
	return nil, nil
}

func TestParseAPIKey(t *testing.T) {
	tests := []struct {
		name              string
		apiKey            string
		wantIntegrationID string
		wantKeyID         string
		wantKeySecret     string
		wantErr           bool
		errContains       string
	}{
		{
			name:              "valid API key",
			apiKey:            "mlabk.cii_test-integration.ki_abc123.secret456",
			wantIntegrationID: "test-integration",
			wantKeyID:         "abc123",
			wantKeySecret:     "secret456",
			wantErr:           false,
		},

		{
			name:              "valid API key with complex IDs",
			apiKey:            "mlabk.cii_org-prod-2024.ki_key-v2-20241030.supersecret",
			wantIntegrationID: "org-prod-2024",
			wantKeyID:         "key-v2-20241030",
			wantKeySecret:     "supersecret",
			wantErr:           false,
		},

		{
			name:        "missing mlabk prefix",
			apiKey:      "cii_test.ki_abc.secret",
			wantErr:     true,
			errContains: "missing apiKeyPrefix",
		},

		{
			name:        "wrong prefix",
			apiKey:      "wrongprefix.cii_test.ki_abc.secret",
			wantErr:     true,
			errContains: "missing apiKeyPrefix",
		},

		{
			name:        "missing cii_ prefix",
			apiKey:      "mlabk.test-integration.ki_abc123.secret456",
			wantErr:     true,
			errContains: "missing integrationIDPrefix",
		},

		{
			name:        "missing ki_ prefix",
			apiKey:      "mlabk.cii_test-integration.abc123.secret456",
			wantErr:     true,
			errContains: "missing keyIDPrefix",
		},

		{
			name:        "only two dot-separated parts",
			apiKey:      "mlabk.cii_test.ki_abc",
			wantErr:     true,
			errContains: "expected 3 entries, got 2",
		},

		{
			name:        "only one dot-separated part",
			apiKey:      "mlabk.cii_test",
			wantErr:     true,
			errContains: "expected 3 entries, got 1",
		},

		{
			name:        "four dot-separated parts",
			apiKey:      "mlabk.cii_test.ki_abc.secret.extra",
			wantErr:     true,
			errContains: "expected 3 entries, got 4",
		},

		{
			name:        "empty string",
			apiKey:      "",
			wantErr:     true,
			errContains: "missing apiKeyPrefix",
		},

		{
			name:        "only prefix",
			apiKey:      "mlabk.",
			wantErr:     true,
			errContains: "expected 3 entries, got 1",
		},

		{
			name:        "empty integrationID",
			apiKey:      "mlabk.cii_.ki_abc.secret",
			wantErr:     true,
			errContains: "integrationID cannot be empty",
		},

		{
			name:        "empty keyID",
			apiKey:      "mlabk.cii_test.ki_.secret",
			wantErr:     true,
			errContains: "keyID cannot be empty",
		},

		{
			name:        "empty keySecret",
			apiKey:      "mlabk.cii_test.ki_abc.",
			wantErr:     true,
			errContains: "keySecret cannot be empty",
		},

		{
			name:        "API key too long (>256 bytes)",
			apiKey:      "mlabk.cii_test.ki_abc." + string(make([]byte, 250)),
			wantErr:     true,
			errContains: "API key too long",
		},

		{
			name:        "keySecret too long (>72 bytes)",
			apiKey:      "mlabk.cii_test.ki_abc." + string(make([]byte, 73)),
			wantErr:     true,
			errContains: "keySecret exceeds bcrypt limit",
		},

		{
			name:              "keySecret exactly 72 bytes (bcrypt limit)",
			apiKey:            "mlabk.cii_test.ki_abc." + string(make([]byte, 72)),
			wantIntegrationID: "test",
			wantKeyID:         "abc",
			wantKeySecret:     string(make([]byte, 72)),
			wantErr:           false,
		},

		{
			name:        "too many dots (SplitN should handle efficiently)",
			apiKey:      "mlabk.cii_test.ki_abc.secret.extra.dots.here",
			wantErr:     true,
			errContains: "expected 3 entries, got 4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIntegrationID, gotKeyID, gotKeySecret, err := parseAPIKey(tt.apiKey)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantIntegrationID, gotIntegrationID)
			assert.Equal(t, tt.wantKeyID, gotKeyID)
			assert.Equal(t, tt.wantKeySecret, gotKeySecret)
		})
	}
}

func TestClientIntegrationManager_ValidateKey(t *testing.T) {
	// Generate a test bcrypt hash for "supersecret"
	testSecret := "supersecret"
	testHash, err := bcrypt.GenerateFromPassword([]byte(testSecret), bcrypt.DefaultCost)
	require.NoError(t, err)

	tests := []struct {
		name              string
		apiKey            string
		setupFake         func(*testing.T) *fakeFlexibleDatastore
		wantIntegrationID string
		wantKeyID         string
		wantErr           bool
		errContains       string
	}{
		{
			name:   "valid key with correct hierarchy",
			apiKey: "mlabk.cii_test-integration.ki_abc123." + testSecret,
			setupFake: func(t *testing.T) *fakeFlexibleDatastore {
				return &fakeFlexibleDatastore{
					t: t,
					get: func(t *testing.T, ctx context.Context, key *datastore.Key, dst any) error {
						// Verify hierarchical key structure
						assert.Equal(t, "abc123", key.Name)
						assert.Equal(t, clientIntegrationAPIKeyKind, key.Kind)
						require.NotNil(t, key.Parent, "expected parent key")
						assert.Equal(t, "test-integration", key.Parent.Name)
						assert.Equal(t, clientIntegrationMetaKind, key.Parent.Kind)
						assert.Equal(t, "test-namespace", key.Namespace)

						// Return valid entity
						entity := dst.(*clientIntegrationAPIKey)
						*entity = clientIntegrationAPIKey{
							KeyHash: string(testHash),
							Status:  clientIntegrationAPIKeyStatusActive,
						}
						return nil
					},
				}
			},
			wantIntegrationID: "test-integration",
			wantKeyID:         "abc123",
			wantErr:           false,
		},

		{
			name:   "malformed API key",
			apiKey: "invalid-key-format",
			setupFake: func(t *testing.T) *fakeFlexibleDatastore {
				return &fakeFlexibleDatastore{
					t: t,
					get: func(t *testing.T, ctx context.Context, key *datastore.Key, dst any) error {
						t.Fatal("Get should not be called for malformed key")
						return nil
					},
				}
			},
			wantErr:     true,
			errContains: "missing apiKeyPrefix",
		},

		{
			name:   "key not found in datastore",
			apiKey: "mlabk.cii_nonexistent.ki_xyz789." + testSecret,
			setupFake: func(t *testing.T) *fakeFlexibleDatastore {
				return &fakeFlexibleDatastore{
					t: t,
					get: func(t *testing.T, ctx context.Context, key *datastore.Key, dst any) error {
						return datastore.ErrNoSuchEntity
					},
				}
			},
			wantErr:     true,
			errContains: "invalid API key",
		},

		{
			name:   "datastore error",
			apiKey: "mlabk.cii_test-integration.ki_abc123." + testSecret,
			setupFake: func(t *testing.T) *fakeFlexibleDatastore {
				return &fakeFlexibleDatastore{
					t: t,
					get: func(t *testing.T, ctx context.Context, key *datastore.Key, dst any) error {
						return errTest
					},
				}
			},
			wantErr:     true,
			errContains: "cannot Get from datastore",
		},

		{
			name:   "inactive key status",
			apiKey: "mlabk.cii_test-integration.ki_abc123." + testSecret,
			setupFake: func(t *testing.T) *fakeFlexibleDatastore {
				return &fakeFlexibleDatastore{
					t: t,
					get: func(t *testing.T, ctx context.Context, key *datastore.Key, dst any) error {
						entity := dst.(*clientIntegrationAPIKey)
						*entity = clientIntegrationAPIKey{
							KeyHash: string(testHash),
							Status:  "revoked", // Not active
						}
						return nil
					},
				}
			},
			wantErr:     true,
			errContains: "the key is not active",
		},

		{
			name:   "incorrect secret",
			apiKey: "mlabk.cii_test-integration.ki_abc123.wrongsecret",
			setupFake: func(t *testing.T) *fakeFlexibleDatastore {
				return &fakeFlexibleDatastore{
					t: t,
					get: func(t *testing.T, ctx context.Context, key *datastore.Key, dst any) error {
						entity := dst.(*clientIntegrationAPIKey)
						*entity = clientIntegrationAPIKey{
							KeyHash: string(testHash),
							Status:  clientIntegrationAPIKeyStatusActive,
						}
						return nil
					},
				}
			},
			wantErr:     true,
			errContains: "comparing secret and hash failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := tt.setupFake(t)
			manager := NewClientIntegrationManager(fake, "test-project", "test-namespace")

			gotIntegrationID, gotKeyID, err := manager.ValidateKey(context.Background(), tt.apiKey)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantIntegrationID, gotIntegrationID)
			assert.Equal(t, tt.wantKeyID, gotKeyID)
		})
	}
}
