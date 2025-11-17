package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"cloud.google.com/go/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeFlexibleDatastore implements [DatastoreClient] using a function-based pattern
// that allows tests to (1) define exactly the behavior they need and (2) embed
// assertions into tested functions via closures.
//
// # Design Pattern
//
// This fake uses closures to capture `*testing.T` from the test context, eliminating
// the need to store it in the struct or pass it as a parameter.
//
// Define a `setupFake` function in your test table that takes `*testing.T` and returns
// the configured fake. Inside `setupFake`, create mock functions that close over the `t`
// parameter - they'll automatically capture the innermost test context.
//
// This pattern is simpler than alternatives because:
//   - No need to store *testing.T in the struct
//   - Mock function signatures match the actual interface (no extra *testing.T param)
//   - Works naturally with table-driven tests and t.Run
//   - The fake has no dependency on the [testing] package
//
// # Usage
//
//	tests := []struct{
//	    name      string
//	    setupFake func(*testing.T) *fakeFlexibleDatastore
//	}{
//	    {
//	        name: "success",
//	        setupFake: func(t *testing.T) *fakeFlexibleDatastore {
//	            return &fakeFlexibleDatastore{
//	                GetFunc: func(ctx context.Context, key *datastore.Key, dst any) error {
//	                    // `t` is captured from the setupFake closure - innermost t!
//	                    require.Equal(t, "expected", key.Name)
//	                    return nil
//	                },
//	            }
//	        },
//	    },
//	}
//
//	for _, tt := range tests {
//	    t.Run(tt.name, func(t *testing.T) {
//	        fake := tt.setupFake(t)  // Captures innermost t via closure
//	        // use fake in test...
//	    })
//	}
type fakeFlexibleDatastore struct {
	// GetFunc defines the behavior of Get.
	//
	// Set this to control what Get returns. Leave nil if you do not
	// expect Get to be called (test will panic if called).
	GetFunc func(context.Context, *datastore.Key, any) error

	// GetAllFunc defines the behavior of GetAll.
	//
	// Set this to control what GetAll returns. Leave nil if you do not
	// expect GetAll to be called (test will panic if called).
	GetAllFunc func(context.Context, *datastore.Query, any) ([]*datastore.Key, error)

	// PutFunc defines the behavior of Put.
	//
	// Set this to control what Put returns. Leave nil if you do not
	// expect Put to be called (test will panic if called).
	PutFunc func(context.Context, *datastore.Key, any) (*datastore.Key, error)
}

var _ DatastoreClient = &fakeFlexibleDatastore{}

// Get implements [DatastoreClient].
func (f *fakeFlexibleDatastore) Get(ctx context.Context, key *datastore.Key, dst any) error {
	return f.GetFunc(ctx, key, dst)
}

// Put implements [DatastoreClient].
func (f *fakeFlexibleDatastore) Put(ctx context.Context, key *datastore.Key, src any) (*datastore.Key, error) {
	return f.PutFunc(ctx, key, src)
}

// GetAll implements [DatastoreClient].
func (f *fakeFlexibleDatastore) GetAll(ctx context.Context, q *datastore.Query, dst any) ([]*datastore.Key, error) {
	return f.GetAllFunc(ctx, q, dst)
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
			name:        "API key 301 bytes (exceeds 300 byte limit)",
			apiKey:      "mlabk.cii_test.ki_abc." + string(make([]byte, 279)),
			wantErr:     true,
			errContains: "API key too long",
		},

		{
			name:        "keySecret too long (>128 bytes)",
			apiKey:      "mlabk.cii_test.ki_abc." + string(make([]byte, 129)),
			wantErr:     true,
			errContains: "keySecret too long",
		},

		{
			name:              "keySecret exactly 128 bytes (max allowed)",
			apiKey:            "mlabk.cii_test.ki_abc." + string(make([]byte, 128)),
			wantIntegrationID: "test",
			wantKeyID:         "abc",
			wantKeySecret:     string(make([]byte, 128)),
			wantErr:           false,
		},

		{
			name:        "integrationID too long (>64 bytes)",
			apiKey:      "mlabk.cii_" + string(make([]byte, 65)) + ".ki_abc.secret",
			wantErr:     true,
			errContains: "integrationID too long",
		},

		{
			name:              "integrationID exactly 64 bytes (max allowed)",
			apiKey:            "mlabk.cii_" + string(make([]byte, 64)) + ".ki_abc.secret",
			wantIntegrationID: string(make([]byte, 64)),
			wantKeyID:         "abc",
			wantKeySecret:     "secret",
			wantErr:           false,
		},

		{
			name:        "keyID too long (>64 bytes)",
			apiKey:      "mlabk.cii_test.ki_" + string(make([]byte, 65)) + ".secret",
			wantErr:     true,
			errContains: "keyID too long",
		},

		{
			name:              "keyID exactly 64 bytes (max allowed)",
			apiKey:            "mlabk.cii_test.ki_" + string(make([]byte, 64)) + ".secret",
			wantIntegrationID: "test",
			wantKeyID:         string(make([]byte, 64)),
			wantKeySecret:     "secret",
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
	// Generate a test SHA-256 hash for "supersecret"
	testSecret := "supersecret"
	hash := sha256.Sum256([]byte(testSecret))
	testHash := hex.EncodeToString(hash[:])

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
					GetFunc: func(ctx context.Context, key *datastore.Key, dst any) error {
						// Verify hierarchical key structure (t captured from closure)
						assert.Equal(t, "abc123", key.Name)
						assert.Equal(t, clientIntegrationAPIKeyKind, key.Kind)
						require.NotNil(t, key.Parent, "expected parent key")
						assert.Equal(t, "test-integration", key.Parent.Name)
						assert.Equal(t, clientIntegrationMetaKind, key.Parent.Kind)
						assert.Equal(t, "test-namespace", key.Namespace)

						// Return valid entity
						entity := dst.(*clientIntegrationAPIKey)
						*entity = clientIntegrationAPIKey{
							KeyHash: testHash,
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
					GetFunc: func(ctx context.Context, key *datastore.Key, dst any) error {
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
					GetFunc: func(ctx context.Context, key *datastore.Key, dst any) error {
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
					GetFunc: func(ctx context.Context, key *datastore.Key, dst any) error {
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
					GetFunc: func(ctx context.Context, key *datastore.Key, dst any) error {
						entity := dst.(*clientIntegrationAPIKey)
						*entity = clientIntegrationAPIKey{
							KeyHash: testHash,
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
					GetFunc: func(ctx context.Context, key *datastore.Key, dst any) error {
						entity := dst.(*clientIntegrationAPIKey)
						*entity = clientIntegrationAPIKey{
							KeyHash: testHash,
							Status:  clientIntegrationAPIKeyStatusActive,
						}
						return nil
					},
				}
			},
			wantErr:     true,
			errContains: "secret does not match stored hash",
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
