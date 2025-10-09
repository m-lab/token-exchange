package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockJWKSPublicKeyProvider implements [PublicKeyProvider] for [TestJWKSHandler].
type mockJWKSPublicKeyProvider struct {
	getPublicJWK func() jose.JSONWebKey
}

var _ PublicKeyProvider = &mockJWKSPublicKeyProvider{}

func (m *mockJWKSPublicKeyProvider) GetPublicJWK() jose.JSONWebKey {
	return m.getPublicJWK()
}

func TestJWKSHandler(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		getPublicJWK  func() jose.JSONWebKey
		wantStatus    int
		wantErrorMsg  string
		checkResponse func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:   "valid request",
			method: http.MethodGet,
			getPublicJWK: func() jose.JSONWebKey {
				key, _ := base64.RawURLEncoding.DecodeString("Gb9ECWnNhP6FQbrBZ9w7lshQhqowtrbQBCdtblFbHME")
				return jose.JSONWebKey{
					KeyID:     "test-key-1",
					Key:       key,
					Algorithm: string(jose.EdDSA),
					Use:       "sig",
				}
			},
			wantStatus: http.StatusOK,
			checkResponse: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
				assert.Equal(t, "public, max-age=3600, must-revalidate", rec.Header().Get("Cache-Control"))
				assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))

				var jwks jose.JSONWebKeySet
				err := json.NewDecoder(rec.Body).Decode(&jwks)
				require.NoError(t, err)

				require.Len(t, jwks.Keys, 1)
				assert.Equal(t, "test-key-1", jwks.Keys[0].KeyID)
				assert.Equal(t, "EdDSA", jwks.Keys[0].Algorithm)
				assert.Equal(t, "sig", jwks.Keys[0].Use)
			},
		},

		{
			name:         "invalid method",
			method:       http.MethodPost,
			wantStatus:   http.StatusMethodNotAllowed,
			wantErrorMsg: "Method not allowed\n",
		},

		{
			name:   "cannot serialize the jose.JSONWebKey",
			method: http.MethodGet,
			getPublicJWK: func() jose.JSONWebKey {
				return jose.JSONWebKey{
					Key: make(chan struct{}), // non-JSON-serializable
				}
			},
			wantStatus:    http.StatusInternalServerError,
			wantErrorMsg:  "Failed to encode JWKS response\n",
			checkResponse: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := NewJWKSHandler(&mockJWKSPublicKeyProvider{
				getPublicJWK: tc.getPublicJWK,
			})

			req := httptest.NewRequest(tc.method, "/.well-known/jwks.json", nil)
			rec := httptest.NewRecorder()

			handler.ServeJWKS(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)

			if tc.wantErrorMsg != "" {
				assert.Equal(t, tc.wantErrorMsg, rec.Body.String())
				return
			}

			if tc.checkResponse != nil {
				tc.checkResponse(t, rec)
			}
		})
	}
}
