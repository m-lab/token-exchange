package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenIDConfigurationHandler(t *testing.T) {
	provider := &mockJWKSPublicKeyProvider{
		getPublicJWK: func() jose.JSONWebKey {
			return jose.JSONWebKey{KeyID: "test-key-1", Algorithm: string(jose.RS256), Use: "sig"}
		},
	}

	tests := []struct {
		name        string
		issuer      string
		method      string
		wantStatus  int
		wantIssuer  string
		wantJWKSURI string
	}{
		{
			name:        "valid request",
			issuer:      "https://auth.example.net",
			method:      http.MethodGet,
			wantStatus:  http.StatusOK,
			wantIssuer:  "https://auth.example.net",
			wantJWKSURI: "https://auth.example.net/.well-known/jwks.json",
		},
		{
			name:       "method not allowed",
			issuer:     "https://auth.example.net",
			method:     http.MethodPost,
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewOpenIDConfigurationHandler(tt.issuer, provider)
			req := httptest.NewRequest(tt.method, "/.well-known/openid-configuration", nil)
			rec := httptest.NewRecorder()

			h.ServeOpenIDConfiguration(rec, req)

			require.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantStatus != http.StatusOK {
				return
			}
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			assert.Equal(t, "public, max-age=3600, must-revalidate", rec.Header().Get("Cache-Control"))

			var got map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			assert.Equal(t, tt.wantIssuer, got["issuer"])
			assert.Equal(t, tt.wantJWKSURI, got["jwks_uri"])
			assert.Equal(t, []any{"id_token"}, got["response_types_supported"])
			assert.Equal(t, []any{"public"}, got["subject_types_supported"])
			assert.Equal(t, []any{"RS256"}, got["id_token_signing_alg_values_supported"])
			assert.Equal(t, []any{"iss", "aud", "sub", "org", "iat", "nbf", "exp", "jti"}, got["claims_supported"])
		})
	}
}
