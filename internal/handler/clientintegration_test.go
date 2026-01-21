package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockClientIntegrationKeyVerifier implements [ClientIntegrationKeyVerifier] for [TestClientIntegrationHandler].
type mockClientIntegrationKeyVerifier struct{}

var _ ClientIntegrationKeyVerifier = &mockClientIntegrationKeyVerifier{}

func (m *mockClientIntegrationKeyVerifier) ValidateKey(ctx context.Context, apiKey string) (string, string, int, error) {
	if apiKey == "valid-key" {
		return "test-integration", "test-key-id", 0, nil
	}
	return "", "", 0, fmt.Errorf("invalid key")
}

// mockClientIntegrationTokenGenerator implements [ClientIntegrationTokenGenerator] for [TestClientIntegrationHandler].
type mockClientIntegrationTokenGenerator struct {
	shouldFail bool
}

var _ ClientIntegrationTokenGenerator = &mockClientIntegrationTokenGenerator{}

func (m *mockClientIntegrationTokenGenerator) GenerateClientIntegrationToken(integrationID, keyID string, tier int, expiry time.Duration, audiences ...string) (string, error) {
	if m.shouldFail {
		return "", fmt.Errorf("generation failed")
	}
	return "test-token", nil
}

func TestClientIntegrationHandler(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		body          any
		tokenGenFails bool
		wantStatus    int
		wantToken     bool
		wantErrorMsg  string
	}{
		{
			name:   "valid request",
			method: http.MethodPost,
			body: ClientIntegrationRequest{
				APIKey: "valid-key",
			},

			tokenGenFails: false,
			wantStatus:    http.StatusOK,
			wantToken:     true,
		},

		{
			name:   "invalid method",
			method: http.MethodGet,
			body: ClientIntegrationRequest{
				APIKey: "valid-key",
			},
			wantStatus:   http.StatusMethodNotAllowed,
			wantErrorMsg: "Method not allowed\n",
		},

		{
			name:         "invalid request body",
			method:       http.MethodPost,
			body:         "invalid json",
			wantStatus:   http.StatusBadRequest,
			wantErrorMsg: "Invalid request body\n",
		},

		{
			name:   "empty api key",
			method: http.MethodPost,
			body:   ClientIntegrationRequest{},

			wantStatus:   http.StatusUnauthorized,
			wantErrorMsg: "Invalid API key\n",
		},

		{
			name:   "invalid api key",
			method: http.MethodPost,
			body: ClientIntegrationRequest{
				APIKey: "invalid-key",
			},
			wantStatus:   http.StatusUnauthorized,
			wantErrorMsg: "Invalid API key\n",
		},

		{
			name:   "token generation failure",
			method: http.MethodPost,
			body: ClientIntegrationRequest{
				APIKey: "valid-key",
			},
			tokenGenFails: true,
			wantStatus:    http.StatusInternalServerError,
			wantErrorMsg:  "Failed to generate token\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Initialize mocks
			mockStore := &mockClientIntegrationKeyVerifier{}
			mockJWT := &mockClientIntegrationTokenGenerator{shouldFail: tc.tokenGenFails}

			// Create handler
			handler := NewClientIntegrationHandler(mockJWT, mockStore)

			// Create request
			var body bytes.Buffer
			if str, ok := tc.body.(string); ok {
				body.WriteString(str)
			} else {
				require.NoError(t, json.NewEncoder(&body).Encode(tc.body))
			}

			req := httptest.NewRequest(tc.method, "/token", &body)
			rec := httptest.NewRecorder()

			// Handle request
			handler.Exchange(rec, req)

			// Check status code
			assert.Equal(t, tc.wantStatus, rec.Code)

			if tc.wantErrorMsg != "" {
				assert.Equal(t, tc.wantErrorMsg, rec.Body.String())
				return
			}

			if tc.wantToken {
				var resp ClientIntegrationResponse
				require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
				assert.Equal(t, "test-token", resp.Token)
				assert.Empty(t, resp.Error)
				assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			}
		})
	}
}
