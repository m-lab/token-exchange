package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockKeyVerifier struct{}

func (m *mockKeyVerifier) ValidateKey(ctx context.Context, apiKey string) (string, error) {
	if apiKey == "valid-key" {
		return "test-org", nil
	}
	return "", fmt.Errorf("invalid key")
}

type mockTokenGenerator struct {
	shouldFail bool
}

func (m *mockTokenGenerator) GenerateToken(org string) (string, error) {
	if m.shouldFail {
		return "", fmt.Errorf("generation failed")
	}
	return "test-token", nil
}

func TestExchange(t *testing.T) {
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
			body: TokenRequest{
				APIKey: "valid-key",
			},

			tokenGenFails: false,
			wantStatus:    http.StatusOK,
			wantToken:     true,
		},
		{
			name:   "invalid method",
			method: http.MethodGet,
			body: TokenRequest{
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
			body:   TokenRequest{},

			wantStatus:   http.StatusUnauthorized,
			wantErrorMsg: "Invalid API key\n",
		},
		{
			name:   "invalid api key",
			method: http.MethodPost,
			body: TokenRequest{
				APIKey: "invalid-key",
			},

			wantStatus:   http.StatusUnauthorized,
			wantErrorMsg: "Invalid API key\n",
		},
		{
			name:   "token generation failure",
			method: http.MethodPost,
			body: TokenRequest{
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
			mockStore := &mockKeyVerifier{}
			mockJWT := &mockTokenGenerator{shouldFail: tc.tokenGenFails}

			// Create handler
			handler := NewExchangeHandler(mockJWT, mockStore)

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
				var resp TokenResponse
				require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
				assert.Equal(t, "test-token", resp.Token)
				assert.Empty(t, resp.Error)
				assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			}
		})
	}
}
