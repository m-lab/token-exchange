package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStorageTokenGenerator implements [StorageTokenGenerator] and records its arguments.
type mockStorageTokenGenerator struct {
	shouldFail bool

	org      string
	expiry   time.Duration
	audience []string
}

var _ StorageTokenGenerator = &mockStorageTokenGenerator{}

func (m *mockStorageTokenGenerator) GenerateStorageToken(org string, expiry time.Duration, audience ...string) (string, error) {
	m.org, m.expiry, m.audience = org, expiry, audience
	if m.shouldFail {
		return "", fmt.Errorf("generation failed")
	}
	return "storage-token", nil
}

func TestStorageHandler(t *testing.T) {
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
			name:       "valid request",
			method:     http.MethodPost,
			body:       StorageRequest{APIKey: "valid-key"},
			wantStatus: http.StatusOK,
			wantToken:  true,
		},
		{
			name:         "invalid method",
			method:       http.MethodGet,
			body:         StorageRequest{APIKey: "valid-key"},
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
			name:         "empty api key",
			method:       http.MethodPost,
			body:         StorageRequest{},
			wantStatus:   http.StatusUnauthorized,
			wantErrorMsg: "Invalid API key\n",
		},
		{
			name:         "invalid api key",
			method:       http.MethodPost,
			body:         StorageRequest{APIKey: "invalid-key"},
			wantStatus:   http.StatusUnauthorized,
			wantErrorMsg: "Invalid API key\n",
		},
		{
			name:          "token generation failure",
			method:        http.MethodPost,
			body:          StorageRequest{APIKey: "valid-key"},
			tokenGenFails: true,
			wantStatus:    http.StatusInternalServerError,
			wantErrorMsg:  "Failed to generate token\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockJWT := &mockStorageTokenGenerator{shouldFail: tc.tokenGenFails}
			h := NewStorageHandler(mockJWT, &mockAutojoinKeyVerifier{})

			var body bytes.Buffer
			if str, ok := tc.body.(string); ok {
				body.WriteString(str)
			} else {
				require.NoError(t, json.NewEncoder(&body).Encode(tc.body))
			}

			req := httptest.NewRequest(tc.method, "/v0/token/storage", &body)
			rec := httptest.NewRecorder()
			h.Exchange(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)

			if tc.wantErrorMsg != "" {
				assert.Equal(t, tc.wantErrorMsg, rec.Body.String())
				return
			}

			var resp StorageResponse
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
			assert.Equal(t, "storage-token", resp.Token)
			assert.Empty(t, resp.Error)
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

			// The token must be minted for the validated org, with the
			// storage audience and a 2 hour lifetime.
			assert.Equal(t, "test-org", mockJWT.org)
			assert.Equal(t, []string{"storage"}, mockJWT.audience)
			assert.Equal(t, 2*time.Hour, mockJWT.expiry)
		})
	}
}
