// clientintegration.go - return signed JWTs for client-integration.

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// ClientIntegrationTokenGenerator defines the interface for generating
// client-integration authentication tokens.
type ClientIntegrationTokenGenerator interface {
	GenerateClientIntegrationToken(integrationID, keyID string, tier int, expiry time.Duration, audience ...string) (string, error)
}

// ClientIntegrationKeyVerifier defines the interface for validating
// API keys and retrieving the integration ID, key ID, and tier.
type ClientIntegrationKeyVerifier interface {
	ValidateKey(ctx context.Context, apiKey string) (integrationID string, keyID string, tier int, err error)
}

// ClientIntegrationHandler exchanges integration API keys for short-lived JWTs.
type ClientIntegrationHandler struct {
	jwtSigner ClientIntegrationTokenGenerator
	store     ClientIntegrationKeyVerifier
}

// ClientIntegrationRequest represents the request payload for token exchanges
// pertaining the [clientIntegrationAudience].
type ClientIntegrationRequest = AutojoinRequest

// ClientIntegrationResponse represents the response payload containing
// the generated JWT for the [clientIntegrationAudience].
type ClientIntegrationResponse = AutojoinResponse

// NewClientIntegrationHandler creates a new [*ClientIntegrationHandler]
// with the provided token generator and key verifier.
func NewClientIntegrationHandler(
	jwtSigner ClientIntegrationTokenGenerator, store ClientIntegrationKeyVerifier) *ClientIntegrationHandler {
	return &ClientIntegrationHandler{
		jwtSigner: jwtSigner,
		store:     store,
	}
}

const (
	clientIntegrationAudience = "integration"
	clientIntegrationExpiry   = 20 * time.Second
)

// Exchange handles HTTP requests to exchange integrator API keys for JWT tokens.
//
// It validates the API key and returns a JWT token for the associated client integration.
//
// This method is thread safe.
func (h *ClientIntegrationHandler) Exchange(w http.ResponseWriter, r *http.Request) {
	// Verify that the method is the expected one
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Receive and decode the request body
	var req ClientIntegrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Verify API key and get integration ID, key ID, and tier
	integrationID, keyID, tier, err := h.store.ValidateKey(r.Context(), req.APIKey)
	if err != nil {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	// Generate JWT using integration ID, key ID, and tier
	token, err := h.jwtSigner.GenerateClientIntegrationToken(integrationID, keyID, tier, clientIntegrationExpiry, clientIntegrationAudience)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Generate and encode the response body
	resp := ClientIntegrationResponse{
		Token: token,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
