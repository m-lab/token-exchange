package handler

import (
	"encoding/json"
	"net/http"
	"time"
)

// IntegrationTokenGenerator defines the interface for generating
// authentication tokens for the `integration` audience.
type IntegrationTokenGenerator = TokenGenerator

// IntegrationKeyVerifier defines the interface for validating
// API keys and retrieving the organization ID.
type IntegrationKeyVerifier = KeyVerifier

// IntegrationHandler exchanges integration API keys for short-lived JWTs.
type IntegrationHandler struct {
	jwtSigner TokenGenerator
	store     KeyVerifier
}

// IntegrationRequest represents the request payload for token exchanges
// pertaining the `integration` audience.
type IntegrationRequest = TokenRequest

// IntegrationResponse represents the response payload containing
// the generated JWT for the `integration` audience.
type IntegrationResponse = TokenResponse

// NewIntegrationHandler creates a new IntegrationHandler with the provided token generator and key verifier.
func NewIntegrationHandler(
	jwtSigner IntegrationTokenGenerator, store IntegrationKeyVerifier) *IntegrationHandler {
	return &IntegrationHandler{
		jwtSigner: jwtSigner,
		store:     store,
	}
}

// Exchange handles HTTP requests to exchange integrator API keys for JWT tokens.
//
// It validates the API key using bcrypt comparison and returns a JWT token for the associated integration.
//
// This method is thread safe.
func (h *IntegrationHandler) Exchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req IntegrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Verify API key and get integration ID
	integrationID, err := h.store.ValidateKey(r.Context(), req.APIKey)
	if err != nil {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	// Generate JWT using integration ID
	const (
		audience = "integration"
		expiry   = 20 * time.Second
	)
	token, err := h.jwtSigner.GenerateToken(integrationID, expiry, audience)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	resp := IntegrationResponse{
		Token: token,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// TODO(bassosimone): Implement integration tests for the token exchange flow.
