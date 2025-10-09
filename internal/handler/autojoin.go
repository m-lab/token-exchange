// autojoin.go - return signed JWTs for autojoin.

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// AutojoinTokenGenerator defines the interface for generating autojoin authentication tokens.
type AutojoinTokenGenerator interface {
	GenerateAutojoinToken(org string, expiry time.Duration, audience ...string) (string, error)
}

// AutojoinKeyVerifier defines the interface for validating API keys and retrieving
// organization information.
type AutojoinKeyVerifier interface {
	ValidateKey(ctx context.Context, apiKey string) (string, error)
}

// AutojoinHandler handles the exchange of API keys for JWTs.
type AutojoinHandler struct {
	jwtSigner AutojoinTokenGenerator
	store     AutojoinKeyVerifier
}

// AutojoinRequest represents the request payload for token exchange.
type AutojoinRequest struct {
	APIKey string `json:"api_key"`
}

// AutojoinResponse represents the response payload containing the generated token.
type AutojoinResponse struct {
	Token string `json:"token"`
	Error string `json:"error,omitempty"`
}

// NewAutojoinHandler creates a new [*AutojoinHandler] with the provided token generator and key verifier.
func NewAutojoinHandler(jwtSigner AutojoinTokenGenerator, store AutojoinKeyVerifier) *AutojoinHandler {
	return &AutojoinHandler{
		jwtSigner: jwtSigner,
		store:     store,
	}
}

const (
	autojoinAudience = "autojoin"
	autojoinExpiry   = time.Hour
)

// Exchange handles HTTP requests to exchange API keys for JWT tokens.
// It validates the API key and returns a JWT token for the associated organization.
func (h *AutojoinHandler) Exchange(w http.ResponseWriter, r *http.Request) {
	// Verify that the method is the expected one
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Receive and decode the request body
	var req AutojoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Verify API key and get organization ID
	orgID, err := h.store.ValidateKey(r.Context(), req.APIKey)
	if err != nil {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	// Generate JWT using organization ID
	token, err := h.jwtSigner.GenerateAutojoinToken(orgID, autojoinExpiry, autojoinAudience)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Generate and encode the response body
	resp := AutojoinResponse{
		Token: token,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
