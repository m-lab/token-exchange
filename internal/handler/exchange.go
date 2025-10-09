package handler

// TODO(bassosimone): This should become `autojoin.go` for clarity.

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// TokenGenerator defines the interface for generating authentication tokens.
//
// TODO(bassosimone): This should become `AutojoinKeyTokenGenerator`.
type TokenGenerator interface {
	GenerateToken(org string, expiry time.Duration, audience ...string) (string, error)
}

// KeyVerifier defines the interface for validating API keys and retrieving
// organization information.
//
// TODO(bassosimone): This should become `AutojoinKeyVerifier`.
type KeyVerifier interface {
	ValidateKey(ctx context.Context, apiKey string) (string, error)
}

// ExchangeHandler handles the exchange of API keys for JWT tokens.
//
// TODO(bassosimone): This should become `AutojoinHandler`.
type ExchangeHandler struct {
	jwtSigner TokenGenerator
	store     KeyVerifier
}

// TokenRequest represents the request payload for token exchange.
//
// TODO(bassosimone): This should become `AutojoinRequest`.
type TokenRequest struct {
	APIKey string `json:"api_key"`
}

// TokenResponse represents the response payload containing the generated token.
//
// TODO(bassosimone): This should become `AutojoinResponse`.
type TokenResponse struct {
	Token string `json:"token"`
	Error string `json:"error,omitempty"`
}

// NewExchangeHandler creates a new ExchangeHandler with the provided token generator and key verifier.
func NewExchangeHandler(jwtSigner TokenGenerator, store KeyVerifier) *ExchangeHandler {
	return &ExchangeHandler{
		jwtSigner: jwtSigner,
		store:     store,
	}
}

// Exchange handles HTTP requests to exchange API keys for JWT tokens.
// It validates the API key and returns a JWT token for the associated organization.
func (h *ExchangeHandler) Exchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TokenRequest
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
	const (
		audience = "autojoin"
		expiry   = time.Hour
	)
	token, err := h.jwtSigner.GenerateToken(orgID, expiry, audience)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	resp := TokenResponse{
		Token: token,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
