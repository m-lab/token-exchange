// jwks.go - JWKS (JSON Web Key Set) public key server.

package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

// PublicKeyProvider defines the interface for providing public keys in JWK format.
type PublicKeyProvider interface {
	GetPublicJWK() jose.JSONWebKey
}

// JWKSHandler handles serving JSON Web Key Set (JWKS) endpoints.
type JWKSHandler struct {
	jwtSigner PublicKeyProvider
}

// NewJWKSHandler creates a new JWKSHandler with the provided public key provider.
func NewJWKSHandler(jwtSigner PublicKeyProvider) *JWKSHandler {
	return &JWKSHandler{
		jwtSigner: jwtSigner,
	}
}

// ServeJWKS handles HTTP requests to serve the JSON Web Key Set (JWKS) containing public keys.
// It returns the public keys in JWKS format with appropriate caching headers.
func (h *JWKSHandler) ServeJWKS(w http.ResponseWriter, r *http.Request) {
	// Verify that the method is the expected one
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Prepare the key set to send
	publicJWK := h.jwtSigner.GetPublicJWK()
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{publicJWK},
	}

	// Set headers including cache and access control to avoid excessive caching
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Serialize and send the key set.
	//
	// Note: the [jose.JSONWebKey] type contains `any` types therefore we cannot assume
	// that the serialization is going to work in general.
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		slog.Error("Error encoding JWKS response", "err", err)
		http.Error(w, "Failed to encode JWKS response", http.StatusInternalServerError)
		return
	}
}
