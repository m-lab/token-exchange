// storage.go - return signed JWTs for Cloud Storage access via Workload Identity Federation.

package handler

import (
	"encoding/json"
	"net/http"
	"time"
)

// StorageTokenGenerator defines the interface for generating storage authentication tokens.
type StorageTokenGenerator interface {
	GenerateStorageToken(org string, expiry time.Duration, audience ...string) (string, error)
}

// StorageHandler handles the exchange of API keys for JWTs that Google STS
// accepts through a workload identity pool.
type StorageHandler struct {
	jwtSigner StorageTokenGenerator
	store     AutojoinKeyVerifier
}

// StorageRequest represents the request payload for a storage token exchange.
type StorageRequest = AutojoinRequest

// StorageResponse represents the response payload containing the generated
// JWT for the [storageAudience].
type StorageResponse = AutojoinResponse

// NewStorageHandler creates a new [*StorageHandler] with the provided token
// generator and key verifier.
func NewStorageHandler(jwtSigner StorageTokenGenerator, store AutojoinKeyVerifier) *StorageHandler {
	return &StorageHandler{
		jwtSigner: jwtSigner,
		store:     store,
	}
}

const (
	storageAudience = "storage"
	storageExpiry   = 2 * time.Hour
)

// Exchange handles HTTP requests to exchange API keys for storage JWT tokens.
// It validates the API key and returns a JWT token for the associated organization.
func (h *StorageHandler) Exchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req StorageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	orgID, err := h.store.ValidateKey(r.Context(), req.APIKey)
	if err != nil {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	token, err := h.jwtSigner.GenerateStorageToken(orgID, storageExpiry, storageAudience)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	resp := StorageResponse{Token: token}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
