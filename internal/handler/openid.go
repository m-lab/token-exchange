// openid.go - OpenID Connect discovery document.

package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// openIDConfiguration is the subset of the OpenID Connect discovery document
// that relying parties need to verify tokens: who issues them and where the
// signing keys are.
type openIDConfiguration struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

// OpenIDConfigurationHandler serves the discovery document for the issuer of
// storage tokens. It lets a relying party such as a Google workload identity
// pool fetch the signing keys from the JWKS endpoint instead of holding a copy.
type OpenIDConfigurationHandler struct {
	issuer    string
	jwtSigner PublicKeyProvider
}

// NewOpenIDConfigurationHandler creates a handler for the given issuer. The
// issuer must be the public https URL of this service and must equal the iss
// claim of the tokens it describes.
func NewOpenIDConfigurationHandler(issuer string, jwtSigner PublicKeyProvider) *OpenIDConfigurationHandler {
	return &OpenIDConfigurationHandler{
		issuer:    issuer,
		jwtSigner: jwtSigner,
	}
}

// ServeOpenIDConfiguration handles requests for /.well-known/openid-configuration.
func (h *OpenIDConfigurationHandler) ServeOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	config := openIDConfiguration{
		// The issuer is reported exactly as configured, because relying
		// parties compare it byte for byte with the iss claim.
		Issuer:                           h.issuer,
		JWKSURI:                          strings.TrimSuffix(h.issuer, "/") + "/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{h.jwtSigner.GetPublicJWK().Algorithm},
		ClaimsSupported:                  []string{"iss", "aud", "sub", "org", "iat", "nbf", "exp", "jti"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if err := json.NewEncoder(w).Encode(config); err != nil {
		slog.Error("Error encoding OpenID configuration response", "err", err)
		http.Error(w, "Failed to encode OpenID configuration response", http.StatusInternalServerError)
		return
	}
}
