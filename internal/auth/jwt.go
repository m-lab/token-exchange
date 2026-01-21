// Package auth implements JWT auth.
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

// Issuer is the entity that issued the JWTs.
const Issuer = "token-exchange"

// JWTSigner is a JWT signer that can be used to sign JWTs.
type JWTSigner struct {
	signer    jose.Signer
	publicJWK jose.JSONWebKey
}

// AutojoinClaims is a JWT claims set for autojoin tokens.
type AutojoinClaims struct {
	jwt.Claims
	Organization string `json:"org"`
}

// ClientIntegrationClaims is a JWT claims set for client-integration tokens.
type ClientIntegrationClaims struct {
	jwt.Claims
	IntegrationID string `json:"int_id"`
	KeyID         string `json:"key_id"`
	Tier          int    `json:"tier"`
}

// NewJWTSigner loads a private key from a JWK file and prepares a signer.
func NewJWTSigner(keyPath string) (*JWTSigner, error) {
	// Read private key JWK file
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", keyPath, err)
	}

	// Unmarshal the raw JSON into a jose.JSONWebKey
	var privateJWK jose.JSONWebKey
	if err := json.Unmarshal(keyBytes, &privateJWK); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWK from %s: %w", keyPath, err)
	}

	// Check if the key is private (required for signing)
	if privateJWK.IsPublic() {
		return nil, fmt.Errorf("JWK in %s is not a private key", keyPath)
	}

	// Ensure the key has a Key ID (kid)
	if privateJWK.KeyID == "" {
		return nil, fmt.Errorf("JWK in %s must have a 'kid' (Key ID)", keyPath)
	}

	// Create the signer using the private key
	signerOpts := (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), privateJWK.KeyID)
	alg := jose.SignatureAlgorithm(privateJWK.Algorithm)
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: alg,
		Key:       privateJWK.Key,
	}, signerOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create jose signer: %w", err)
	}

	// Store the public part of the key for the JWKS endpoint
	publicJWK := privateJWK.Public()

	return &JWTSigner{
		signer:    signer,
		publicJWK: publicJWK,
	}, nil
}

// GenerateAutojoinToken generates a JWT token for autojoin with organization ID.
//
// This method is thread safe.
func (s *JWTSigner) GenerateAutojoinToken(org string, expiry time.Duration, audience ...string) (string, error) {
	if org == "" {
		return "", errors.New("organization cannot be empty")
	}
	if len(audience) <= 0 {
		return "", errors.New("audience cannot be empty")
	}

	now := time.Now()

	claims := AutojoinClaims{
		Organization: org,
		Claims: jwt.Claims{
			ID:        uuid.New().String(),
			Issuer:    Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(now.Add(expiry)),
			Audience:  audience,
		},
	}

	signedToken, err := jwt.Signed(s.signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign claims: %w", err)
	}

	return signedToken, nil
}

// GenerateClientIntegrationToken generates a JWT token for client-integration
// with integration ID, key ID, and service tier.
//
// This method is thread safe.
func (s *JWTSigner) GenerateClientIntegrationToken(integrationID, keyID string, tier int, expiry time.Duration, audience ...string) (string, error) {
	if integrationID == "" {
		return "", errors.New("integrationID cannot be empty")
	}
	if keyID == "" {
		return "", errors.New("keyID cannot be empty")
	}
	if len(audience) <= 0 {
		return "", errors.New("audience cannot be empty")
	}

	now := time.Now()

	claims := ClientIntegrationClaims{
		IntegrationID: integrationID,
		KeyID:         keyID,
		Tier:          tier,
		Claims: jwt.Claims{
			ID:        uuid.New().String(),
			Issuer:    Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(now.Add(expiry)),
			Audience:  audience,
		},
	}

	signedToken, err := jwt.Signed(s.signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign claims: %w", err)
	}

	return signedToken, nil
}

// GetPublicJWK returns the public key in jose.JSONWebKey format.
//
// This method is thread safe as long as the returned key is not modified.
func (s *JWTSigner) GetPublicJWK() jose.JSONWebKey {
	return s.publicJWK
}
