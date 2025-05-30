package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJWTSigner(t *testing.T) {
	// Use testdata directory for test files
	testdataDir := "testdata"

	// Test cases for file-based tests
	t.Run("valid testdata key", func(t *testing.T) {
		keyPath := filepath.Join(testdataDir, "private-key.json")
		signer, err := NewJWTSigner(keyPath)

		assert.NoError(t, err)
		assert.NotNil(t, signer)
		assert.NotNil(t, signer.signer)
		assert.NotNil(t, signer.publicJWK)
		assert.True(t, signer.publicJWK.IsPublic())
	})

	// Create a temporary directory for dynamic test files
	tmpDir, err := os.MkdirTemp("", "jwt-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Test cases
	tests := []struct {
		name        string
		keyContent  string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid EdDSA key",
			keyContent: `{
				"kty": "OKP",
				"d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
				"use": "sig",
				"crv": "Ed25519",
				"kid": "test-key-1",
				"x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				"alg": "EdDSA"
			}`,
			expectError: false,
		},
		{
			name: "missing key ID",
			keyContent: `{
				"kty": "OKP",
				"d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
				"use": "sig",
				"crv": "Ed25519",
				"x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				"alg": "EdDSA"
			}`,
			expectError: true,
			errorMsg:    "must have a 'kid'",
		},
		{
			name: "public key only",
			keyContent: `{
				"kty": "OKP",
				"use": "sig",
				"crv": "Ed25519",
				"kid": "test-key-2",
				"x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				"alg": "EdDSA"
			}`,
			expectError: true,
			errorMsg:    "is not a private key",
		},
		{
			name:        "invalid json",
			keyContent:  `invalid json content`,
			expectError: true,
			errorMsg:    "failed to unmarshal JWK",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a temporary key file
			keyPath := filepath.Join(tmpDir, "test-key.json")
			err := os.WriteFile(keyPath, []byte(tc.keyContent), 0600)
			require.NoError(t, err)

			// Test NewJWTSigner
			signer, err := NewJWTSigner(keyPath)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
				assert.Nil(t, signer)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, signer)
				assert.NotNil(t, signer.signer)
				assert.NotNil(t, signer.publicJWK)
				assert.True(t, signer.publicJWK.IsPublic())
			}
		})
	}

	// Test non-existent file
	t.Run("non-existent file", func(t *testing.T) {
		signer, err := NewJWTSigner("/non/existent/path")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read private key file")
		assert.Nil(t, signer)
	})
}

func TestGenerateToken(t *testing.T) {
	// Use the real key file from testdata
	keyPath := filepath.Join("testdata", "private-key.json")

	// Initialize a JWTSigner
	signer, err := NewJWTSigner(keyPath)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Test GenerateToken
	t.Run("valid token generation", func(t *testing.T) {
		orgID := "test-org-123"

		// Generate token
		tokenString, err := signer.GenerateToken(orgID)
		assert.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		supportedAlgs := []jose.SignatureAlgorithm{jose.EdDSA}
		token, err := jwt.ParseSigned(tokenString, supportedAlgs)
		assert.NoError(t, err)

		// Claims() verifies the signature using the public key before extracting claims
		var claims Claims
		publicKey := signer.GetPublicJWK()
		err = token.Claims(publicKey.Key, &claims)
		assert.NoError(t, err)

		// Verify claims
		assert.Equal(t, orgID, claims.Organization)
		assert.Equal(t, "token-exchange", claims.Issuer)
		assert.NotEmpty(t, claims.ID)

		// Verify time claims
		now := time.Now()
		assert.NotNil(t, claims.IssuedAt)
		assert.NotNil(t, claims.Expiry)
		assert.NotNil(t, claims.NotBefore)

		// IssuedAt should be close to now
		issuedAt := claims.IssuedAt.Time()
		assert.WithinDuration(t, now, issuedAt, 5*time.Second)

		// Expiry should be about an hour in the future
		expiry := claims.Expiry.Time()
		expectedExpiry := issuedAt.Add(time.Hour)
		assert.WithinDuration(t, expectedExpiry, expiry, 5*time.Second)

		// NotBefore should be equal to IssuedAt
		assert.Equal(t, issuedAt.Unix(), claims.NotBefore.Time().Unix())
	})

	// Test with empty organization ID
	t.Run("empty organization ID", func(t *testing.T) {
		token, err := signer.GenerateToken("")
		assert.NoError(t, err) // Should still work with empty org
		assert.NotEmpty(t, token)

		// Parse the token and verify its signature using the public key
		supportedAlgs := []jose.SignatureAlgorithm{jose.EdDSA}
		parsedToken, err := jwt.ParseSigned(token, supportedAlgs)
		assert.NoError(t, err)

		var claims Claims
		publicKey := signer.GetPublicJWK()
		err = parsedToken.Claims(publicKey.Key, &claims) // Also verifies signature
		assert.NoError(t, err)

		// Verify empty org claim
		assert.Equal(t, "", claims.Organization)
	})
}

func TestGetPublicJWK(t *testing.T) {
	// Use the real key file from testdata
	keyPath := filepath.Join("testdata", "private-key.json")

	// Initialize a JWTSigner
	signer, err := NewJWTSigner(keyPath)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Test GetPublicJWK
	publicJWK := signer.GetPublicJWK()

	// Check that it's a public key
	assert.True(t, publicJWK.IsPublic())

	// Check key properties
	assert.Equal(t, "Kd-Wp0rnXg8rxIRO1ChTbcdd0wtB8jv5_H7RoTOJvLU=", publicJWK.KeyID)
	assert.Equal(t, "sig", publicJWK.Use)
	assert.Equal(t, "EdDSA", publicJWK.Algorithm)

	// Ensure the private key part is not present
	jsonData, err := publicJWK.MarshalJSON()
	require.NoError(t, err)
	assert.NotContains(t, string(jsonData), "TI-z7vTzg24lVrLgwejEA0NrY184tP4SDq_Z9mToV5w")
}
