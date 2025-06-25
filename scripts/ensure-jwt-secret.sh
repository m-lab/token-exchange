#!/bin/bash

set -euo pipefail

# Configuration
SECRET_NAME="auth-private-key"
PROJECT_ID="${PROJECT_ID:-mlab-sandbox}"
TEMP_DIR=$(mktemp -d)

# Cleanup function
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Function to check if secret exists
secret_exists() {
    gcloud secrets describe "$SECRET_NAME" --project="$PROJECT_ID" >/dev/null 2>&1
}

# Function to generate RSA key pair in JWK format using jose-util
generate_jwk_keypair() {
    local target_private_file="$1"

    # Change to temp directory since jose-util creates files in current directory
    cd "$TEMP_DIR"

    # Generate RSA key using jose-util
    jose-util generate-key --use sig --alg RS256

    # Find the generated private key file
    local generated_private_file
    generated_private_file=$(find . -name "jwk-sig-*-priv.json" -type f | head -1)

    if [[ -z "$generated_private_file" ]]; then
        echo "Error: jose-util did not create expected private key file"
        exit 1
    fi

    # Move the generated file to our target location
    mv "$generated_private_file" "$target_private_file"

    echo "Generated private key file: $generated_private_file -> $target_private_file"

    # Clean up the public key file
    rm -f jwk-sig-*-pub.json

    # Return to original directory
    cd - > /dev/null
}

# Function to create secret and upload key
create_secret_with_key() {
    local private_key_file="$1"

    echo "Creating secret '$SECRET_NAME' and uploading private key..."

    # Create the secret with the private key as the first version
    gcloud secrets create "$SECRET_NAME" \
        --project="$PROJECT_ID" \
        --data-file="$private_key_file"

    echo "Secret '$SECRET_NAME' created successfully"
}

main() {
    echo "Checking if secret '$SECRET_NAME' exists in project '$PROJECT_ID'..."

    if secret_exists; then
        echo "Secret '$SECRET_NAME' already exists. Nothing to do."
        exit 0
    fi

    echo "Secret '$SECRET_NAME' does not exist. Generating new RSA key pair..."

    # Generate the key pair
    PRIVATE_KEY_FILE="$TEMP_DIR/private-key.json"
    generate_jwk_keypair "$PRIVATE_KEY_FILE"

    # Extract kid from generated key for logging
    KID=$(cat "$PRIVATE_KEY_FILE" | grep -o '"kid":"[^"]*"' | cut -d'"' -f4)
    echo "Generated RSA key pair with kid: $KID"

    # Create secret and upload private key
    create_secret_with_key "$PRIVATE_KEY_FILE"

    echo "JWT signing secret setup completed successfully!"
    echo "Key ID: $KID"
}

# Verify dependencies
if ! command -v jose-util &> /dev/null; then
    echo "Error: jose-util is required but not installed"
    echo "Install with: go install github.com/go-jose/go-jose/v4/jose-util@latest"
    exit 1
fi

if ! command -v gcloud &> /dev/null; then
    echo "Error: gcloud CLI is required but not installed"
    exit 1
fi

# Run main function
main "$@"
