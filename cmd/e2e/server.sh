#!/bin/bash

# Generate a self-signed certificate and private key
TMP=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -keyout "${TMP}/key.pem" -out "${TMP}/cert.pem" -days 365 -nodes -subj "/CN=localhost"

echo "Starting server on port 4433"
echo "Use Ctrl+C to stop the server"

# Start the OpenSSL server
openssl s_server -cert "${TMP}/cert.pem" -key "${TMP}/key.pem" -accept 4433 -quiet | {
    while IFS= read -r line; do
        echo "$line"
    done
}

# Clean up certificate files
rm -rf "${TMP}"
