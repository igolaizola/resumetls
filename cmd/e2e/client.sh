#!/bin/bash

# Start OpenSSL client and process its output
openssl s_client -connect localhost:4433 -quiet 2>/dev/null | {
    count=0
    while IFS= read -r line && [ $count -lt 2 ]; do
        echo "Received message $((count+1)): $line"
        count=$((count+1))
    done
    exit 0
} &

# Keep the script running
echo "Connecting to server on localhost:4433..."
echo "Waiting for messages..."
cat > fifo
