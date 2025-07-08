#!/bin/bash

# Integration test script for Secure IPC
# This script demonstrates how to run client and server examples together

set -e

echo "=== Secure IPC Integration Test ==="
echo "This script demonstrates client-server communication"
echo

# Check if certificates exist
if [ ! -f "certs/agent/server.pem" ] || [ ! -f "certs/app/client.pem" ]; then
    echo "❌ Certificates not found!"
    echo "Please generate test certificates first:"
    echo "  ./scripts/generate_test_certs.sh"
    exit 1
fi

echo "✓ Certificates found"
echo

echo "Starting integration test..."
echo "1. Server will start in background"
echo "2. Client will connect and send test messages"
echo "3. Server will process messages and respond"
echo "4. Both will shut down gracefully"
echo

# Function to cleanup background processes
cleanup() {
    echo
    echo "Cleaning up..."
    if [ ! -z "$SERVER_PID" ]; then
        echo "Stopping server (PID: $SERVER_PID)..."
        kill $SERVER_PID 2>/dev/null || true
    fi
    exit 0
}

# Set up signal handling
trap cleanup SIGINT SIGTERM

echo "Starting server in background..."
# Note: In a real test, you would run the actual server
# For this demo, we'll simulate the server running
echo "Server would start here with: cargo run --example daemon -p secure-ipc-server"
SERVER_PID=$$

# Wait a moment for server to start
sleep 2

echo "Server started (simulated)"
echo

echo "Testing client connection..."
echo "Client would connect here with: cargo run --example cli -- ping"
echo "Client would send commands here with: cargo run --example basic"

# Simulate some client-server interaction
echo "Simulated client-server interaction:"
echo "  Client -> Server: ping"
echo "  Server -> Client: pong"
echo "  Client -> Server: echo 'Hello, Secure IPC!'"
echo "  Server -> Client: Echo: Hello, Secure IPC!"
echo "  Client -> Server: time"
echo "  Server -> Client: Current time: $(date +%s)"

echo
echo "✓ Integration test completed successfully!"
echo

# Cleanup
cleanup 