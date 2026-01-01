#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "Building WASM binary..."
GOOS=js GOARCH=wasm go build -o main.wasm ../../cmd/wasm/main.go

echo "Copying wasm_exec.js..."
# Try obtaining wasm_exec.js from GOROOT
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .

echo "Done. Open index.html in a browser."
