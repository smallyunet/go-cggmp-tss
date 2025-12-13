package schnorr

import (
"crypto/rand"
"math/big"
"testing"

"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestSchnorrProof(t *testing.T) {
	curve := secp256k1.S256()
	n := curve.N

	// 1. Generate a random secret x
	x, err := rand.Int(rand.Reader, n)
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	// 2. Compute public key X = x * G
	var X secp256k1.JacobianPoint
	xScalar := new(secp256k1.ModNScalar)
	xScalar.SetByteSlice(x.Bytes())
	secp256k1.ScalarBaseMultNonConst(xScalar, &X)

	// 3. Generate Proof
	proof, err := Prove(x, &X)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// 4. Verify Proof
	if !proof.Verify(&X) {
		t.Fatal("Verify failed for valid proof")
	}
}

func TestSchnorrProofInvalid(t *testing.T) {
	curve := secp256k1.S256()
	n := curve.N

	// 1. Generate a random secret x
	x, _ := rand.Int(rand.Reader, n)
	
	// 2. Compute public key X = x * G
	var X secp256k1.JacobianPoint
	xScalar := new(secp256k1.ModNScalar)
	xScalar.SetByteSlice(x.Bytes())
	secp256k1.ScalarBaseMultNonConst(xScalar, &X)

	// 3. Generate Proof
	proof, _ := Prove(x, &X)

	// 4. Tamper with the proof
	// Case A: Modify s
	proof.S.Add(proof.S, big.NewInt(1))
	if proof.Verify(&X) {
		t.Fatal("Verify passed for tampered s")
	}

	// Case B: Modify R
	// We need to modify R to be a valid point but different
	// Let's just double it
secp256k1.DoubleNonConst(proof.R, proof.R)

// Restore s (it was modified in Case A)
proof.S.Sub(proof.S, big.NewInt(1))

if proof.Verify(&X) {
t.Fatal("Verify passed for tampered R")
}
}
