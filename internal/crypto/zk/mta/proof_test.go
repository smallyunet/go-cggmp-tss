package mta

import (
"crypto/rand"
"math/big"
"testing"

"github.com/decred/dcrd/dcrec/secp256k1/v4"
"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
)

func TestMtaProof(t *testing.T) {
	// 1. Setup Paillier (Receiver)
	receiverPriv, _ := paillier.GenerateKey(rand.Reader, 1024)
	receiverPk := &receiverPriv.PublicKey

	// 2. Setup Secrets (Prover)
	x, _ := rand.Int(rand.Reader, secp256k1.S256().N)
	beta, _ := rand.Int(rand.Reader, receiverPk.N)
	r, _ := rand.Int(rand.Reader, receiverPk.N)

	// 3. Public Inputs
	// A = E(a) (Receiver encrypts a)
	a := big.NewInt(42)
	A, _, _ := receiverPk.Encrypt(a)

	// X = x * G
	var X secp256k1.JacobianPoint
	xScalar := new(secp256k1.ModNScalar)
	xScalar.SetByteSlice(x.Bytes())
	secp256k1.ScalarBaseMultNonConst(xScalar, &X)

	// C = A^x * E(beta)
	Ax := new(big.Int).Exp(A, x, receiverPk.N2)
	E_beta, _ := receiverPk.EncryptWithNonce(beta, r)
	C := new(big.Int).Mul(Ax, E_beta)
	C.Mod(C, receiverPk.N2)

	// 4. Prove
	proof, err := Prove(receiverPk, A, x, beta, r, &X)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// 5. Verify
	if !proof.Verify(receiverPk, A, C, &X) {
		t.Fatal("Verify failed")
	}
}
