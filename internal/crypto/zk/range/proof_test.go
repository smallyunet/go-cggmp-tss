package range_proof

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
)

func TestRangeProof(t *testing.T) {
	// 1. Generate Paillier Key
	sk, err := paillier.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pk := &sk.PublicKey

	// 2. Encrypt a value x
	x := big.NewInt(42)
	r, err := rand.Int(rand.Reader, pk.N)
	if err != nil {
		t.Fatal(err)
	}
	C, err := pk.EncryptWithR(x, r)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Generate Proof
	proof, err := Prove(pk, C, x, r, 256)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// 4. Verify Proof
	if !proof.Verify(pk, C, 256) {
		t.Fatal("Verify failed")
	}
}
