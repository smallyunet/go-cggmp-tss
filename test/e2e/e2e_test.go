package e2e

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
)

func TestCryptoIntegration(t *testing.T) {
	// Simulate 3 parties
	nParties := 3
	keys := make([]*paillier.PrivateKey, nParties)

	// 1. Key Generation Phase
	for i := 0; i < nParties; i++ {
		key, err := paillier.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("Party %d failed to generate key: %v", i, err)
		}
		keys[i] = key
	}

	// 2. Communication Phase (Simulated)
	// Party 0 sends encrypted message to Party 1
	msg := big.NewInt(12345)
	
	// Party 0 encrypts using Party 1's public key
	c, _, err := keys[1].PublicKey.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Party 1 receives and decrypts
	decrypted, err := keys[1].Decrypt(c)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if msg.Cmp(decrypted) != 0 {
		t.Errorf("Decrypted message does not match original. Got %s, want %s", decrypted, msg)
	}

	// 3. Homomorphic Operation Phase
	// Party 2 sends encrypted '10' to Party 1
	val2 := big.NewInt(10)
	c2, _, err := keys[1].PublicKey.Encrypt(val2)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Party 1 adds the two ciphertexts: Enc(12345) + Enc(10) = Enc(12355)
	cSum := keys[1].PublicKey.Add(c, c2)

	// Party 1 decrypts the sum
	decryptedSum, err := keys[1].Decrypt(cSum)
	if err != nil {
		t.Fatalf("Decryption of sum failed: %v", err)
	}

	expectedSum := new(big.Int).Add(msg, val2)
	if expectedSum.Cmp(decryptedSum) != 0 {
		t.Errorf("Homomorphic addition failed. Got %s, want %s", decryptedSum, expectedSum)
	}
}
