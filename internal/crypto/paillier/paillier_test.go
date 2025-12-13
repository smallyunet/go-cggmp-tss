package paillier

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if priv.N.BitLen() < 1023 { // Allow slight variance
		t.Errorf("Expected modulus bit length ~1024, got %d", priv.N.BitLen())
	}
	if priv.N2.Cmp(new(big.Int).Mul(priv.N, priv.N)) != 0 {
		t.Errorf("N2 is not N*N")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	msg := big.NewInt(123456789)
	c, _, err := priv.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := priv.Decrypt(c)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if msg.Cmp(decrypted) != 0 {
		t.Errorf("Decryption failed. Expected %s, got %s", msg, decrypted)
	}
}

func TestHomomorphicAdd(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	m1 := big.NewInt(100)
	m2 := big.NewInt(200)
	expected := big.NewInt(300)

	c1, _, _ := priv.Encrypt(m1)
	c2, _, _ := priv.Encrypt(m2)

	cSum := priv.Add(c1, c2)

	decryptedSum, err := priv.Decrypt(cSum)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if expected.Cmp(decryptedSum) != 0 {
		t.Errorf("Homomorphic add failed. Expected %s, got %s", expected, decryptedSum)
	}
}

func TestHomomorphicMul(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	m := big.NewInt(50)
	k := big.NewInt(3)
	expected := big.NewInt(150)

	c, _, _ := priv.Encrypt(m)

	cProd := priv.Mul(c, k)

	decryptedProd, err := priv.Decrypt(cProd)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if expected.Cmp(decryptedProd) != 0 {
		t.Errorf("Homomorphic mul failed. Expected %s, got %s", expected, decryptedProd)
	}
}

func TestEncryptWithNonce(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	msg := big.NewInt(999)
	r, _ := rand.Int(rand.Reader, priv.N)

	c, err := priv.EncryptWithNonce(msg, r)
	if err != nil {
		t.Fatalf("EncryptWithNonce failed: %v", err)
	}

	decrypted, err := priv.Decrypt(c)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if msg.Cmp(decrypted) != 0 {
		t.Errorf("Decryption failed. Expected %s, got %s", msg, decrypted)
	}
}
