package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var (
	one = big.NewInt(1)
)

// PublicKey represents a Paillier public key (n).
type PublicKey struct {
	N    *big.Int // Modulus n = p * q
	N2   *big.Int // n^2, cached for performance
}

// PrivateKey represents a Paillier private key (lambda, mu).
type PrivateKey struct {
	PublicKey
	Lambda *big.Int // lcm(p-1, q-1)
	Mu     *big.Int // modular multiplicative inverse of lambda mod n
}

// GenerateKey generates a Paillier key pair with the given bit length for the modulus n.
// bits must be at least 1024.
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	if bits < 1024 {
		return nil, errors.New("paillier: bits must be at least 1024")
	}

	// 1. Choose two large prime numbers p and q
	p, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	q, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// Ensure p != q
	for p.Cmp(q) == 0 {
		q, err = rand.Prime(random, bits/2)
		if err != nil {
			return nil, err
		}
	}

	// 2. Compute n = p * q
	n := new(big.Int).Mul(p, q)
	n2 := new(big.Int).Mul(n, n)

	// 3. Compute lambda = lcm(p-1, q-1) = (p-1)*(q-1) / gcd(p-1, q-1)
	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)
	
	gcd := new(big.Int).GCD(nil, nil, pMinus1, qMinus1)
	lambda := new(big.Int).Mul(pMinus1, qMinus1)
	lambda.Div(lambda, gcd)

	// 4. Compute mu = lambda^-1 mod n
	mu := new(big.Int).ModInverse(lambda, n)
	if mu == nil {
		return nil, errors.New("paillier: failed to compute modular inverse for mu")
	}

	return &PrivateKey{
		PublicKey: PublicKey{
			N:  n,
			N2: n2,
		},
		Lambda: lambda,
		Mu:     mu,
	}, nil
}

// Encrypt encrypts a plaintext message m into a ciphertext c.
// m must be in the range [0, n).
func (pk *PublicKey) Encrypt(m *big.Int) (*big.Int, *big.Int, error) {
	if m.Sign() == -1 || m.Cmp(pk.N) >= 0 {
		return nil, nil, errors.New("paillier: message m must be in range [0, n)")
	}

	// Generate random r in [1, n-1]
	// We use [0, n-1) + 1 to get [1, n] which is close enough to [1, n-1] for large n
	// Strictly it should be gcd(r, n) = 1, but for large primes probability is negligible.
	r, err := rand.Int(rand.Reader, pk.N)
	if err != nil {
		return nil, nil, err
	}
	// Ensure r != 0
	if r.Sign() == 0 {
		r = big.NewInt(1) 
	}

	// c = (1 + n*m) * r^n mod n^2
	// Optimization: (1 + n*m) mod n^2 is just (1 + n*m) since m < n
	
	// gm = 1 + n*m
	gm := new(big.Int).Mul(pk.N, m)
	gm.Add(gm, one)
	
	// rn = r^n mod n^2
	rn := new(big.Int).Exp(r, pk.N, pk.N2)

	// c = gm * rn mod n^2
	c := new(big.Int).Mul(gm, rn)
	c.Mod(c, pk.N2)

	return c, r, nil
}

// EncryptWithR encrypts a plaintext message m using a specific randomness r.
// This is useful for Zero-Knowledge Proofs.
func (pk *PublicKey) EncryptWithR(m, r *big.Int) (*big.Int, error) {
	if m.Sign() == -1 || m.Cmp(pk.N) >= 0 {
		return nil, errors.New("paillier: message m must be in range [0, n)")
	}

	// gm = 1 + n*m
	gm := new(big.Int).Mul(pk.N, m)
	gm.Add(gm, one)

	// rn = r^n mod n^2
	rn := new(big.Int).Exp(r, pk.N, pk.N2)

	// c = gm * rn mod n^2
	c := new(big.Int).Mul(gm, rn)
	c.Mod(c, pk.N2)

	return c, nil
}

// Decrypt decrypts a ciphertext c into a plaintext message m.
func (priv *PrivateKey) Decrypt(c *big.Int) (*big.Int, error) {
	if c.Sign() == -1 || c.Cmp(priv.N2) >= 0 {
		return nil, errors.New("paillier: ciphertext c must be in range [0, n^2)")
	}

	// m = L(c^lambda mod n^2) * mu mod n
	// where L(x) = (x-1)/n

	// u = c^lambda mod n^2
	u := new(big.Int).Exp(c, priv.Lambda, priv.N2)

	// L(u) = (u - 1) / n
	l := new(big.Int).Sub(u, one)
	l.Div(l, priv.N)

	// m = l * mu mod n
	m := new(big.Int).Mul(l, priv.Mu)
	m.Mod(m, priv.N)

	return m, nil
}

// Add performs homomorphic addition of two ciphertexts.
// E(m1) + E(m2) = E(m1 + m2)
// c = c1 * c2 mod n^2
func (pk *PublicKey) Add(c1, c2 *big.Int) *big.Int {
	c := new(big.Int).Mul(c1, c2)
	c.Mod(c, pk.N2)
	return c
}

// Mul performs homomorphic multiplication of a ciphertext by a scalar.
// E(m) * k = E(m * k)
// c = c1^k mod n^2
func (pk *PublicKey) Mul(c1, k *big.Int) *big.Int {
	c := new(big.Int).Exp(c1, k, pk.N2)
	return c
}

// EncryptWithNonce encrypts a message m using a specific random nonce r.
// This is useful for Zero-Knowledge Proofs where r needs to be kept.
func (pk *PublicKey) EncryptWithNonce(m, r *big.Int) (*big.Int, error) {
	if m.Sign() == -1 || m.Cmp(pk.N) >= 0 {
		return nil, errors.New("paillier: message m must be in range [0, n)")
	}
	
	// c = (1 + n*m) * r^n mod n^2
	
	gm := new(big.Int).Mul(pk.N, m)
	gm.Add(gm, one)
	
	rn := new(big.Int).Exp(r, pk.N, pk.N2)

	c := new(big.Int).Mul(gm, rn)
	c.Mod(c, pk.N2)

	return c, nil
}

// ValidateCiphertext checks if a ciphertext is valid (in range [0, n^2) and coprime to n^2).
// Note: Checking coprimality is expensive and usually not strictly required if inputs are trusted or ZKPs are used.
// Here we just check the range.
func (pk *PublicKey) ValidateCiphertext(c *big.Int) error {
	if c.Sign() == -1 || c.Cmp(pk.N2) >= 0 {
		return fmt.Errorf("paillier: ciphertext out of range")
	}
	return nil
}
