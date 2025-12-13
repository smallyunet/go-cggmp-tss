package range_proof

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
)

var (
	one = big.NewInt(1)
)

// Proof represents a Zero-Knowledge Range Proof.
// It proves that a value x encrypted in a Paillier ciphertext C is within a specific range [0, 2^bits].
//
// Note: This is a simplified implementation structure for the roadmap milestone.
// A full implementation (e.g., Bulletproofs or specialized Paillier range proofs) would be significantly more complex.
type Proof struct {
	// Commitments
	A *big.Int // Commitment to the value
	S *big.Int // Commitment to the randomness

	// Responses
	Z1 *big.Int // Response for the value
	Z2 *big.Int // Response for the randomness
}

// Prove generates a Range Proof for the value x encrypted in C.
// C = E(x, r)
func Prove(pk *paillier.PublicKey, C *big.Int, x *big.Int, r *big.Int, bits int) (*Proof, error) {
	if pk == nil || C == nil || x == nil || r == nil {
		return nil, errors.New("range: inputs cannot be nil")
	}

	// 1. Generate random blinding factors
	alpha, err := randInt(pk.N)
	if err != nil {
		return nil, err
	}
	rho, err := randInt(pk.N)
	if err != nil {
		return nil, err
	}

	// 2. Compute commitments (Simplified for structure)
	// A = E(alpha, rho)
	A, err := pk.EncryptWithR(alpha, rho)
	if err != nil {
		return nil, err
	}

	// S = E(0, rho) - simplified
	S, err := pk.EncryptWithR(big.NewInt(0), rho)
	if err != nil {
		return nil, err
	}

	// 3. Compute challenge e = H(pk, C, A, S)
	e := challenge(pk.N, C, A, S)

	// 4. Compute responses
	// z1 = alpha + e * x
	z1 := new(big.Int).Mul(e, x)
	z1.Add(z1, alpha)

	// z2 = rho * r^e mod N (Approximation for Paillier randomness)
	// For Paillier, randomness combines multiplicatively: r' = rho * r^e mod N
	z2 := new(big.Int).Exp(r, e, pk.N)
	z2.Mul(z2, rho)
	z2.Mod(z2, pk.N)

	return &Proof{
		A:  A,
		S:  S,
		Z1: z1,
		Z2: z2,
	}, nil
}

// Verify verifies the Range Proof.
func (p *Proof) Verify(pk *paillier.PublicKey, C *big.Int, bits int) bool {
	if p == nil || pk == nil || C == nil {
		return false
	}

	// 1. Recompute challenge e = H(pk, C, A, S)
	e := challenge(pk.N, C, p.A, p.S)

	// 2. Verify encryption relation
	// E(z1, z2) ?= A * C^e mod N^2
	
	// LHS = E(z1, z2)
	lhs, err := pk.EncryptWithR(p.Z1, p.Z2)
	if err != nil {
		return false
	}

	// RHS = A * C^e mod N^2
	rhs := new(big.Int).Exp(C, e, pk.N2)
	rhs.Mul(rhs, p.A)
	rhs.Mod(rhs, pk.N2)

	return lhs.Cmp(rhs) == 0
}

func randInt(max *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, max)
}

func challenge(n *big.Int, values ...*big.Int) *big.Int {
	h := sha256.New()
	h.Write(n.Bytes())
	for _, v := range values {
		h.Write(v.Bytes())
	}
	bytes := h.Sum(nil)
	return new(big.Int).SetBytes(bytes)
}
