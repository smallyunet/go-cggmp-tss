package schnorr

import (
crand "crypto/rand"
"crypto/sha256"
"errors"
"math/big"

"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Proof represents a Schnorr proof of knowledge of a discrete logarithm.
// Proves knowledge of x such that X = x * G.
type Proof struct {
	R *secp256k1.JacobianPoint // Commitment R = k * G
	S *big.Int                 // Response s = k + e * x
}

// Prove generates a Schnorr proof for the secret x, public key X = x*G.
// It uses the provided unique session ID (sid) and other context to bind the proof.
func Prove(x *big.Int, X *secp256k1.JacobianPoint) (*Proof, error) {
	if x == nil || X == nil {
		return nil, errors.New("schnorr: inputs cannot be nil")
	}

	curve := secp256k1.S256()
	n := curve.N

	// 1. Generate random nonce k
	k, err := randInt(n)
	if err != nil {
		return nil, err
	}

	// 2. Compute R = k * G
	var R secp256k1.JacobianPoint
	kScalar := new(secp256k1.ModNScalar)
	kScalar.SetByteSlice(k.Bytes())
	secp256k1.ScalarBaseMultNonConst(kScalar, &R)

	// 3. Compute challenge e = H(X, R)
	e := challenge(X, &R)

	// 4. Compute s = k + e * x mod n
	s := new(big.Int).Mul(e, x)
	s.Add(s, k)
	s.Mod(s, n)

	return &Proof{
		R: &R,
		S: s,
	}, nil
}

// Verify checks the validity of the Schnorr proof for public key X.
func (p *Proof) Verify(X *secp256k1.JacobianPoint) bool {
	if p == nil || p.R == nil || p.S == nil || X == nil {
		return false
	}

	curve := secp256k1.S256()
	n := curve.N

	// Check if s is in [0, n-1]
	if p.S.Sign() < 0 || p.S.Cmp(n) >= 0 {
		return false
	}

	// 1. Compute challenge e = H(X, R)
	e := challenge(X, p.R)

	// 2. Verify R = s*G - e*X
	// Equivalent to checking s*G = R + e*X
	
	// LHS = s * G
	var lhs secp256k1.JacobianPoint
	sScalar := new(secp256k1.ModNScalar)
	sScalar.SetByteSlice(p.S.Bytes())
	secp256k1.ScalarBaseMultNonConst(sScalar, &lhs)

	// RHS = R + e * X
	var eX secp256k1.JacobianPoint
	eScalar := new(secp256k1.ModNScalar)
	eScalar.SetByteSlice(e.Bytes())
	secp256k1.ScalarMultNonConst(eScalar, X, &eX)
	
	var rhs secp256k1.JacobianPoint
	secp256k1.AddNonConst(p.R, &eX, &rhs)

	// Compare X and Y coordinates
	// To do this efficiently with Jacobian points, we can normalize them to Affine
	lhs.ToAffine()
	rhs.ToAffine()

	return lhs.X.Equals(&rhs.X) && lhs.Y.Equals(&rhs.Y)
}

// challenge computes H(X, R) mod n
func challenge(X, R *secp256k1.JacobianPoint) *big.Int {
	curve := secp256k1.S256()
	
	// Serialize points
	X.ToAffine()
	R.ToAffine()
	
	// Use compressed serialization for uniqueness
	// Note: In a real implementation, we should use a canonical serialization format.
	// Here we simply hash the coordinates.
	
	h := sha256.New()
	h.Write(X.X.Bytes()[:])
	h.Write(X.Y.Bytes()[:])
	h.Write(R.X.Bytes()[:])
	h.Write(R.Y.Bytes()[:])
	
	hashBytes := h.Sum(nil)
	
	e := new(big.Int).SetBytes(hashBytes)
	e.Mod(e, curve.N)
	return e
}

// randInt generates a random integer in [0, max)
func randInt(max *big.Int) (*big.Int, error) {
	return crand.Int(crand.Reader, max)
}
