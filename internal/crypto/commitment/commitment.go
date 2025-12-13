package commitment

import (
"crypto/rand"
"crypto/sha256"
"math/big"
)

// Commitment represents the output of a commitment scheme.
// C = H(msg, salt)
type Commitment struct {
	C []byte // The commitment value (hash)
	D []byte // The decommitment value (salt/randomness)
}

// New implements a simple SHA-256 based commitment scheme.
// It commits to a message `data` using a random `salt`.
// Returns the commitment hash C and the random salt D.
func New(data []byte) (*Commitment, error) {
	// 1. Generate random salt (32 bytes for security)
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	// 2. Compute C = SHA256(salt || data)
	// Note: The order (salt || data) or (data || salt) matters.
	// We use salt || data to prevent length extension attacks if data is variable length,
	// though SHA256 is resistant.
	hash := sha256.New()
	hash.Write(salt)
	hash.Write(data)
	c := hash.Sum(nil)

	return &Commitment{
		C: c,
		D: salt,
	}, nil
}

// Verify checks if the provided commitment C matches the message data and decommitment salt D.
func Verify(c []byte, d []byte, data []byte) bool {
	if len(c) != 32 || len(d) != 32 {
		return false
	}

	// Recompute hash
	hash := sha256.New()
	hash.Write(d)
	hash.Write(data)
	computedC := hash.Sum(nil)

	// Constant time comparison is preferred for security, though for public commitments
	// standard comparison is often acceptable. We use standard bytes.Equal here.
	// For high security, use subtle.ConstantTimeCompare.
	return string(computedC) == string(c)
}

// NewComplex commits to a list of big.Ints or other data structures by serializing them first.
// This is a helper for committing to protocol messages.
func NewComplex(parts ...[]byte) (*Commitment, error) {
	// Concatenate all parts
	var data []byte
	for _, p := range parts {
		data = append(data, p...)
	}
	return New(data)
}

// VerifyComplex verifies a commitment against a list of parts.
func VerifyComplex(c []byte, d []byte, parts ...[]byte) bool {
	var data []byte
	for _, p := range parts {
		data = append(data, p...)
	}
	return Verify(c, d, data)
}

// IntToBytes is a helper to convert big.Int to bytes for commitment.
func IntToBytes(i *big.Int) []byte {
	if i == nil {
		return []byte{}
	}
	return i.Bytes()
}
