package curves

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Curve defines the interface for elliptic curve operations needed by TSS.
type Curve interface {
	// Params returns the curve parameters (Order, etc.)
	Params() *elliptic.CurveParams

	// NewScalar generates a random scalar in Z_q
	NewScalar() (*big.Int, error)

	// ScalarMult computes k * G (base point multiplication)
	ScalarBaseMult(k *big.Int) (*big.Int, *big.Int)

	// ScalarMult computes k * P
	ScalarMult(Px, Py, k *big.Int) (*big.Int, *big.Int)

	// Add combines two points
	Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int)
}

type Secp256k1 struct{}

func (c *Secp256k1) Params() *elliptic.CurveParams {
	return secp256k1.S256().Params()
}

func (c *Secp256k1) NewScalar() (*big.Int, error) {
	params := c.Params()
	// Generate random integer in [0, N-1]
	k, err := rand.Int(rand.Reader, params.N)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (c *Secp256k1) ScalarBaseMult(k *big.Int) (*big.Int, *big.Int) {
	return secp256k1.S256().ScalarBaseMult(k.Bytes())
}

func (c *Secp256k1) ScalarMult(Px, Py, k *big.Int) (*big.Int, *big.Int) {
	return secp256k1.S256().ScalarMult(Px, Py, k.Bytes())
}

func (c *Secp256k1) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	return secp256k1.S256().Add(x1, y1, x2, y2)
}

// NewSecp256k1 returns a new instance of the Secp256k1 curve wrapper
func NewSecp256k1() Curve {
	return &Secp256k1{}
}
