package curves

import (
	"math/big"
)

// Point represents a point on an elliptic curve.
// It abstracts away the underlying coordinate system (Affine, Jacobian, Edwards).
type Point interface {
	// Bytes returns the compressed serialization of the point.
	Bytes() []byte
	
	// Add adds this point to another point.
	Add(p Point) Point
	
	// ScalarMult multiplies this point by a scalar.
	ScalarMult(s Scalar) Point
}

// Scalar represents a scalar value in the curve's scalar field.
type Scalar interface {
	// Bytes returns the serialization of the scalar.
	Bytes() []byte
	
	// BigInt returns the scalar as a big integer.
	BigInt() *big.Int
	
	// Add adds this scalar to another scalar.
	Add(s Scalar) Scalar
	
	// Mul multiplies this scalar by another scalar.
	Mul(s Scalar) Scalar
	
	// Invert returns the modular inverse of the scalar.
	Invert() Scalar
}

// CurveV2 is the proposed new interface for supporting multiple curve types.
type CurveV2 interface {
	// Name returns the name of the curve.
	Name() string
	
	// NewScalar generates a random scalar.
	NewScalar() (Scalar, error)
	
	// NewScalarFromBigInt creates a scalar from a big integer.
	NewScalarFromBigInt(n *big.Int) Scalar
	
	// NewPointFromBytes deserializes a point.
	NewPointFromBytes(b []byte) (Point, error)
	
	// BasePoint returns the generator point G.
	BasePoint() Point
	
	// Order returns the order of the base point (group order).
	Order() *big.Int
}
