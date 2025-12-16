package curves

import (
	"crypto/rand"
	"math/big"

	"filippo.io/edwards25519"
)

type Ed25519Curve struct{}

func (c *Ed25519Curve) Name() string {
	return "Ed25519"
}

func (c *Ed25519Curve) Order() *big.Int {
	// l = 2^252 + 27742317777372353535851937790883648493
	s, _ := new(big.Int).SetString("72370055773322622139731865630429942408571163593799076060019509382854542509893", 10)
	return s
}

func (c *Ed25519Curve) NewScalar() (Scalar, error) {
	var b [64]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return nil, err
	}
	
	s, err := edwards25519.NewScalar().SetUniformBytes(b[:])
	if err != nil {
		return nil, err
	}
	return &Ed25519Scalar{s: s}, nil
}

func (c *Ed25519Curve) NewScalarFromBigInt(n *big.Int) Scalar {
	// edwards25519.Scalar doesn't have SetBigInt directly, need bytes.
	// We need to be careful with endianness. edwards25519 uses little-endian.
	// big.Int.Bytes() is big-endian.
	
	bytes := n.Bytes()
	// Pad to 32 bytes
	if len(bytes) > 32 {
		// Modulo order?
		n = new(big.Int).Mod(n, c.Order())
		bytes = n.Bytes()
	}
	
	var buf [32]byte
	// Reverse bytes for little-endian
	for i := 0; i < len(bytes); i++ {
		buf[len(bytes)-1-i] = bytes[i]
	}
	
	s, _ := edwards25519.NewScalar().SetCanonicalBytes(buf[:])
	return &Ed25519Scalar{s: s}
}

func (c *Ed25519Curve) BasePoint() Point {
	return &Ed25519Point{p: edwards25519.NewGeneratorPoint()}
}

func (c *Ed25519Curve) NewPointFromBytes(b []byte) (Point, error) {
	p, err := edwards25519.NewIdentityPoint().SetBytes(b)
	if err != nil {
		return nil, err
	}
	return &Ed25519Point{p: p}, nil
}

// Ed25519Scalar implements Scalar
type Ed25519Scalar struct {
	s *edwards25519.Scalar
}

func (s *Ed25519Scalar) Bytes() []byte {
	return s.s.Bytes()
}

func (s *Ed25519Scalar) BigInt() *big.Int {
	b := s.s.Bytes()
	// Convert little-endian bytes to big.Int (big-endian)
	var buf []byte
	for i := len(b) - 1; i >= 0; i-- {
		buf = append(buf, b[i])
	}
	return new(big.Int).SetBytes(buf)
}

func (s *Ed25519Scalar) Add(other Scalar) Scalar {
	o, ok := other.(*Ed25519Scalar)
	if !ok { panic("type mismatch") }
	res := edwards25519.NewScalar().Add(s.s, o.s)
	return &Ed25519Scalar{s: res}
}

func (s *Ed25519Scalar) Mul(other Scalar) Scalar {
	o, ok := other.(*Ed25519Scalar)
	if !ok { panic("type mismatch") }
	res := edwards25519.NewScalar().Multiply(s.s, o.s)
	return &Ed25519Scalar{s: res}
}

func (s *Ed25519Scalar) Invert() Scalar {
	res := edwards25519.NewScalar().Invert(s.s)
	return &Ed25519Scalar{s: res}
}

// Ed25519Point implements Point
type Ed25519Point struct {
	p *edwards25519.Point
}

func (p *Ed25519Point) Bytes() []byte {
	return p.p.Bytes()
}

func (p *Ed25519Point) Add(other Point) Point {
	o, ok := other.(*Ed25519Point)
	if !ok { panic("type mismatch") }
	res := edwards25519.NewIdentityPoint().Add(p.p, o.p)
	return &Ed25519Point{p: res}
}

func (p *Ed25519Point) ScalarMult(scalar Scalar) Point {
	s, ok := scalar.(*Ed25519Scalar)
	if !ok { panic("type mismatch") }
	res := edwards25519.NewIdentityPoint().ScalarMult(s.s, p.p)
	return &Ed25519Point{p: res}
}
