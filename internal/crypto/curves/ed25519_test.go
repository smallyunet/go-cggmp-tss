package curves

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEd25519Scalar(t *testing.T) {
	curve := &Ed25519Curve{}
	
	// Test NewScalar
	s1, err := curve.NewScalar()
	assert.NoError(t, err)
	assert.NotNil(t, s1)
	
	// Test NewScalarFromBigInt
	val := big.NewInt(12345)
	s2 := curve.NewScalarFromBigInt(val)
	assert.Equal(t, val, s2.BigInt())
	
	// Test Add
	s3 := s2.Add(s2)
	assert.Equal(t, big.NewInt(24690), s3.BigInt())
	
	// Test Mul
	s4 := s2.Mul(s2)
	expected := new(big.Int).Mul(val, val)
	assert.Equal(t, expected, s4.BigInt())
	
	// Test Invert
	s5 := s2.Invert()
	s6 := s5.Mul(s2)
	assert.Equal(t, big.NewInt(1), s6.BigInt())
}

func TestEd25519Point(t *testing.T) {
	curve := &Ed25519Curve{}
	
	// Test BasePoint
	g := curve.BasePoint()
	assert.NotNil(t, g)
	
	// Test ScalarMult
	s := curve.NewScalarFromBigInt(big.NewInt(2))
	p2 := g.ScalarMult(s)
	
	// Test Add
	p3 := g.Add(g)
	assert.Equal(t, p2.Bytes(), p3.Bytes())
	
	// Test NewPointFromBytes
	bytes := p2.Bytes()
	p4, err := curve.NewPointFromBytes(bytes)
	assert.NoError(t, err)
	assert.Equal(t, p2.Bytes(), p4.Bytes())
}
