package polynomial

import (
	"math/big"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/curves"
)

// Polynomial represents a polynomial f(x) = a_0 + a_1*x + ... + a_t*x^t
// over the scalar field of the curve.
type Polynomial struct {
	Coefficients []*big.Int
	Curve        curves.Curve
}

// New generates a random polynomial of given degree with the constant term (secret) provided.
// If secret is nil, a random constant term is generated.
func New(curve curves.Curve, degree int, secret *big.Int) (*Polynomial, error) {
	coeffs := make([]*big.Int, degree+1)
	var err error

	// a_0 is the secret
	if secret == nil {
		coeffs[0], err = curve.NewScalar()
		if err != nil {
			return nil, err
		}
	} else {
		coeffs[0] = new(big.Int).Set(secret)
	}

	// Generate random coefficients a_1 ... a_t
	for i := 1; i <= degree; i++ {
		coeffs[i], err = curve.NewScalar()
		if err != nil {
			return nil, err
		}
	}

	return &Polynomial{
		Coefficients: coeffs,
		Curve:        curve,
	}, nil
}

// Evaluate calculates f(x) mod q
func (p *Polynomial) Evaluate(x *big.Int) *big.Int {
	// Horner's method
	// result = a_t
	// for i = t-1 down to 0:
	//   result = result * x + a_i
	
	q := p.Curve.Params().N
	degree := len(p.Coefficients) - 1
	result := new(big.Int).Set(p.Coefficients[degree])

	for i := degree - 1; i >= 0; i-- {
		result.Mul(result, x)
		result.Add(result, p.Coefficients[i])
		result.Mod(result, q)
	}

	return result
}

// EvaluateMulti calculates f(x) for multiple x values
func (p *Polynomial) EvaluateMulti(xs []*big.Int) []*big.Int {
	results := make([]*big.Int, len(xs))
	for i, x := range xs {
		results[i] = p.Evaluate(x)
	}
	return results
}
