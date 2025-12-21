package polynomial

import (
	"math/big"
	"testing"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/curves"
)

func TestNew(t *testing.T) {
	curve := curves.NewSecp256k1()

	t.Run("with random secret", func(t *testing.T) {
		poly, err := New(curve, 2, nil)
		if err != nil {
			t.Fatalf("Failed to create polynomial: %v", err)
		}

		if len(poly.Coefficients) != 3 {
			t.Errorf("Expected 3 coefficients for degree 2, got %d", len(poly.Coefficients))
		}

		// All coefficients should be non-nil and within range
		for i, c := range poly.Coefficients {
			if c == nil {
				t.Errorf("Coefficient %d is nil", i)
			}
			if c.Cmp(curve.Params().N) >= 0 {
				t.Errorf("Coefficient %d is out of range", i)
			}
		}
	})

	t.Run("with provided secret", func(t *testing.T) {
		secret := big.NewInt(12345)
		poly, err := New(curve, 2, secret)
		if err != nil {
			t.Fatalf("Failed to create polynomial: %v", err)
		}

		if poly.Coefficients[0].Cmp(secret) != 0 {
			t.Errorf("Expected a_0 = %s, got %s", secret, poly.Coefficients[0])
		}
	})

	t.Run("degree 0", func(t *testing.T) {
		secret := big.NewInt(999)
		poly, err := New(curve, 0, secret)
		if err != nil {
			t.Fatalf("Failed to create polynomial: %v", err)
		}

		if len(poly.Coefficients) != 1 {
			t.Errorf("Expected 1 coefficient for degree 0, got %d", len(poly.Coefficients))
		}
	})
}

func TestEvaluate(t *testing.T) {
	curve := curves.NewSecp256k1()
	q := curve.Params().N

	t.Run("constant polynomial", func(t *testing.T) {
		// f(x) = 5
		poly := &Polynomial{
			Coefficients: []*big.Int{big.NewInt(5)},
			Curve:        curve,
		}

		result := poly.Evaluate(big.NewInt(0))
		if result.Cmp(big.NewInt(5)) != 0 {
			t.Errorf("f(0) = %s, expected 5", result)
		}

		result = poly.Evaluate(big.NewInt(100))
		if result.Cmp(big.NewInt(5)) != 0 {
			t.Errorf("f(100) = %s, expected 5", result)
		}
	})

	t.Run("linear polynomial", func(t *testing.T) {
		// f(x) = 3 + 2x
		poly := &Polynomial{
			Coefficients: []*big.Int{big.NewInt(3), big.NewInt(2)},
			Curve:        curve,
		}

		// f(0) = 3
		result := poly.Evaluate(big.NewInt(0))
		if result.Cmp(big.NewInt(3)) != 0 {
			t.Errorf("f(0) = %s, expected 3", result)
		}

		// f(1) = 3 + 2 = 5
		result = poly.Evaluate(big.NewInt(1))
		if result.Cmp(big.NewInt(5)) != 0 {
			t.Errorf("f(1) = %s, expected 5", result)
		}

		// f(5) = 3 + 10 = 13
		result = poly.Evaluate(big.NewInt(5))
		if result.Cmp(big.NewInt(13)) != 0 {
			t.Errorf("f(5) = %s, expected 13", result)
		}
	})

	t.Run("quadratic polynomial", func(t *testing.T) {
		// f(x) = 1 + 2x + 3x^2
		poly := &Polynomial{
			Coefficients: []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)},
			Curve:        curve,
		}

		// f(0) = 1
		result := poly.Evaluate(big.NewInt(0))
		if result.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("f(0) = %s, expected 1", result)
		}

		// f(1) = 1 + 2 + 3 = 6
		result = poly.Evaluate(big.NewInt(1))
		if result.Cmp(big.NewInt(6)) != 0 {
			t.Errorf("f(1) = %s, expected 6", result)
		}

		// f(2) = 1 + 4 + 12 = 17
		result = poly.Evaluate(big.NewInt(2))
		if result.Cmp(big.NewInt(17)) != 0 {
			t.Errorf("f(2) = %s, expected 17", result)
		}

		// f(3) = 1 + 6 + 27 = 34
		result = poly.Evaluate(big.NewInt(3))
		if result.Cmp(big.NewInt(34)) != 0 {
			t.Errorf("f(3) = %s, expected 34", result)
		}
	})

	t.Run("modular reduction", func(t *testing.T) {
		// Test that results are properly reduced mod q
		// f(x) = q-1 + x (should wrap around)
		qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
		poly := &Polynomial{
			Coefficients: []*big.Int{qMinus1, big.NewInt(2)},
			Curve:        curve,
		}

		// f(1) = (q-1) + 2 = q+1 mod q = 1
		result := poly.Evaluate(big.NewInt(1))
		if result.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("f(1) = %s, expected 1 (after mod q)", result)
		}
	})
}

func TestEvaluateMulti(t *testing.T) {
	curve := curves.NewSecp256k1()

	// f(x) = 5 + 3x
	poly := &Polynomial{
		Coefficients: []*big.Int{big.NewInt(5), big.NewInt(3)},
		Curve:        curve,
	}

	xs := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(10),
	}

	expected := []*big.Int{
		big.NewInt(5),  // f(0) = 5
		big.NewInt(8),  // f(1) = 8
		big.NewInt(11), // f(2) = 11
		big.NewInt(35), // f(10) = 35
	}

	results := poly.EvaluateMulti(xs)

	if len(results) != len(expected) {
		t.Fatalf("Expected %d results, got %d", len(expected), len(results))
	}

	for i, r := range results {
		if r.Cmp(expected[i]) != 0 {
			t.Errorf("f(%s) = %s, expected %s", xs[i], r, expected[i])
		}
	}
}

func TestShamirSecretSharing(t *testing.T) {
	// Test that polynomial evaluation produces valid Shamir shares
	curve := curves.NewSecp256k1()
	q := curve.Params().N

	// Create polynomial with known secret
	secret := big.NewInt(42)
	poly, err := New(curve, 2, secret) // degree 2 means t=2, so 3 shares needed
	if err != nil {
		t.Fatalf("Failed to create polynomial: %v", err)
	}

	// Generate shares for parties 1, 2, 3
	shares := make([]*big.Int, 3)
	for i := 1; i <= 3; i++ {
		shares[i-1] = poly.Evaluate(big.NewInt(int64(i)))
	}

	// Verify f(0) = secret using Lagrange interpolation with all 3 shares
	// For 3 points (1, y1), (2, y2), (3, y3):
	// L_1(0) = (0-2)(0-3) / (1-2)(1-3) = 6/2 = 3
	// L_2(0) = (0-1)(0-3) / (2-1)(2-3) = 3/(-1) = -3 mod q
	// L_3(0) = (0-1)(0-2) / (3-1)(3-2) = 2/2 = 1

	l1 := big.NewInt(3)
	l2 := new(big.Int).Mod(big.NewInt(-3), q)
	l3 := big.NewInt(1)

	reconstructed := new(big.Int)
	reconstructed.Add(reconstructed, new(big.Int).Mul(shares[0], l1))
	reconstructed.Add(reconstructed, new(big.Int).Mul(shares[1], l2))
	reconstructed.Add(reconstructed, new(big.Int).Mul(shares[2], l3))
	reconstructed.Mod(reconstructed, q)

	if reconstructed.Cmp(secret) != 0 {
		t.Errorf("Reconstructed secret = %s, expected %s", reconstructed, secret)
	}
}
