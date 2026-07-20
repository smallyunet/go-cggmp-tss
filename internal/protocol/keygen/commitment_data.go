package keygen

import (
	"fmt"
	"math/big"
)

const (
	paillierModulusSize = 256
	curveCoordinateSize = 32
)

// encodeCommitmentData returns the canonical fixed-width representation used
// by both the commitment and decommitment phases of key generation.
func encodeCommitmentData(paillierN *big.Int, vssCommitments []*big.Int) ([]byte, error) {
	if paillierN == nil || paillierN.Sign() <= 0 {
		return nil, fmt.Errorf("invalid Paillier modulus")
	}
	if len(vssCommitments) == 0 {
		return nil, fmt.Errorf("missing VSS commitments")
	}

	encoded := make([]byte, paillierModulusSize+len(vssCommitments)*curveCoordinateSize)
	if err := putFixedWidth(encoded[:paillierModulusSize], paillierN, "Paillier modulus"); err != nil {
		return nil, err
	}

	for i, coordinate := range vssCommitments {
		start := paillierModulusSize + i*curveCoordinateSize
		if err := putFixedWidth(encoded[start:start+curveCoordinateSize], coordinate, "VSS coordinate"); err != nil {
			return nil, fmt.Errorf("coordinate %d: %w", i, err)
		}
	}

	return encoded, nil
}

func putFixedWidth(dst []byte, value *big.Int, name string) error {
	if value == nil || value.Sign() < 0 {
		return fmt.Errorf("invalid %s", name)
	}

	valueBytes := value.Bytes()
	if len(valueBytes) > len(dst) {
		return fmt.Errorf("%s exceeds %d bytes", name, len(dst))
	}

	copy(dst[len(dst)-len(valueBytes):], valueBytes)
	return nil
}
