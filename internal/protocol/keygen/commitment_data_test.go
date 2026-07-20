package keygen

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeCommitmentDataPreservesLeadingZeros(t *testing.T) {
	paillierN := new(big.Int).Lsh(big.NewInt(1), 2040)
	coordinates := []*big.Int{
		big.NewInt(1),
		new(big.Int).SetBytes([]byte{0x80, 0x01}),
	}

	encoded, err := encodeCommitmentData(paillierN, coordinates)
	require.NoError(t, err)
	require.Len(t, encoded, paillierModulusSize+2*curveCoordinateSize)

	firstCoordinate := encoded[paillierModulusSize : paillierModulusSize+curveCoordinateSize]
	require.Equal(t, make([]byte, curveCoordinateSize-1), firstCoordinate[:curveCoordinateSize-1])
	require.Equal(t, byte(1), firstCoordinate[curveCoordinateSize-1])

	encodedAgain, err := encodeCommitmentData(paillierN, coordinates)
	require.NoError(t, err)
	require.Equal(t, encoded, encodedAgain)
}

func TestEncodeCommitmentDataRejectsOversizedValues(t *testing.T) {
	oversizedCoordinate := new(big.Int).Lsh(big.NewInt(1), curveCoordinateSize*8)

	_, err := encodeCommitmentData(big.NewInt(1), []*big.Int{oversizedCoordinate})
	require.ErrorContains(t, err, "exceeds 32 bytes")
}
