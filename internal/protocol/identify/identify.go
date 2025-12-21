package identify

import (
	"errors"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/zk/schnorr"
	"github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// IdentifyProof represents a proof of key ownership.
// A party can use this to prove they possess a valid secret key share.
type IdentifyProof struct {
	PartyID    string
	Proof      *schnorr.Proof
	PublicKeyX *big.Int
	PublicKeyY *big.Int
}

// NewIdentifyProof generates a ZK proof that the party owns their secret key share.
// This is a non-interactive proof using the Fiat-Shamir heuristic.
func NewIdentifyProof(params *tss.Parameters, keyData *keygen.LocalPartySaveData) (*IdentifyProof, error) {
	if params == nil || keyData == nil {
		return nil, errors.New("identify: params and keyData cannot be nil")
	}

	if keyData.Xi == nil {
		return nil, errors.New("identify: missing secret share (Xi)")
	}

	if keyData.XiX == nil || keyData.XiY == nil {
		return nil, errors.New("identify: missing public key share (XiX, XiY)")
	}

	// Convert public key share to Jacobian point
	var Xi_jac secp256k1.JacobianPoint
	var Xi_x_field, Xi_y_field secp256k1.FieldVal
	Xi_x_field.SetByteSlice(keyData.XiX.Bytes())
	Xi_y_field.SetByteSlice(keyData.XiY.Bytes())
	Xi_jac.X = Xi_x_field
	Xi_jac.Y = Xi_y_field
	Xi_jac.Z.SetInt(1)

	// Generate Schnorr proof: proves knowledge of x_i such that X_i = x_i * G
	proof, err := schnorr.Prove(keyData.Xi, &Xi_jac)
	if err != nil {
		return nil, err
	}

	return &IdentifyProof{
		PartyID:    params.PartyID.ID(),
		Proof:      proof,
		PublicKeyX: keyData.XiX,
		PublicKeyY: keyData.XiY,
	}, nil
}

// VerifyIdentifyProof checks if the provided proof is valid for the claimed public key share.
func VerifyIdentifyProof(proof *IdentifyProof) bool {
	if proof == nil || proof.Proof == nil {
		return false
	}

	if proof.PublicKeyX == nil || proof.PublicKeyY == nil {
		return false
	}

	// Reconstruct the public key share as a Jacobian point
	var Xi_jac secp256k1.JacobianPoint
	var Xi_x_field, Xi_y_field secp256k1.FieldVal
	Xi_x_field.SetByteSlice(proof.PublicKeyX.Bytes())
	Xi_y_field.SetByteSlice(proof.PublicKeyY.Bytes())
	Xi_jac.X = Xi_x_field
	Xi_jac.Y = Xi_y_field
	Xi_jac.Z.SetInt(1)

	return proof.Proof.Verify(&Xi_jac)
}

// IdentifySession enables multi-party identification verification.
// Each party broadcasts their proof, and all parties verify each other.
type IdentifySession struct {
	params      *tss.Parameters
	myProof     *IdentifyProof
	peerProofs  map[string]*IdentifyProof
	peerPubKeys map[string]struct{ X, Y *big.Int }
}

// NewIdentifySession creates a new identification session.
func NewIdentifySession(params *tss.Parameters, keyData *keygen.LocalPartySaveData) (*IdentifySession, *IdentifyProof, error) {
	proof, err := NewIdentifyProof(params, keyData)
	if err != nil {
		return nil, nil, err
	}

	// We need to know the expected public key shares of all parties
	// In a real scenario, these would come from the keygen output or a trusted source
	peerPubKeys := make(map[string]struct{ X, Y *big.Int })

	return &IdentifySession{
		params:      params,
		myProof:     proof,
		peerProofs:  make(map[string]*IdentifyProof),
		peerPubKeys: peerPubKeys,
	}, proof, nil
}

// AddPeerProof adds and verifies a proof from another party.
// expectedX, expectedY are the expected public key share coordinates for this party.
func (s *IdentifySession) AddPeerProof(proof *IdentifyProof, expectedX, expectedY *big.Int) error {
	if proof == nil {
		return errors.New("identify: proof cannot be nil")
	}

	if proof.PartyID == s.params.PartyID.ID() {
		return errors.New("identify: cannot add own proof as peer proof")
	}

	// Verify the public key matches expected
	if expectedX != nil && expectedY != nil {
		if proof.PublicKeyX.Cmp(expectedX) != 0 || proof.PublicKeyY.Cmp(expectedY) != 0 {
			return errors.New("identify: public key mismatch")
		}
	}

	// Verify the ZK proof
	if !VerifyIdentifyProof(proof) {
		return errors.New("identify: proof verification failed")
	}

	s.peerProofs[proof.PartyID] = proof
	return nil
}

// IsComplete returns true if we have verified proofs from all other parties.
func (s *IdentifySession) IsComplete() bool {
	expectedCount := len(s.params.Parties) - 1 // Exclude self
	return len(s.peerProofs) >= expectedCount
}
