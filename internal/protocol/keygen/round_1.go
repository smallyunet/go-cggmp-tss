package keygen

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/commitment"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/curves"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/polynomial"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// round1 executes the logic for the first round of the KeyGen protocol.
func (s *state) round1() (tss.StateMachine, []tss.Message, error) {
	// 1. Generate Paillier Key Pair
	// Using 2048 bits as a standard security parameter
	paillierSk, err := paillier.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate paillier key: %w", err)
	}

	// Save keys to state
	s.saveData.PaillierSk = paillierSk
	s.saveData.PaillierPk = &paillierSk.PublicKey

	// 2. Generate VSS Polynomial
	// Degree t = threshold
	curve := curves.NewSecp256k1()
	poly, err := polynomial.New(curve, s.params.Threshold, nil) // nil secret -> random u_i
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate polynomial: %w", err)
	}

	// Save our secret share (u_i = poly.Coefficients[0])
	s.saveData.Ui = poly.Coefficients[0]
	s.tempData["polynomial"] = poly

	// 3. Calculate VSS Commitments (Feldman VSS)
	// C_k = a_k * G
	vssCommitments := make([]*big.Int, len(poly.Coefficients)*2) // Store as (x, y) pairs flattened
	for i, coeff := range poly.Coefficients {
		x, y := curve.ScalarBaseMult(coeff)
		vssCommitments[i*2] = x
		vssCommitments[i*2+1] = y
	}
	s.tempData["vss_commitments"] = vssCommitments

	// 4. Create Commitment
	// We commit to (PaillierPK, VSS_Commitments)
	// Serialize data for commitment
	// Format: PaillierN || VSS_X0 || VSS_Y0 || ...
	var commitData []byte
	commitData = append(commitData, paillierSk.PublicKey.N.Bytes()...)
	for _, coord := range vssCommitments {
		commitData = append(commitData, coord.Bytes()...)
	}

	// Create commitment: C = Hash(salt, data)
	comm, err := commitment.New(commitData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create commitment: %w", err)
	}

	// Store the decommitment (D) for Round 2
	s.tempData["round1_decommit"] = comm.D

	// 5. Create the Broadcast Message
	// The payload is the commitment hash C
	msg := &KeyGenMessage{
		FromParty:   s.params.PartyID,
		ToParties:   nil, // Broadcast
		IsBcast:     true,
		Data:        comm.C,
		TypeString:  "KeyGenRound1",
		RoundNum:    1,
	}

	return s, []tss.Message{msg}, nil
}
