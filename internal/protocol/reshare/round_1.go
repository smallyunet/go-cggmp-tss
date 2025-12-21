package reshare

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/commitment"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/curves"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/polynomial"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

func (s *state) round1() (tss.StateMachine, []tss.Message, error) {
	// 1. Setup Commit Data
	type CommitData struct {
		PaillierN []byte     `json:"paillier_n,omitempty"` // For New Committee
		VSS       []*big.Int `json:"vss,omitempty"`        // For Old Committee
	}
	cData := CommitData{}

	// 2. New Committee: Generate Paillier Key
	if s.isNewCommittee {
		paillierSk, err := paillier.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate paillier key: %w", err)
		}

		s.saveData.PaillierSk = paillierSk
		s.saveData.PaillierPk = &paillierSk.PublicKey
		cData.PaillierN = paillierSk.PublicKey.N.Bytes()
	}

	// 3. Old Committee: Generate Polynomial splitting Xi
	if s.isOldCommittee {
		// Degree is t' (threshold of New Committee)
		degree := s.params.Threshold
		// Constant term is current share Xi
		secret := s.oldKeyData.Xi

		curve := curves.NewSecp256k1()
		poly, err := polynomial.New(curve, degree, secret)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate polynomial: %w", err)
		}
		s.tempData["polynomial"] = poly

		// Calculate VSS Commitments
		vssCommitments := make([]*big.Int, len(poly.Coefficients)*2)
		for i, coeff := range poly.Coefficients {
			x, y := curve.ScalarBaseMult(coeff)
			vssCommitments[i*2] = x
			vssCommitments[i*2+1] = y
		}
		s.tempData["vss_commitments"] = vssCommitments
		cData.VSS = vssCommitments
	}

	// 4. Create and Broadcast Commitment
	commitBytes, err := json.Marshal(cData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal commit data: %w", err)
	}

	comm, err := commitment.New(commitBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create commitment: %w", err)
	}

	s.tempData["round1_decommit"] = comm.D

	msg := &ReshareMessage{
		FromParty:  s.params.PartyID,
		ToParties:  nil, // Broadcast
		IsBcast:    true,
		Data:       comm.C,
		TypeString: "ReshareRound1",
		RoundNum:   1,
	}

	return s, []tss.Message{msg}, nil
}
