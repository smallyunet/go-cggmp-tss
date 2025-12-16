package refresh

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
	// 1. Generate New Paillier Key Pair
	paillierSk, err := paillier.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate paillier key: %w", err)
	}

	s.saveData.PaillierSk = paillierSk
	s.saveData.PaillierPk = &paillierSk.PublicKey

	// 2. Generate Zero-Hole Polynomial (Constant term = 0)
	curve := curves.NewSecp256k1()
	zero := big.NewInt(0)
	poly, err := polynomial.New(curve, s.params.Threshold, zero)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate polynomial: %w", err)
	}
	
	s.tempData["polynomial"] = poly

	// 3. Calculate VSS Commitments
	vssCommitments := make([]*big.Int, len(poly.Coefficients)*2)
	for i, coeff := range poly.Coefficients {
		x, y := curve.ScalarBaseMult(coeff)
		vssCommitments[i*2] = x
		vssCommitments[i*2+1] = y
	}
	s.tempData["vss_commitments"] = vssCommitments

	// 4. Create Commitment
	// We commit to (PaillierPK, VSS_Commitments)
	type CommitData struct {
		PaillierN []byte
		VSS       []*big.Int
	}
	
	cData := CommitData{
		PaillierN: paillierSk.PublicKey.N.Bytes(),
		VSS:       vssCommitments,
	}
	
	commitBytes, err := json.Marshal(cData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal commit data: %w", err)
	}

	comm, err := commitment.New(commitBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create commitment: %w", err)
	}

	s.tempData["round1_decommit"] = comm.D

	// 5. Broadcast Commitment
	msg := &RefreshMessage{
		FromParty:   s.params.PartyID,
		ToParties:   nil,
		IsBcast:     true,
		Data:        comm.C,
		TypeString:  "RefreshRound1",
		RoundNum:    1,
	}

	return s, []tss.Message{msg}, nil
}
