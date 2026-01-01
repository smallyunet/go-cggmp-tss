package keygen

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/curves"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/polynomial"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// round1Direct executes the logic for the first round of the 1-Round KeyGen optimization.
// In this mode, we skip the commitment round and directly broadcast keys and commitments.
func (s *state) round1Direct() (tss.StateMachine, []tss.Message, error) {
	// 1. Generate Paillier Key Pair
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
		fmt.Printf("DEBUG: Sender %s Coeff[%d] = %s\n", s.params.PartyID.ID(), i, coeff.String())
		x, y := curve.ScalarBaseMult(coeff)
		vssCommitments[i*2] = x
		vssCommitments[i*2+1] = y
	}
	s.tempData["vss_commitments"] = vssCommitments

	fmt.Printf("DEBUG: Sender %s generated VSS C0=(%s, %s)\n", s.params.PartyID.ID(), vssCommitments[0].String(), vssCommitments[1].String())
	if len(vssCommitments) > 2 {
		fmt.Printf("DEBUG: Sender %s generated VSS C1=(%s, %s)\n", s.params.PartyID.ID(), vssCommitments[2].String(), vssCommitments[3].String())
	}

	// 4. Prepare Broadcast Payload (PaillierPK || VSS_Commitments)
	// Same serialization as Round 2 Decommit, but without Salt.
	var payload []byte

	// Pad Paillier N to 256 bytes (2048 bits)
	nBytes := paillierSk.PublicKey.N.Bytes()
	paddedN := make([]byte, 256)
	if len(nBytes) > 256 {
		// Just copy suffix if too long
		copy(paddedN, nBytes[len(nBytes)-256:])
	} else {
		copy(paddedN[256-len(nBytes):], nBytes)
	}
	payload = append(payload, paddedN...)

	for _, coord := range vssCommitments {
		// Pad to 32 bytes (256 bits)
		cBytes := coord.Bytes()
		paddedC := make([]byte, 32)
		if len(cBytes) > 32 {
			copy(paddedC, cBytes[len(cBytes)-32:])
		} else {
			copy(paddedC[32-len(cBytes):], cBytes)
		}
		payload = append(payload, paddedC...)
	}

	outMsgs := []tss.Message{}

	// Broadcast Message
	bcastMsg := &KeyGenMessage{
		FromParty:  s.params.PartyID,
		ToParties:  nil, // Broadcast
		IsBcast:    true,
		Data:       payload,
		TypeString: "KeyGen1Round_Direct_Broadcast", // Distinguishes from Round 1 Commit
		RoundNum:   1,
	}
	outMsgs = append(outMsgs, bcastMsg)

	// 5. Send VSS Shares (P2P)
	// Same logic as standard Round 2
	for i, peer := range s.params.Parties {
		if peer.ID() == s.params.PartyID.ID() {
			continue
		}

		// Calculate x = index + 1
		x := big.NewInt(int64(i + 1))
		share := poly.Evaluate(x)

		p2pMsg := &KeyGenMessage{
			FromParty:  s.params.PartyID,
			ToParties:  []tss.PartyID{peer},
			IsBcast:    false,
			Data:       share.Bytes(),
			TypeString: "KeyGen1Round_Direct_Share",
			RoundNum:   1, // It's still Round 1 in this protocol
		}
		outMsgs = append(outMsgs, p2pMsg)
	}

	// Update state
	// We stay in Round 1 (conceptually) until we receive messages, then transition to "Round 2" logic which is finalizing.
	// But in `Update`, we expect round number to match.
	// If we send Round 1 messages, we expect to receive Round 1 messages.
	// `state.round` is 1.

	// We need to persist tempData for the next step (verification)
	// We can reuse the state struct since we just modify it
	// But usually we return 's' or a new state.
	// 's' is already in round 1.

	return s, outMsgs, nil
}
