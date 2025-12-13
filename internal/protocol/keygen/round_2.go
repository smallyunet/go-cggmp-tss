package keygen

import (
	"fmt"
	"math/big"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/polynomial"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

func (s *state) round2() (tss.StateMachine, []tss.Message, error) {
	// 1. Process Round 1 Messages (Commitments)
	peerCommitments := make(map[string][]byte)
	for id, msgs := range s.receivedMsgs {
		if len(msgs) == 0 {
			continue
		}
		peerCommitments[id] = msgs[0].Payload()
	}
	s.tempData["peer_commitments"] = peerCommitments

	// 2. Prepare Output Messages
	var outMsgs []tss.Message

	// 2a. Broadcast Decommitment
	decommitSalt, ok := s.tempData["round1_decommit"].([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("missing decommitment salt")
	}
	
	// We need to reconstruct the data we committed to in Round 1 to send it along with the salt
	// Or we just send the salt and the data separately?
	// Usually Decommitment = (Salt, Data). The verifier hashes (Salt, Data) and checks against Commitment.
	// In Round 1 we committed to (PaillierPK || VSS_Commitments).
	// We need to send this data now.
	
	paillierPk := s.saveData.PaillierPk
	vssCommitments, ok := s.tempData["vss_commitments"].([]*big.Int)
	if !ok {
		return nil, nil, fmt.Errorf("missing vss commitments")
	}

	// Re-serialize data
	var decommitData []byte
	decommitData = append(decommitData, paillierPk.N.Bytes()...)
	for _, coord := range vssCommitments {
		decommitData = append(decommitData, coord.Bytes()...)
	}

	// Payload: Salt || Data
	// To make parsing easier, we might want a proper serialization format (e.g. Protobuf or length-prefixed).
	// For now, let's just append. The receiver knows the length of Salt (32 bytes).
	payload := make([]byte, len(decommitSalt)+len(decommitData))
	copy(payload, decommitSalt)
	copy(payload[len(decommitSalt):], decommitData)

	broadcastMsg := &KeyGenMessage{
		FromParty:   s.params.PartyID,
		ToParties:   nil,
		IsBcast:     true,
		Data:        payload,
		TypeString:  "KeyGenRound2_Decommit",
		RoundNum:    2,
	}
	outMsgs = append(outMsgs, broadcastMsg)

	// 2b. Send VSS Shares (P2P)
	poly, ok := s.tempData["polynomial"].(*polynomial.Polynomial)
	if !ok {
		return nil, nil, fmt.Errorf("missing polynomial")
	}

	for i, peer := range s.params.Parties {
		if peer.ID() == s.params.PartyID.ID() {
			continue
		}

		// Calculate x = index + 1 (using 1-based index for polynomial evaluation)
		// We assume s.params.Parties is sorted and consistent across all parties.
		x := big.NewInt(int64(i + 1))
		share := poly.Evaluate(x)

		// Payload: Share (big.Int bytes)
		p2pMsg := &KeyGenMessage{
			FromParty:   s.params.PartyID,
			ToParties:   []tss.PartyID{peer},
			IsBcast:     false,
			Data:        share.Bytes(),
			TypeString:  "KeyGenRound2_Share",
			RoundNum:    2,
		}
		outMsgs = append(outMsgs, p2pMsg)
	}

	// 3. Update State
	newState := &state{
		params:       s.params,
		round:        2,
		saveData:     s.saveData,
		tempData:     s.tempData,
		receivedMsgs: make(map[string][]tss.Message), // Clear for next round
	}

	return newState, outMsgs, nil
}
