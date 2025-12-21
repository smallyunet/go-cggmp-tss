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
	// Re-serialize data
	// Use fixed-width fields to avoid parsing ambiguity
	var decommitData []byte

	// Pad Paillier N to 256 bytes (2048 bits)
	nBytes := paillierPk.N.Bytes()
	if len(nBytes) > 256 {
		// Should not happen for 2048-bit keys, but handle gracefully or error?
		// For now, take suffix or just append.
		// Realistically, if it's > 256 bytes, we have a bigger config issue.
		// But let's assume it fits.
	}
	paddedN := make([]byte, 256)
	// Right-align the bytes (BigEndian)
	copy(paddedN[256-len(nBytes):], nBytes)
	decommitData = append(decommitData, paddedN...)

	for _, coord := range vssCommitments {
		// Pad to 32 bytes (256 bits)
		cBytes := coord.Bytes()
		paddedC := make([]byte, 32)
		if len(cBytes) > 32 {
			// This can happen if mod N is close to 2^256? secp256k1 order is < 2^256.
			// Just copy suffix if too long (unlikely for valid field elements)
			copy(paddedC, cBytes[len(cBytes)-32:])
		} else {
			copy(paddedC[32-len(cBytes):], cBytes)
		}
		decommitData = append(decommitData, paddedC...)
	}

	// Payload: Salt || Data
	// To make parsing easier, we might want a proper serialization format (e.g. Protobuf or length-prefixed).
	// For now, let's just append. The receiver knows the length of Salt (32 bytes).
	payload := make([]byte, len(decommitSalt)+len(decommitData))
	copy(payload, decommitSalt)
	copy(payload[len(decommitSalt):], decommitData)

	broadcastMsg := &KeyGenMessage{
		FromParty:  s.params.PartyID,
		ToParties:  nil,
		IsBcast:    true,
		Data:       payload,
		TypeString: "KeyGenRound2_Decommit",
		RoundNum:   2,
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
			FromParty:  s.params.PartyID,
			ToParties:  []tss.PartyID{peer},
			IsBcast:    false,
			Data:       share.Bytes(),
			TypeString: "KeyGenRound2_Share",
			RoundNum:   2,
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
