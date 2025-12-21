package reshare

import (
	"encoding/json"
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
	// Both Old and New parties decommit whatever they committed to.
	decommitSalt, ok := s.tempData["round1_decommit"].([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("missing decommitment salt")
	}

	cData := CommitData{}

	if s.isNewCommittee {
		if s.saveData.PaillierPk == nil {
			return nil, nil, fmt.Errorf("new committee member missing paillier key")
		}
		cData.PaillierN = s.saveData.PaillierPk.N.Bytes()
	}

	if s.isOldCommittee {
		vssCommitments, ok := s.tempData["vss_commitments"].([]*big.Int)
		if !ok {
			return nil, nil, fmt.Errorf("old committee member missing vss commitments")
		}
		cData.VSS = vssCommitments
		cData.GlobalPubX = s.oldKeyData.PublicKeyX.Bytes()
		cData.GlobalPubY = s.oldKeyData.PublicKeyY.Bytes()
	}

	decommitData, err := json.Marshal(cData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal decommit data: %w", err)
	}

	payload := make([]byte, len(decommitSalt)+len(decommitData))
	copy(payload, decommitSalt)
	copy(payload[len(decommitSalt):], decommitData)

	broadcastMsg := &ReshareMessage{
		FromParty:  s.params.PartyID,
		ToParties:  nil,
		IsBcast:    true,
		Data:       payload,
		TypeString: "ReshareRound2_Decommit",
		RoundNum:   2,
	}
	outMsgs = append(outMsgs, broadcastMsg)

	// 2b. Old Parties Send Shares to New Parties
	if s.isOldCommittee {
		poly, ok := s.tempData["polynomial"].(*polynomial.Polynomial)
		if !ok {
			return nil, nil, fmt.Errorf("missing polynomial")
		}

		// Iterate over NEW committee parties
		for i, peer := range s.params.Parties {
			// Calculate share for Party i+1 (1-based index)
			// Note: We use the index in the NEW committee list.
			x := big.NewInt(int64(i + 1))
			share := poly.Evaluate(x)

			if peer.ID() == s.params.PartyID.ID() {
				// Store self share
				s.tempData["self_share"] = share
				continue
			}

			// Construct message
			p2pMsg := &ReshareMessage{
				FromParty:  s.params.PartyID,
				ToParties:  []tss.PartyID{peer},
				IsBcast:    false,
				Data:       share.Bytes(),
				TypeString: "ReshareRound2_Share",
				RoundNum:   2,
			}
			outMsgs = append(outMsgs, p2pMsg)
		}
	}

	s.receivedMsgs = make(map[string][]tss.Message)
	s.round = 2
	return s, outMsgs, nil
}
