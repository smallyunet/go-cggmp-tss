package refresh

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/polynomial"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

func (s *state) round2() (tss.StateMachine, []tss.Message, error) {
	// 1. Process Round 1 Messages
	peerCommitments := make(map[string][]byte)
	for id, msgs := range s.receivedMsgs {
		if len(msgs) == 0 { continue }
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
	
	paillierPk := s.saveData.PaillierPk
	vssCommitments, ok := s.tempData["vss_commitments"].([]*big.Int)
	if !ok {
		return nil, nil, fmt.Errorf("missing vss commitments")
	}

	type CommitData struct {
		PaillierN []byte
		VSS       []*big.Int
	}
	
	cData := CommitData{
		PaillierN: paillierPk.N.Bytes(),
		VSS:       vssCommitments,
	}
	
	decommitData, err := json.Marshal(cData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal decommit data: %w", err)
	}

	payload := make([]byte, len(decommitSalt)+len(decommitData))
	copy(payload, decommitSalt)
	copy(payload[len(decommitSalt):], decommitData)

	broadcastMsg := &RefreshMessage{
		FromParty:   s.params.PartyID,
		ToParties:   nil,
		IsBcast:     true,
		Data:        payload,
		TypeString:  "RefreshRound2_Decommit",
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

		x := big.NewInt(int64(i + 1))
		share := poly.Evaluate(x)

		p2pMsg := &RefreshMessage{
			FromParty:   s.params.PartyID,
			ToParties:   []tss.PartyID{peer},
			IsBcast:     false,
			Data:        share.Bytes(),
			TypeString:  "RefreshRound2_Share",
			RoundNum:    2,
		}
		outMsgs = append(outMsgs, p2pMsg)
	}

	s.receivedMsgs = make(map[string][]tss.Message)
	s.round = 2
	return s, outMsgs, nil
}
