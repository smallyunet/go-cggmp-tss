package sign

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

type Round2Payload struct {
	C_delta *big.Int
	C_sigma *big.Int
}

func (s *state) round2() (tss.StateMachine, []tss.Message, error) {
	// 1. Process Round 1 Messages
	peerEncK := make(map[string]*big.Int)
	peerGammaX := make(map[string]*big.Int)
	peerGammaY := make(map[string]*big.Int)
	
	for id, msgs := range s.receivedMsgs {
		if len(msgs) == 0 { continue }
		var payload Round1Payload
		if err := json.Unmarshal(msgs[0].Payload(), &payload); err != nil {
			return nil, nil, err
		}
		peerEncK[id] = new(big.Int).SetBytes(payload.EncK)
		peerGammaX[id] = new(big.Int).SetBytes(payload.GammaX)
		peerGammaY[id] = new(big.Int).SetBytes(payload.GammaY)
	}
	s.tempData["peerEncK"] = peerEncK
	s.tempData["peerGammaX"] = peerGammaX
	s.tempData["peerGammaY"] = peerGammaY

	// 2. Perform MtA with each peer
	var outMsgs []tss.Message
	
	betas := make(map[string]*big.Int)
	nus := make(map[string]*big.Int)
	
	for _, peer := range s.params.Parties {
		if peer.ID() == s.params.PartyID.ID() {
			continue
		}
		
		pid := peer.ID()
		encKj := peerEncK[pid]
		pkj := s.keyData.PeerPaillierPks[pid]
		if pkj == nil {
			return nil, nil, fmt.Errorf("missing paillier key for %s", pid)
		}
		
		// 2a. Compute C_delta_ij = EncK_j * gamma_i + Enc(beta_ij)
		gammai := s.tempData["gammai"].(*big.Int)
		
		beta_ij, err := rand.Int(rand.Reader, pkj.N)
		if err != nil { return nil, nil, err }
		betas[pid] = beta_ij
		
		encBeta, _, err := pkj.Encrypt(beta_ij)
		if err != nil { return nil, nil, err }
		
		term1 := pkj.Mul(encKj, gammai)
		c_delta := pkj.Add(term1, encBeta)
		
		// 2b. Compute C_sigma_ij = EncK_j * w_i + Enc(nu_ij)
		wi := s.tempData["wi"].(*big.Int)
		
		nu_ij, err := rand.Int(rand.Reader, pkj.N)
		if err != nil { return nil, nil, err }
		nus[pid] = nu_ij
		
		encNu, _, err := pkj.Encrypt(nu_ij)
		if err != nil { return nil, nil, err }
		
		term2 := pkj.Mul(encKj, wi)
		c_sigma := pkj.Add(term2, encNu)
		
		// Create Message
		payload := Round2Payload{
			C_delta: c_delta,
			C_sigma: c_sigma,
		}
		data, err := json.Marshal(payload)
		if err != nil { return nil, nil, err }
		
		msg := &SignMessage{
			FromParty: s.params.PartyID,
			ToParties: []tss.PartyID{peer},
			IsBcast:   false,
			Data:      data,
			TypeString: "SignRound2_MtA",
			RoundNum:  2,
		}
		outMsgs = append(outMsgs, msg)
	}
	
	s.tempData["betas"] = betas
	s.tempData["nus"] = nus
	
	newState := &state{
		params:       s.params,
		keyData:      s.keyData,
		msgToSign:    s.msgToSign,
		round:        2,
		tempData:     s.tempData,
		receivedMsgs: make(map[string][]tss.Message),
	}

	return newState, outMsgs, nil
}
