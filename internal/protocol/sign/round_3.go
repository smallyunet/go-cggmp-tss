package sign

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/curves"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

type Round3Payload struct {
	DeltaI *big.Int
}

func (s *state) round3() (tss.StateMachine, []tss.Message, error) {
	curve := curves.NewSecp256k1()
	N := curve.Params().N

	// 1. Process Round 2 Messages (MtA Responses)
	// We expect 1 message from each peer containing C_delta, C_sigma
	
	alphas := make(map[string]*big.Int)
	mus := make(map[string]*big.Int)
	
	for id, msgs := range s.receivedMsgs {
		if len(msgs) == 0 { continue }
		var payload Round2Payload
		if err := json.Unmarshal(msgs[0].Payload(), &payload); err != nil {
			return nil, nil, err
		}
		
		// Decrypt C_delta to get alpha_ij
		// This is response to MY EncK_i. So I use MY Secret Key.
		alpha, err := s.keyData.PaillierSk.Decrypt(payload.C_delta)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt alpha from %s: %w", id, err)
		}
		alphas[id] = alpha
		
		// Decrypt C_sigma to get mu_ij
		mu, err := s.keyData.PaillierSk.Decrypt(payload.C_sigma)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt mu from %s: %w", id, err)
		}
		mus[id] = mu
	}

	// 2. Compute delta_i and sigma_i
	// delta_i = k_i * gamma_i + sum(alpha_ij) - sum(beta_ji)
	// sigma_i = k_i * w_i + sum(mu_ij) - sum(nu_ji)
	
	ki := s.tempData["ki"].(*big.Int)
	gammai := s.tempData["gammai"].(*big.Int)
	wi := s.tempData["wi"].(*big.Int)
	
	// k_i * gamma_i
	delta_i := new(big.Int).Mul(ki, gammai)
	delta_i.Mod(delta_i, N)
	
	// k_i * w_i
	sigma_i := new(big.Int).Mul(ki, wi)
	sigma_i.Mod(sigma_i, N)
	
	betas := s.tempData["betas"].(map[string]*big.Int)
	nus := s.tempData["nus"].(map[string]*big.Int)
	
	for id := range alphas {
		// Add alpha_ij
		delta_i.Add(delta_i, alphas[id])
		delta_i.Mod(delta_i, N)
		
		sigma_i.Add(sigma_i, mus[id])
		sigma_i.Mod(sigma_i, N)
		
		// Subtract beta_ji (stored in betas[id])
		// Note: betas[id] is beta_{i->id}.
		// Wait, in Round 2 loop: `betas[pid] = beta_ij`.
		// pid is the peer ID. So betas[id] is indeed beta_{i->j}.
		// And we want to subtract it.
		
		delta_i.Sub(delta_i, betas[id])
		delta_i.Mod(delta_i, N)
		if delta_i.Sign() < 0 {
			delta_i.Add(delta_i, N)
		}
		
		sigma_i.Sub(sigma_i, nus[id])
		sigma_i.Mod(sigma_i, N)
		if sigma_i.Sign() < 0 {
			sigma_i.Add(sigma_i, N)
		}
	}
	
	s.tempData["delta_i"] = delta_i
	s.tempData["sigma_i"] = sigma_i

	// 3. Broadcast delta_i
	payload := Round3Payload{
		DeltaI: delta_i,
	}
	data, err := json.Marshal(payload)
	if err != nil { return nil, nil, err }
	
	msg := &SignMessage{
		FromParty: s.params.PartyID,
		ToParties: nil,
		IsBcast:   true,
		Data:      data,
		TypeString: "SignRound3_Delta",
		RoundNum:  3,
	}
	
	newState := &state{
		params:       s.params,
		keyData:      s.keyData,
		msgToSign:    s.msgToSign,
		round:        3,
		tempData:     s.tempData,
		receivedMsgs: make(map[string][]tss.Message),
	}

	return newState, []tss.Message{msg}, nil
}
