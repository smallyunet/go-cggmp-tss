package sign

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/curves"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

type Round4Payload struct {
	Si *big.Int
}

func (s *state) round4() (tss.StateMachine, []tss.Message, error) {
	curve := curves.NewSecp256k1()
	N := curve.Params().N

	// 1. Process Round 3 Messages (Delta_j)
	delta := new(big.Int).Set(s.tempData["delta_i"].(*big.Int))
	
	for _, msgs := range s.receivedMsgs {
		if len(msgs) == 0 { continue }
		var payload Round3Payload
		if err := json.Unmarshal(msgs[0].Payload(), &payload); err != nil {
			return nil, nil, err
		}
		delta.Add(delta, payload.DeltaI)
		delta.Mod(delta, N)
	}
	
	// 2. Compute R = delta^-1 * Gamma
	// Gamma = sum(Gamma_j)
	
	// Start with own Gamma_i
	GammaX := s.tempData["GammaX"].(*big.Int)
	GammaY := s.tempData["GammaY"].(*big.Int)
	
	peerGammaX := s.tempData["peerGammaX"].(map[string]*big.Int)
	peerGammaY := s.tempData["peerGammaY"].(map[string]*big.Int)
	
	for id := range peerGammaX {
		gx := peerGammaX[id]
		gy := peerGammaY[id]
		GammaX, GammaY = curve.Add(GammaX, GammaY, gx, gy)
	}
	
	// delta^-1
	deltaInv := new(big.Int).ModInverse(delta, N)
	if deltaInv == nil {
		return nil, nil, fmt.Errorf("delta is not invertible")
	}
	
	// R = delta^-1 * Gamma
	Rx, Ry := curve.ScalarMult(GammaX, GammaY, deltaInv)
	
	r := Rx
	r.Mod(r, N)
	if r.Sign() == 0 {
		return nil, nil, fmt.Errorf("calculated r is 0, retry signing")
	}
	
	// 3. Compute s_i = m * k_i + r * sigma_i
	// m is hash of message
	m := new(big.Int).SetBytes(s.msgToSign)
	// Truncate m if longer than N?
	// Usually we assume m is already hashed and mod N or similar.
	// Standard ECDSA: z = hash(msg), if z > N, truncate.
	// Here we assume msgToSign is the digest.
	
	ki := s.tempData["ki"].(*big.Int)
	sigma_i := s.tempData["sigma_i"].(*big.Int)
	
	// term1 = m * k_i
	term1 := new(big.Int).Mul(m, ki)
	term1.Mod(term1, N)
	
	// term2 = r * sigma_i
	term2 := new(big.Int).Mul(r, sigma_i)
	term2.Mod(term2, N)
	
	si := new(big.Int).Add(term1, term2)
	si.Mod(si, N)
	
	s.tempData["r"] = r
	s.tempData["si"] = si
	s.tempData["Rx"] = Rx
	s.tempData["Ry"] = Ry

	// 4. Broadcast s_i
	payload := Round4Payload{
		Si: si,
	}
	data, err := json.Marshal(payload)
	if err != nil { return nil, nil, err }
	
	msg := &SignMessage{
		FromParty: s.params.PartyID,
		ToParties: nil,
		IsBcast:   true,
		Data:      data,
		TypeString: "SignRound4_Si",
		RoundNum:  4,
	}
	
	// We need a final step to aggregate s_i
	// So we transition to a "round 5" or handle it in next update?
	// My state machine `nextRound` only goes up to 4.
	// I should add `round5` or `finalize`.
	// Let's add `round5` to `state.go` and implement it here.
	// Wait, `round4` returns `newState` with round=4.
	// `Update` checks `round=4` messages.
	// Then calls `nextRound` -> `round5`.
	
	newState := &state{
		params:       s.params,
		keyData:      s.keyData,
		msgToSign:    s.msgToSign,
		round:        4,
		tempData:     s.tempData,
		receivedMsgs: make(map[string][]tss.Message),
	}

	return newState, []tss.Message{msg}, nil
}
