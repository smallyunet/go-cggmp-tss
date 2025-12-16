package sign

import (
	"encoding/json"
	"math/big"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/curves"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

func (s *state) roundOnline1() (tss.StateMachine, []tss.Message, error) {
	curve := curves.NewSecp256k1()
	N := curve.Params().N

	// Populate tempData for round5
	s.tempData["r"] = s.preSignature.R
	s.tempData["Rx"] = s.preSignature.Rx
	s.tempData["Ry"] = s.preSignature.Ry

	// Compute s_i = m * k_i + r * sigma_i
	m := new(big.Int).SetBytes(s.msgToSign)
	
	ki := s.preSignature.Ki
	sigma_i := s.preSignature.SigmaI
	r := s.preSignature.R

	// term1 = m * k_i
	term1 := new(big.Int).Mul(m, ki)
	term1.Mod(term1, N)

	// term2 = r * sigma_i
	term2 := new(big.Int).Mul(r, sigma_i)
	term2.Mod(term2, N)

	si := new(big.Int).Add(term1, term2)
	si.Mod(si, N)

	s.tempData["si"] = si

	// Broadcast s_i
	// We use Round4Payload because it's the same data structure as in the full protocol
	payload := Round4Payload{
		Si: si,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}

	msg := &SignMessage{
		FromParty:  s.params.PartyID,
		ToParties:  nil, // Broadcast
		IsBcast:    true,
		Data:       data,
		TypeString: "SignRound4", // Reuse existing type string so round5 can process it
		RoundNum:   4,            // Reuse existing round number
	}

	return s, []tss.Message{msg}, nil
}
