package sign

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/curves"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

type Round1Payload struct {
	EncK    []byte // Paillier ciphertext of k_i
	GammaX  []byte // Gamma_i X
	GammaY  []byte // Gamma_i Y
}

func (s *state) round1() (tss.StateMachine, []tss.Message, error) {
	curve := curves.NewSecp256k1()
	
	// 1. Generate k_i, gamma_i
	ki, err := curve.NewScalar()
	if err != nil {
		return nil, nil, err
	}
	gammai, err := curve.NewScalar()
	if err != nil {
		return nil, nil, err
	}
	
	s.tempData["ki"] = ki
	s.tempData["gammai"] = gammai

	// Calculate Lagrange Coefficient and w_i
	lambda, err := s.calcLagrangeCoeffs()
	if err != nil { return nil, nil, err }
	
	wi := new(big.Int).Mul(s.keyData.Xi, lambda)
	wi.Mod(wi, curve.Params().N)
	s.tempData["wi"] = wi

	// 2. Encrypt k_i using our Paillier Key
	// We use the Paillier key generated in KeyGen
	encK, _, err := s.keyData.PaillierPk.Encrypt(ki)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt k_i: %w", err)
	}
	s.tempData["encK"] = encK

	// 3. Compute Gamma_i = gamma_i * G
	Gx, Gy := curve.ScalarBaseMult(gammai)
	s.tempData["GammaX"] = Gx
	s.tempData["GammaY"] = Gy

	// 4. Broadcast
	payload := Round1Payload{
		EncK:   encK.Bytes(),
		GammaX: Gx.Bytes(),
		GammaY: Gy.Bytes(),
	}
	
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}

	msg := &SignMessage{
		FromParty:   s.params.PartyID,
		ToParties:   nil,
		IsBcast:     true,
		Data:        data,
		TypeString:  "SignRound1",
		RoundNum:    1,
	}

	return s, []tss.Message{msg}, nil
}

func (s *state) calcLagrangeCoeffs() (*big.Int, error) {
	curve := curves.NewSecp256k1()
	N := curve.Params().N
	
	// Identify x-coordinates
	// Assuming s.params.Parties matches KeyGen order and we use all of them.
	// x_i = index + 1
	
	var myX *big.Int
	allX := make([]*big.Int, len(s.params.Parties))
	
	for i, p := range s.params.Parties {
		x := big.NewInt(int64(i + 1))
		allX[i] = x
		if p.ID() == s.params.PartyID.ID() {
			myX = x
		}
	}
	
	if myX == nil {
		return nil, fmt.Errorf("party not found in list")
	}
	
	num := big.NewInt(1)
	den := big.NewInt(1)
	
	for _, x := range allX {
		if x.Cmp(myX) == 0 { continue }
		
		// num = num * x
		num.Mul(num, x)
		num.Mod(num, N)
		
		// den = den * (x - myX)
		diff := new(big.Int).Sub(x, myX)
		diff.Mod(diff, N)
		if diff.Sign() < 0 {
			diff.Add(diff, N)
		}
		den.Mul(den, diff)
		den.Mod(den, N)
	}
	
	denInv := new(big.Int).ModInverse(den, N)
	if denInv == nil {
		return nil, fmt.Errorf("failed to invert denominator")
	}
	
	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, N)
	
	return lambda, nil
}
