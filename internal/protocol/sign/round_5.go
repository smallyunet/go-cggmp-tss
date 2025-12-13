package sign

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/curves"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

func (s *state) round5() (tss.StateMachine, []tss.Message, error) {
	curve := curves.NewSecp256k1()
	N := curve.Params().N

	// 1. Process Round 4 Messages (s_j)
	si := s.tempData["si"].(*big.Int)
	finalS := new(big.Int).Set(si)
	
	for _, msgs := range s.receivedMsgs {
		if len(msgs) == 0 { continue }
		var payload Round4Payload
		if err := json.Unmarshal(msgs[0].Payload(), &payload); err != nil {
			return nil, nil, err
		}
		finalS.Add(finalS, payload.Si)
		finalS.Mod(finalS, N)
	}
	
	// 2. Verify Signature (r, s)
	r := s.tempData["r"].(*big.Int)
	
	// Construct Signature
	signature := &Signature{
		R: r,
		S: finalS,
	}
	
	// Verify using standard ECDSA verification
	// We need the global public key
	pkX := s.keyData.PublicKeyX
	pkY := s.keyData.PublicKeyY
	
	// Use secp256k1 library to verify
	var fx, fy secp256k1.FieldVal
	fx.SetByteSlice(pkX.Bytes())
	fy.SetByteSlice(pkY.Bytes())
	pk := secp256k1.NewPublicKey(&fx, &fy)
	
	// Parse Signature
	var rMod, sMod secp256k1.ModNScalar
	rMod.SetByteSlice(r.Bytes())
	sMod.SetByteSlice(finalS.Bytes())
	
	sig := ecdsa.NewSignature(&rMod, &sMod)
	
	// Verify
	// ecdsa.Verify expects hash as []byte
	if !sig.Verify(s.msgToSign, pk) {
		return nil, nil, fmt.Errorf("signature verification failed")
	}
	
	// Success!
	return &finishedState{signature: signature}, nil, nil
}
