package keygen

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/curves"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/zk/schnorr"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

func (s *state) round4() (tss.StateMachine, []tss.Message, error) {
	// 1. Process Round 3 Messages (Schnorr Proofs)
	curve := curves.NewSecp256k1()
	allVss, _ := s.tempData["all_vss"].(map[string][]*big.Int)

	for id, msgs := range s.receivedMsgs {
		if len(msgs) == 0 {
			continue
		}
		msg := msgs[0] // Expecting 1 broadcast message
		
		var payload Round3Payload
		if err := json.Unmarshal(msg.Payload(), &payload); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal round 3 payload from %s: %w", id, err)
		}

		// 2. Verify Schnorr Proof
		// Reconstruct X_j point
		Xj_x := new(big.Int).SetBytes(payload.XiX)
		Xj_y := new(big.Int).SetBytes(payload.XiY)
		
		// Convert to Jacobian
		var Xj_jac secp256k1.JacobianPoint
		var Xj_x_field, Xj_y_field secp256k1.FieldVal
		Xj_x_field.SetByteSlice(Xj_x.Bytes())
		Xj_y_field.SetByteSlice(Xj_y.Bytes())
		Xj_jac.X = Xj_x_field
		Xj_jac.Y = Xj_y_field
		Xj_jac.Z.SetInt(1)

		// Reconstruct Proof
		// R
		pubKey, err := secp256k1.ParsePubKey(payload.ProofR)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse R point from %s: %w", id, err)
		}
		
		var R_jac_recovered secp256k1.JacobianPoint
		pubKey.AsJacobian(&R_jac_recovered)
		
		proof := &schnorr.Proof{
			R: &R_jac_recovered,
			S: new(big.Int).SetBytes(payload.ProofS),
		}
		
		if !proof.Verify(&Xj_jac) {
			return nil, nil, tss.NewBlame(msg.From(), "schnorr proof verification failed", nil)
		}

		// 3. Verify X_j against VSS
		// X_j should be sum_k (Eval(A_k, j+1))
		// j is the ID of the sender of this message
		
		// Parse j's ID to int
		jIdx := new(big.Int)
		jIdx.SetString(id, 10)
		
		// Calculate expected X_j
		var expectedX, expectedY *big.Int
		
		// Iterate over all parties k (including self)
		for _, vss := range allVss {
			// Evaluate polynomial A_k at x = jIdx
			// A_k is defined by vss (points)
			// val = sum_m (A_k,m * jIdx^m)
			
			var termSumX, termSumY *big.Int
			t := s.params.Threshold
			
			for m := 0; m <= t; m++ {
				akX := vss[m*2]
				akY := vss[m*2+1]
				
				scalar := new(big.Int).Exp(jIdx, big.NewInt(int64(m)), curve.Params().N)
				tx, ty := curve.ScalarMult(akX, akY, scalar)
				
				if m == 0 {
					termSumX, termSumY = tx, ty
				} else {
					termSumX, termSumY = curve.Add(termSumX, termSumY, tx, ty)
				}
			}
			
			// Add to total sum
			if expectedX == nil {
				expectedX, expectedY = termSumX, termSumY
			} else {
				expectedX, expectedY = curve.Add(expectedX, expectedY, termSumX, termSumY)
			}
		}
		
		if Xj_x.Cmp(expectedX) != 0 || Xj_y.Cmp(expectedY) != 0 {
			return nil, nil, tss.NewBlame(msg.From(), "public key share mismatch", nil)
		}
	}

	// Protocol Finished!
	return &finishedState{data: s.saveData}, nil, nil
}
