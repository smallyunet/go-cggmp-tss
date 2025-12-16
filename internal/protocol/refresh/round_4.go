package refresh

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
	curve := curves.NewSecp256k1()
	N := curve.Params().N
	
	// Map PartyID to index (x coordinate)
	partyIndices := make(map[string]*big.Int)
	for i, p := range s.params.Parties {
		partyIndices[p.ID()] = big.NewInt(int64(i + 1))
	}

	// Collect all X_j (including own)
	allXiX := make(map[string]*big.Int)
	allXiY := make(map[string]*big.Int)
	
	// Own
	allXiX[s.params.PartyID.ID()] = s.saveData.XiX
	allXiY[s.params.PartyID.ID()] = s.saveData.XiY
	
	for id, msgs := range s.receivedMsgs {
		if len(msgs) == 0 { continue }
		msg := msgs[0]
		
		var payload Round3Payload
		if err := json.Unmarshal(msg.Payload(), &payload); err != nil {
			return nil, nil, err
		}
		
		// Verify Schnorr Proof
		Xj_x := new(big.Int).SetBytes(payload.XiX)
		Xj_y := new(big.Int).SetBytes(payload.XiY)
		
		var Xj_jac secp256k1.JacobianPoint
		var fx, fy secp256k1.FieldVal
		fx.SetByteSlice(Xj_x.Bytes())
		fy.SetByteSlice(Xj_y.Bytes())
		Xj_jac.X = fx
		Xj_jac.Y = fy
		Xj_jac.Z.SetInt(1)
		
		pubKey, err := secp256k1.ParsePubKey(payload.ProofR)
		if err != nil { return nil, nil, err }
		
		var R_jac secp256k1.JacobianPoint
		pubKey.AsJacobian(&R_jac)
		
		proof := &schnorr.Proof{
			R: &R_jac,
			S: new(big.Int).SetBytes(payload.ProofS),
		}
		
		if !proof.Verify(&Xj_jac) {
			return nil, nil, fmt.Errorf("schnorr proof failed for %s", id)
		}
		
		allXiX[id] = Xj_x
		allXiY[id] = Xj_y
	}
	
	// Compute X = sum(lambda_j * X_j)
	var X_sum_x, X_sum_y *big.Int
	
	// We iterate over all parties in the session (assuming all participated)
	// If threshold < n, we only need t+1 parties.
	// But Refresh usually involves all parties (n-out-of-n for resharing, or same committee).
	// Here we assume all parties in s.params.Parties participated.
	
	for _, p := range s.params.Parties {
		id := p.ID()
		xj := partyIndices[id]
		
		// Calculate lambda_j (Lagrange coefficient at x=0)
		num := big.NewInt(1)
		den := big.NewInt(1)
		
		for _, op := range s.params.Parties {
			oid := op.ID()
			if id == oid { continue }
			ox := partyIndices[oid]
			
			// num *= ox
			num.Mul(num, ox)
			num.Mod(num, N)
			
			// den *= (ox - xj)
			diff := new(big.Int).Sub(ox, xj)
			diff.Mod(diff, N)
			den.Mul(den, diff)
			den.Mod(den, N)
		}
		
		denInv := new(big.Int).ModInverse(den, N)
		lambda := new(big.Int).Mul(num, denInv)
		lambda.Mod(lambda, N)
		
		// term = lambda * X_j
		tx, ty := curve.ScalarMult(allXiX[id], allXiY[id], lambda)
		
		if X_sum_x == nil {
			X_sum_x, X_sum_y = tx, ty
		} else {
			X_sum_x, X_sum_y = curve.Add(X_sum_x, X_sum_y, tx, ty)
		}
	}
	
	// Verify Global Public Key
	if X_sum_x.Cmp(s.oldKeyData.PublicKeyX) != 0 || X_sum_y.Cmp(s.oldKeyData.PublicKeyY) != 0 {
		return nil, nil, fmt.Errorf("global public key changed! refresh failed")
	}
	
	// Success
	return &finishedState{saveData: s.saveData}, nil, nil
}
