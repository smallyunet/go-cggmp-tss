package refresh

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/commitment"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/polynomial"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/zk/schnorr"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

type Round3Payload struct {
	XiX    []byte
	XiY    []byte
	ProofR []byte
	ProofS []byte
}

func (s *state) round3() (tss.StateMachine, []tss.Message, error) {
	// 1. Process Round 2 Messages
	peerCommitments, _ := s.tempData["peer_commitments"].(map[string][]byte)
	poly, _ := s.tempData["polynomial"].(*polynomial.Polynomial)
	curve := poly.Curve
	N := curve.Params().N

	// Initialize sum of shares with our own share of 0
	myIdx := new(big.Int)
	myIdx.SetString(s.params.PartyID.ID(), 10)
	
	shareSum := poly.Evaluate(myIdx)
	
	// Store all VSS commitments
	allVss := make(map[string][]*big.Int)
	
	ownVss := make([]*big.Int, len(poly.Coefficients)*2)
	for k, c := range poly.Coefficients {
		x, y := curve.ScalarBaseMult(c)
		ownVss[k*2] = x
		ownVss[k*2+1] = y
	}
	allVss[s.params.PartyID.ID()] = ownVss

	// Iterate over peers
	for id, msgs := range s.receivedMsgs {
		var decommitMsg, shareMsg tss.Message
		for _, m := range msgs {
			if m.Type() == "RefreshRound2_Decommit" {
				decommitMsg = m
			} else if m.Type() == "RefreshRound2_Share" {
				shareMsg = m
			}
		}

		if decommitMsg == nil || shareMsg == nil {
			return nil, nil, fmt.Errorf("missing messages from party %s", id)
		}

		// Verify Decommitment
		payload := decommitMsg.Payload()
		if len(payload) < 32 { return nil, nil, fmt.Errorf("invalid decommitment") }
		salt := payload[:32]
		data := payload[32:]

		if !commitment.Verify(peerCommitments[id], salt, data) {
			return nil, nil, fmt.Errorf("commitment verification failed for %s", id)
		}

		// Parse Data
		type CommitData struct {
			PaillierN []byte
			VSS       []*big.Int
		}
		var cData CommitData
		if err := json.Unmarshal(data, &cData); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal commit data from %s: %w", id, err)
		}
		
		paillierN := new(big.Int).SetBytes(cData.PaillierN)
		peerPk := &paillier.PublicKey{N: paillierN, N2: new(big.Int).Mul(paillierN, paillierN)}
		
		if s.saveData.PeerPaillierPks == nil {
			s.saveData.PeerPaillierPks = make(map[string]*paillier.PublicKey)
		}
		s.saveData.PeerPaillierPks[id] = peerPk

		allVss[id] = cData.VSS

		// Verify VSS Share
		share := new(big.Int).SetBytes(shareMsg.Payload())
		
		// Verify share against VSS commitments
		// share * G == sum(A_k * i^k)
		
		shareG_x, shareG_y := curve.ScalarBaseMult(share)
		
		var rhsX, rhsY *big.Int
		for k := 0; k < len(cData.VSS)/2; k++ {
			akX := cData.VSS[k*2]
			akY := cData.VSS[k*2+1]
			
			// i^k
			scalar := new(big.Int).Exp(myIdx, big.NewInt(int64(k)), N)
			
			termX, termY := curve.ScalarMult(akX, akY, scalar)
			
			if k == 0 {
				rhsX, rhsY = termX, termY
			} else {
				rhsX, rhsY = curve.Add(rhsX, rhsY, termX, termY)
			}
		}
		
		if shareG_x.Cmp(rhsX) != 0 || shareG_y.Cmp(rhsY) != 0 {
			return nil, nil, fmt.Errorf("vss share verification failed for party %s", id)
		}
		
		// Add share to sum
		shareSum.Add(shareSum, share)
		shareSum.Mod(shareSum, N)
	}
	
	s.tempData["all_vss"] = allVss
	
	// Update Secret Key
	// x_i_new = x_i_old + shareSum
	xiNew := new(big.Int).Add(s.oldKeyData.Xi, shareSum)
	xiNew.Mod(xiNew, N)
	
	s.saveData.Xi = xiNew
	s.saveData.ShareID = myIdx
	
	// Calculate new Public Key Share X_i
	XiX, XiY := curve.ScalarBaseMult(xiNew)
	s.saveData.XiX = XiX
	s.saveData.XiY = XiY
	
	// Generate Schnorr Proof for new X_i
	var Xi_jac secp256k1.JacobianPoint
	var fx, fy secp256k1.FieldVal
	fx.SetByteSlice(XiX.Bytes())
	fy.SetByteSlice(XiY.Bytes())
	Xi_jac.X = fx
	Xi_jac.Y = fy
	Xi_jac.Z.SetInt(1)
	
	proof, err := schnorr.Prove(xiNew, &Xi_jac)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate schnorr proof: %w", err)
	}
	
	// Serialize Proof
	R_jac := *proof.R
	R_jac.ToAffine()
	R_affine := secp256k1.NewPublicKey(&R_jac.X, &R_jac.Y)
	proofR := R_affine.SerializeCompressed()
	
	payload := Round3Payload{
		XiX:    XiX.Bytes(),
		XiY:    XiY.Bytes(),
		ProofR: proofR,
		ProofS: proof.S.Bytes(),
	}
	
	data, err := json.Marshal(payload)
	if err != nil { return nil, nil, err }
	
	msg := &RefreshMessage{
		FromParty:   s.params.PartyID,
		ToParties:   nil,
		IsBcast:     true,
		Data:        data,
		TypeString:  "RefreshRound3",
		RoundNum:    3,
	}
	
	s.receivedMsgs = make(map[string][]tss.Message)
	s.round = 3
	return s, []tss.Message{msg}, nil
}
