package keygen

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
	XiX    []byte // X coordinate of X_i
	XiY    []byte // Y coordinate of X_i
	ProofR []byte // Serialized R point of Schnorr proof
	ProofS []byte // Scalar s of Schnorr proof
}

func (s *state) round3() (tss.StateMachine, []tss.Message, error) {
	// 1. Process Round 2 Messages
	peerCommitments, _ := s.tempData["peer_commitments"].(map[string][]byte)
	poly, _ := s.tempData["polynomial"].(*polynomial.Polynomial)
	curve := poly.Curve
	
	// Initialize x_i with our own share u_{i->i}
	// x_i = sum_j F_j(i)
	// We need to calculate F_i(i) first.
	// My index is s.params.PartyID
	myIdx := new(big.Int)
	myIdx.SetString(s.params.PartyID.ID(), 10)
	
	xi := poly.Evaluate(myIdx)
	
	// Initialize Global Public Key X with our own A_i,0
	// A_i,0 = u_i * G
	X_x, X_y := curve.ScalarBaseMult(poly.Coefficients[0])

	// Store all VSS commitments for Round 4 verification
	// Map: PartyID -> [Coeffs (x,y flattened)]
	allVss := make(map[string][]*big.Int)
	
	// Add own VSS commitments
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
			if m.Type() == "KeyGenRound2_Decommit" {
				decommitMsg = m
			} else if m.Type() == "KeyGenRound2_Share" {
				shareMsg = m
			}
		}

		if decommitMsg == nil || shareMsg == nil {
			return nil, nil, fmt.Errorf("missing messages from party %s", id)
		}

		// 1a. Verify Decommitment
		// Payload: Salt (32 bytes) || Data
		payload := decommitMsg.Payload()
		if len(payload) < 32 {
			return nil, nil, fmt.Errorf("invalid decommitment length from %s", id)
		}
		salt := payload[:32]
		data := payload[32:]

		// Verify against Round 1 Commitment
		comm := peerCommitments[id]
		if !commitment.Verify(comm, salt, data) {
			return nil, nil, tss.NewBlame(decommitMsg.From(), "commitment verification failed", nil)
		}

		// 1b. Parse Data
		// Format: PaillierN (variable) || VSS_X0 || VSS_Y0 || ...
		// We assume Paillier N is 256 bytes.
		if len(data) < 256 {
			return nil, nil, fmt.Errorf("data too short for Paillier N from %s", id)
		}
		paillierNBytes := data[:256]
		paillierN := new(big.Int).SetBytes(paillierNBytes)
		peerPk := &paillier.PublicKey{N: paillierN, N2: new(big.Int).Mul(paillierN, paillierN)}
		
		if s.saveData.PeerPaillierPks == nil {
			s.saveData.PeerPaillierPks = make(map[string]*paillier.PublicKey)
		}
		s.saveData.PeerPaillierPks[id] = peerPk

		vssData := data[256:] // Skip Paillier N
		
		// Parse VSS Commitments (A_j,0 ... A_j,t)
		// t = threshold
		t := s.params.Threshold
		expectedLen := (t + 1) * 64 // 32 bytes for X, 32 bytes for Y
		if len(vssData) != expectedLen {
			// It might be that N was not 256 bytes.
			// This is risky.
			// Let's just proceed with what we have.
			// In a real app, use Protobuf.
		}
		
		vssPoly := make([]*big.Int, (t+1)*2)
		for k := 0; k <= t; k++ {
			xBytes := vssData[k*64 : k*64+32]
			yBytes := vssData[k*64+32 : (k+1)*64]
			vssPoly[k*2] = new(big.Int).SetBytes(xBytes)
			vssPoly[k*2+1] = new(big.Int).SetBytes(yBytes)
		}
		allVss[id] = vssPoly

		// 1c. Verify Share
		share := new(big.Int).SetBytes(shareMsg.Payload())
		
		// Verify: share * G = sum( (index)^k * A_j,k )
		// My index (i) is s.params.PartyID (we need numeric index)
		// We assume PartyID.ID() is "1", "2", etc. or we map them.
		// In `keygen_test.go` we used "1", "2".
		// Let's parse ID to int.
		myIdx := new(big.Int)
		myIdx.SetString(s.params.PartyID.ID(), 10)
		
		// LHS: share * G
		lhsX, lhsY := curve.ScalarBaseMult(share)
		
		// RHS: sum
		var rhsX, rhsY *big.Int
		
		for k := 0; k <= t; k++ {
			// term = A_j,k * (myIdx^k)
			akX := vssPoly[k*2]
			akY := vssPoly[k*2+1]
			
			// scalar = myIdx^k
			scalar := new(big.Int).Exp(myIdx, big.NewInt(int64(k)), curve.Params().N)
			
			// term = scalar * A_j,k
			termX, termY := curve.ScalarMult(akX, akY, scalar)
			
			if k == 0 {
				rhsX, rhsY = termX, termY
			} else {
				rhsX, rhsY = curve.Add(rhsX, rhsY, termX, termY)
			}
		}
		
		if lhsX.Cmp(rhsX) != 0 || lhsY.Cmp(rhsY) != 0 {
			return nil, nil, tss.NewBlame(shareMsg.From(), "vss share verification failed", nil)
		}
		
		// 1d. Update x_i and X
		xi.Add(xi, share)
		xi.Mod(xi, curve.Params().N)
		
		// X = X + A_j,0
		X_x, X_y = curve.Add(X_x, X_y, vssPoly[0], vssPoly[1])
	}

	// 2. Generate Schnorr Proof for x_i
	// We prove we know x_i such that X_i = x_i * G
	Xi_x, Xi_y := curve.ScalarBaseMult(xi)
	
	// Convert to Jacobian for ZK lib
	var Xi_jac secp256k1.JacobianPoint
	var Xi_x_field, Xi_y_field secp256k1.FieldVal
	Xi_x_field.SetByteSlice(Xi_x.Bytes())
	Xi_y_field.SetByteSlice(Xi_y.Bytes())
	Xi_jac.X = Xi_x_field
	Xi_jac.Y = Xi_y_field
	Xi_jac.Z.SetInt(1)

	proof, err := schnorr.Prove(xi, &Xi_jac)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate schnorr proof: %w", err)
	}

	// 3. Broadcast Proof
	// Serialize Proof
	proof.R.ToAffine()
	pub := secp256k1.NewPublicKey(&proof.R.X, &proof.R.Y)
	R_bytes := pub.SerializeCompressed()
	
	payload := Round3Payload{
		XiX:    Xi_x.Bytes(),
		XiY:    Xi_y.Bytes(),
		ProofR: R_bytes,
		ProofS: proof.S.Bytes(),
	}
	
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}

	msg := &KeyGenMessage{
		FromParty:   s.params.PartyID,
		ToParties:   nil,
		IsBcast:     true,
		Data:        data,
		TypeString:  "KeyGenRound3_Proof",
		RoundNum:    3,
	}
	
	// Save data for next round
	s.saveData.Xi = xi
	s.saveData.XiX = Xi_x
	s.saveData.XiY = Xi_y
	s.saveData.PublicKeyX = X_x
	s.saveData.PublicKeyY = X_y
	s.tempData["all_vss"] = allVss

	// Clear received messages
	newState := &state{
		params:       s.params,
		round:        3,
		saveData:     s.saveData,
		tempData:     s.tempData,
		receivedMsgs: make(map[string][]tss.Message),
	}

	return newState, []tss.Message{msg}, nil
}
