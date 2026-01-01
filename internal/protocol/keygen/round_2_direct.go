package keygen

import (
	"fmt"
	"math/big"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/polynomial"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// round2Direct processes the direct messages from Round 1 and finalizes the key generation.
func (s *state) round2Direct() (tss.StateMachine, []tss.Message, error) {
	// We have received "KeyGen1Round_Direct_Broadcast" and "KeyGen1Round_Direct_Share" from all peers.

	// Retrieve our polynomial
	poly, ok := s.tempData["polynomial"].(*polynomial.Polynomial)
	if !ok {
		return nil, nil, fmt.Errorf("missing polynomial")
	}
	curve := poly.Curve

	// Prepare to calculate x_i
	myIdx := new(big.Int)
	myIdx.SetString(s.params.PartyID.ID(), 10)

	// x_i starts with our own share F_i(i)
	xi := poly.Evaluate(myIdx)

	// X (Public Key) starts with our own A_i,0
	X_x, X_y := curve.ScalarBaseMult(poly.Coefficients[0])

	// Save our own VSS for completeness in `allVss`
	allVss := make(map[string][]*big.Int)
	ownVss := make([]*big.Int, len(poly.Coefficients)*2)
	for k, c := range poly.Coefficients {
		x, y := curve.ScalarBaseMult(c)
		ownVss[k*2] = x
		ownVss[k*2+1] = y
	}
	allVss[s.params.PartyID.ID()] = ownVss

	s.saveData.PeerPaillierPks = make(map[string]*paillier.PublicKey)

	// Iterate over messages
	for id, msgs := range s.receivedMsgs {
		var bcastMsg, shareMsg tss.Message
		for _, m := range msgs {
			if m.Type() == "KeyGen1Round_Direct_Broadcast" {
				bcastMsg = m
			} else if m.Type() == "KeyGen1Round_Direct_Share" {
				shareMsg = m
			}
		}

		if bcastMsg == nil || shareMsg == nil {
			return nil, nil, fmt.Errorf("missing messages from party %s", id)
		}

		// 1. Process Broadcast Data (PaillierPK || VSS_Commitments)
		data := bcastMsg.Payload()
		if len(data) < 256 {
			return nil, nil, fmt.Errorf("data too short for Paillier N from %s", id)
		}

		paillierNBytes := data[:256]
		paillierN := new(big.Int).SetBytes(paillierNBytes)
		peerPk := &paillier.PublicKey{N: paillierN, N2: new(big.Int).Mul(paillierN, paillierN)}
		s.saveData.PeerPaillierPks[id] = peerPk

		vssData := data[256:]
		t := s.params.Threshold
		expectedLen := (t + 1) * 64
		if len(vssData) != expectedLen {
			return nil, nil, fmt.Errorf("vss data length mismatch from %s: expected %d, got %d", id, expectedLen, len(vssData))
		}

		vssPoly := make([]*big.Int, (t+1)*2)
		for k := 0; k <= t; k++ {
			xBytes := vssData[k*64 : k*64+32]
			yBytes := vssData[k*64+32 : (k+1)*64]
			vssPoly[k*2] = new(big.Int).SetBytes(xBytes)
			vssPoly[k*2+1] = new(big.Int).SetBytes(yBytes)
		}

		fmt.Printf("DEBUG: Receiver %s parsed VSS from %s: C0=(%s, %s)\n", s.params.PartyID.ID(), id, vssPoly[0].String(), vssPoly[1].String())
		if len(vssPoly) > 2 {
			fmt.Printf("DEBUG: Receiver %s parsed VSS from %s: C1=(%s, %s)\n", s.params.PartyID.ID(), id, vssPoly[2].String(), vssPoly[3].String())
		}

		allVss[id] = vssPoly

		// 2. Verify Share
		share := new(big.Int).SetBytes(shareMsg.Payload())

		// LHS: share * G
		lhsX, lhsY := curve.ScalarBaseMult(share)

		// RHS: sum( A_j,k * i^k )
		var rhsX, rhsY *big.Int
		for k := 0; k <= t; k++ {
			akX := vssPoly[k*2]
			akY := vssPoly[k*2+1]
			scalar := new(big.Int).Exp(myIdx, big.NewInt(int64(k)), curve.Params().N)
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

		// Update x_i and X
		xi.Add(xi, share)
		xi.Mod(xi, curve.Params().N)

		X_x, X_y = curve.Add(X_x, X_y, vssPoly[0], vssPoly[1])
	}

	// 3. Generate Schnorr Proof for x_i (for consistency with standard keygen result)
	// We might want to broadcast this in a "Round 2" if we need everyone to verify proofs.
	// But "1-Round" implies we are done exchanging key material.
	// If the user wants to verify the resulting public key is correct, they need these proofs.
	// Strictly speaking, if we want "1 Round" to mean "1 Round of Key Exchange", we can output the key now.
	// But usually "KeyGen" includes proof of possession.
	// If we output now, we can compute the proof and store it, or broadcast it?
	// If we broadcast it, that's a 2nd round.
	// The implementation plan said: "Decision: We will return the finished state immediately... Proofs can be done in a separate Identify protocol".
	// So we won't broadcast proofs here.
	// We will just compute the final result and finish.

	// Calculate public key share X_i = x_i * G
	Xi_x, Xi_y := curve.ScalarBaseMult(xi)

	// Save data
	s.saveData.Xi = xi
	s.saveData.XiX = Xi_x
	s.saveData.XiY = Xi_y
	s.saveData.PublicKeyX = X_x
	s.saveData.PublicKeyY = X_y
	// We also save allVss if needed for future
	// s.tempData["all_vss"] = allVss // Not strict require for result

	// Return finished state
	return &finishedState{data: s.saveData}, nil, nil
}
