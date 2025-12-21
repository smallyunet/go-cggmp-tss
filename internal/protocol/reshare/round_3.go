package reshare

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/commitment"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/curves"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
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
	// New Parties receive shares and decommitments
	// Old Parties might verify decommitments if they are also New (conceptually)

	if !s.isNewCommittee {
		// Old-only parties just move to next round or finish?
		// They need to wait for completion?
		// For now, let's just finish the round logic but produce no result.
		// Actually, Old parties also receive decommitments from New Parties (Paillier PKs),
		// but they don't need to compute keys.
		// Let's assume Old-Only parties just proceed.
		s.receivedMsgs = make(map[string][]tss.Message)
		s.round = 3
		// Broadcast Round 3 message? No, verification result?
		// In Refresh/Reshare, Round 3 message is usually the ZK Proof of the new key.
		// Since Old parties don't have a new key, they might just stay silent or wait.

		// If I am NOT new, I don't have shareSum, so I can't generate Schnorr Proof.
		// So checking "isNewCommittee" is crucial.

		// Just wait for messages for Round 4?
		// Wait, Round 4 expects Schnorr Proofs from EVERYONE in NEW committee.
		// Old Parties don't send Schnorr Proofs unless they are in New committee.
		// So Old-only parties are effectively done after Round 2?
		// Or they wait to verify everything.

		// Let's return, assuming checks in Update will handle them.
		s.round = 3
		return s, nil, nil
	}

	// I am a New Party (Receiver)

	peerCommitments, _ := s.tempData["peer_commitments"].(map[string][]byte)
	// We might not have 'polynomial' if we are New-Only party
	// But we need the curve.
	// We used polynomial in Round 1 only if we were Old.
	// So we create a dummy curve instance.
	curve := curves.NewSecp256k1()
	N := curve.Params().N

	// My Index in NEW committee
	myIdx := new(big.Int)
	// Find my index in s.params.Parties
	found := false
	for i, p := range s.params.Parties {
		if p.ID() == s.params.PartyID.ID() {
			myIdx.SetInt64(int64(i + 1)) // 1-based index
			found = true
			break
		}
	}
	if !found {
		return nil, nil, fmt.Errorf("party not found in new committee")
	}

	shareSum := big.NewInt(0)

	// Keep track of which Old Parties sent us shares
	// We assume ALL Old Parties must participate for reconstruction
	participatingOldIDs := make([]*big.Int, 0, len(s.oldParams.Parties))
	for i := range s.oldParams.Parties {
		participatingOldIDs = append(participatingOldIDs, big.NewInt(int64(i+1)))
	}

	// Helper to find index of a party in Old Committee
	getOldPartyIndex := func(id string) int {
		for i, p := range s.oldParams.Parties {
			if p.ID() == id {
				return i + 1
			}
		}
		return -1
	}

	// Iterate over peers
	for id, msgs := range s.receivedMsgs {
		var decommitMsg, shareMsg tss.Message
		for _, m := range msgs {
			if m.Type() == "ReshareRound2_Decommit" {
				decommitMsg = m
			} else if m.Type() == "ReshareRound2_Share" {
				shareMsg = m
			}
		}

		// If peer is Old Party, we expect Share.
		// If peer is New-Only, we assume they only sent Decommit (Paillier).
		// Wait, did New Parties send Decommit? Yes.

		// Verify Decommitment
		if decommitMsg != nil {
			payload := decommitMsg.Payload()
			// Basic check
			if len(payload) < 32 {
				return nil, nil, fmt.Errorf("invalid decommitment")
			}
			salt := payload[:32]
			data := payload[32:]

			if !commitment.Verify(peerCommitments[id], salt, data) {
				return nil, nil, tss.NewBlame(decommitMsg.From(), "commitment verification failed", nil)
			}

			// Parse Data to extract VSS (if any)
			type CommitData struct {
				PaillierN []byte     `json:"paillier_n,omitempty"`
				VSS       []*big.Int `json:"vss,omitempty"`
			}
			var cData CommitData
			if err := json.Unmarshal(data, &cData); err != nil {
				return nil, nil, fmt.Errorf("failed to unmarshal commit data from %s: %w", id, err)
			}

			// Store Paillier PK (from peers in New Committee)
			// But wait, do we need Paillier keys of New Committee?
			// Usually for MtA during Signing. So yes, keep them.
			if cData.PaillierN != nil {
				paillierN := new(big.Int).SetBytes(cData.PaillierN)
				peerPk := &paillier.PublicKey{N: paillierN, N2: new(big.Int).Mul(paillierN, paillierN)}

				if s.saveData.PeerPaillierPks == nil {
					s.saveData.PeerPaillierPks = make(map[string]*paillier.PublicKey)
				}
				s.saveData.PeerPaillierPks[id] = peerPk
			}

			// If message has VSS, we verify the Share
			if cData.VSS != nil && shareMsg != nil {
				// 1. Verify Share against VSS
				share := new(big.Int).SetBytes(shareMsg.Payload())

				shareG_x, shareG_y := curve.ScalarBaseMult(share)

				// Evaluate VSS Poly at My Index (myIdx)
				var rhsX, rhsY *big.Int
				for k := 0; k < len(cData.VSS)/2; k++ {
					akX := cData.VSS[k*2]
					akY := cData.VSS[k*2+1]

					scalar := new(big.Int).Exp(myIdx, big.NewInt(int64(k)), N)
					termX, termY := curve.ScalarMult(akX, akY, scalar)

					if k == 0 {
						rhsX, rhsY = termX, termY
					} else {
						rhsX, rhsY = curve.Add(rhsX, rhsY, termX, termY)
					}
				}

				if shareG_x.Cmp(rhsX) != 0 || shareG_y.Cmp(rhsY) != 0 {
					return nil, nil, tss.NewBlame(shareMsg.From(), "vss share verification failed", nil)
				}

				// 2. Add weighted share to sum
				// Calculate Lagrange Coefficient for this Sender (Old Party j)
				// L_j(0) = product_{k != j} (0 - x_k) / (x_j - x_k)

				senderIdxVal := getOldPartyIndex(id)
				if senderIdxVal == -1 {
					// Should not happen if we trusted params
					continue
				}
				senderIdx := big.NewInt(int64(senderIdxVal))

				lagrange := big.NewInt(1)
				for _, k := range participatingOldIDs {
					if k.Cmp(senderIdx) == 0 {
						continue
					}
					// num = 0 - k = -k
					num := new(big.Int).Sub(big.NewInt(0), k)
					num.Mod(num, N)

					// den = j - k
					den := new(big.Int).Sub(senderIdx, k)
					den.Mod(den, N)

					// invDen = den^-1
					invDen := new(big.Int).ModInverse(den, N)

					term := new(big.Int).Mul(num, invDen)
					term.Mod(term, N)

					lagrange.Mul(lagrange, term)
					lagrange.Mod(lagrange, N)
				}

				// weightedShare = share * lambda_j
				weightedShare := new(big.Int).Mul(share, lagrange)
				weightedShare.Mod(weightedShare, N)

				shareSum.Add(shareSum, weightedShare)
				shareSum.Mod(shareSum, N)
			}
		}
	}

	// Process Self Share (if any)
	if selfShareVal, ok := s.tempData["self_share"].(*big.Int); ok {
		// I am an Old Party and I sent a share to myself (New Party)
		// I act as 'sender'
		senderIdxVal := getOldPartyIndex(s.params.PartyID.ID())
		if senderIdxVal != -1 {
			senderIdx := big.NewInt(int64(senderIdxVal))

			lagrange := big.NewInt(1)
			for _, k := range participatingOldIDs {
				if k.Cmp(senderIdx) == 0 {
					continue
				}
				num := new(big.Int).Sub(big.NewInt(0), k)
				num.Mod(num, N)
				den := new(big.Int).Sub(senderIdx, k)
				den.Mod(den, N)
				invDen := new(big.Int).ModInverse(den, N)
				term := new(big.Int).Mul(num, invDen)
				term.Mod(term, N)
				lagrange.Mul(lagrange, term)
				lagrange.Mod(lagrange, N)
			}

			weightedShare := new(big.Int).Mul(selfShareVal, lagrange)
			weightedShare.Mod(weightedShare, N)

			shareSum.Add(shareSum, weightedShare)
			shareSum.Mod(shareSum, N)
		}
	}

	// Update Secret Key
	// For New Party: xiNew = sum(share * lambda)
	// (Note: s.oldKeyData might be nil if I was not in old committee)

	s.saveData.Xi = shareSum
	s.saveData.ShareID = myIdx

	// Calculate new Public Key Share X_i
	XiX, XiY := curve.ScalarBaseMult(shareSum)
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

	proof, err := schnorr.Prove(shareSum, &Xi_jac)
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
	if err != nil {
		return nil, nil, err
	}

	msg := &ReshareMessage{
		FromParty:  s.params.PartyID,
		ToParties:  nil,
		IsBcast:    true,
		Data:       data,
		TypeString: "ReshareRound3",
		RoundNum:   3,
	}

	s.receivedMsgs = make(map[string][]tss.Message)
	s.round = 3
	return s, []tss.Message{msg}, nil
}
