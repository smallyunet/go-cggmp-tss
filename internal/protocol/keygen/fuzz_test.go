package keygen

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/curves"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/polynomial"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

func FuzzRound3Decommit(f *testing.F) {
	// Seed corpus
	f.Add([]byte("short"))
	f.Add(make([]byte, 256))    // correct length for N
	f.Add(make([]byte, 256+64)) // correct length for N + 1 point
	f.Add(make([]byte, 1000))   // long

	f.Fuzz(func(t *testing.T, data []byte) {
		// 1. Setup minimal state for round3
		p1 := &MockPartyID{id: "1"}
		p2 := &MockPartyID{id: "2"}

		params := &tss.Parameters{
			PartyID:   p1,
			Parties:   []tss.PartyID{p1, p2},
			Threshold: 1,
			Curve:     "secp256k1",
			SessionID: []byte("fuzz-session"),
		}

		// Mock polynomial
		curve := curves.NewSecp256k1()
		poly, _ := polynomial.New(curve, 1, big.NewInt(100))
		poly.Curve = curve

		s := &state{
			params: params,
			round:  2, // Conceptual state before entering round 3
			saveData: &LocalPartySaveData{
				LocalPartyID: p1,
			},
			tempData:     make(map[string]interface{}),
			receivedMsgs: make(map[string][]tss.Message),
		}

		s.tempData["polynomial"] = poly

		if len(data) < 32 {
			return // Too short for salt
		}

		salt := data[:32]
		msgData := data[32:]

		// 2. Compute valid commitment so Verify passes
		// We use sha256 as in internal/crypto/commitment
		hash := sha256.New()
		hash.Write(salt)
		hash.Write(msgData)
		comm := hash.Sum(nil)

		peerCommitments := map[string][]byte{
			p2.ID(): comm,
		}
		s.tempData["peer_commitments"] = peerCommitments

		// 3. Mock messages
		decommitMsg := &KeyGenMessage{
			FromParty:  p2,
			IsBcast:    true,
			Data:       data, // payload = salt || msgData
			TypeString: "KeyGenRound2_Decommit",
			RoundNum:   2,
		}

		s.receivedMsgs[p2.ID()] = []tss.Message{decommitMsg}

		// Also need Share message or it errors early "missing messages"
		shareMsg := &KeyGenMessage{
			FromParty:  p2,
			IsBcast:    false,
			Data:       []byte("dummy-share"),
			TypeString: "KeyGenRound2_Share",
			RoundNum:   2,
		}
		s.receivedMsgs[p2.ID()] = append(s.receivedMsgs[p2.ID()], shareMsg)

		// 4. Run Round 3 logic via unexported method
		_, _, err := s.round3()

		// We expect error or success, BUT NO PANIC.
		_ = err
	})
}
