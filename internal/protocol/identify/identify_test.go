package identify

import (
	"math/big"
	"testing"

	"github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

type MockPartyID struct {
	id string
}

func (m *MockPartyID) ID() string      { return m.id }
func (m *MockPartyID) Moniker() string { return m.id }
func (m *MockPartyID) Key() []byte     { return []byte(m.id) }

func TestIdentifyProof(t *testing.T) {
	// 1. Run KeyGen first to get valid key data
	pIDs := []string{"1", "2", "3"}
	parties := make([]tss.PartyID, 3)
	for i, id := range pIDs {
		parties[i] = &MockPartyID{id: id}
	}

	keygenSMs := make([]tss.StateMachine, 3)
	outMsgs := make([][]tss.Message, 3)
	var err error

	for i := 0; i < 3; i++ {
		params := &tss.Parameters{
			PartyID:   parties[i],
			Parties:   parties,
			Threshold: 1,
			Curve:     "secp256k1",
			SessionID: []byte("test-session"),
		}
		keygenSMs[i], outMsgs[i], err = keygen.NewStateMachine(params)
		if err != nil {
			t.Fatalf("Failed to create keygen state machine: %v", err)
		}
	}

	route := func(sms []tss.StateMachine, outMsgs [][]tss.Message) ([]tss.StateMachine, [][]tss.Message) {
		allMsgs := []tss.Message{}
		for _, msgs := range outMsgs {
			allMsgs = append(allMsgs, msgs...)
		}
		newOutMsgs := make([][]tss.Message, 3)

		for i := 0; i < 3; i++ {
			if sms[i] == nil {
				continue
			}

			for _, msg := range allMsgs {
				if msg.From().ID() == parties[i].ID() {
					continue
				}
				if !msg.IsBroadcast() {
					found := false
					for _, dest := range msg.To() {
						if dest.ID() == parties[i].ID() {
							found = true
							break
						}
					}
					if !found {
						continue
					}
				}

				next, newOut, err := sms[i].Update(msg)
				if err != nil {
					t.Fatalf("Party %d failed: %v", i, err)
				}
				sms[i] = next
				if newOut != nil {
					newOutMsgs[i] = append(newOutMsgs[i], newOut...)
				}
			}
		}
		return sms, newOutMsgs
	}

	// Run KeyGen rounds
	for r := 1; r <= 4; r++ {
		keygenSMs, outMsgs = route(keygenSMs, outMsgs)
	}

	// Collect KeyGen results
	keyData := make([]*keygen.LocalPartySaveData, 3)
	for i := 0; i < 3; i++ {
		res := keygenSMs[i].Result()
		if res == nil {
			t.Fatalf("KeyGen failed for party %d", i)
		}
		keyData[i] = res.(*keygen.LocalPartySaveData)
	}

	// 2. Test Identification Protocol
	t.Run("SingleProofGenAndVerify", func(t *testing.T) {
		params := &tss.Parameters{
			PartyID:   parties[0],
			Parties:   parties,
			Threshold: 1,
			Curve:     "secp256k1",
			SessionID: []byte("test-session-identify"),
		}

		proof, err := NewIdentifyProof(params, keyData[0])
		if err != nil {
			t.Fatalf("Failed to create identify proof: %v", err)
		}

		if !VerifyIdentifyProof(proof) {
			t.Fatal("Valid proof failed verification")
		}

		if proof.PartyID != "1" {
			t.Fatalf("Expected party ID '1', got '%s'", proof.PartyID)
		}
	})

	t.Run("IdentifySessionE2E", func(t *testing.T) {
		sessions := make([]*IdentifySession, 3)
		proofs := make([]*IdentifyProof, 3)

		// Create sessions for all parties
		for i := 0; i < 3; i++ {
			params := &tss.Parameters{
				PartyID:   parties[i],
				Parties:   parties,
				Threshold: 1,
				Curve:     "secp256k1",
				SessionID: []byte("test-session-identify"),
			}

			session, proof, err := NewIdentifySession(params, keyData[i])
			if err != nil {
				t.Fatalf("Failed to create identify session for party %d: %v", i, err)
			}
			sessions[i] = session
			proofs[i] = proof
		}

		// Exchange proofs
		for i := 0; i < 3; i++ {
			for j := 0; j < 3; j++ {
				if i == j {
					continue
				}
				err := sessions[i].AddPeerProof(proofs[j], keyData[j].XiX, keyData[j].XiY)
				if err != nil {
					t.Fatalf("Party %d failed to verify proof from party %d: %v", i, j, err)
				}
			}
		}

		// Check completion
		for i := 0; i < 3; i++ {
			if !sessions[i].IsComplete() {
				t.Fatalf("Session %d not complete", i)
			}
		}
	})

	t.Run("InvalidProofRejected", func(t *testing.T) {
		params := &tss.Parameters{
			PartyID:   parties[0],
			Parties:   parties,
			Threshold: 1,
			Curve:     "secp256k1",
			SessionID: []byte("test-session-identify"),
		}

		proof, err := NewIdentifyProof(params, keyData[0])
		if err != nil {
			t.Fatalf("Failed to create identify proof: %v", err)
		}

		// Tamper with the proof
		proof.Proof.S.Add(proof.Proof.S, big.NewInt(1))

		if VerifyIdentifyProof(proof) {
			t.Fatal("Tampered proof should fail verification")
		}
	})
}
