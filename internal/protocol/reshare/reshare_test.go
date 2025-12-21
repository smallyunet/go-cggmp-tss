package reshare

import (
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

func TestRefreshE2E(t *testing.T) {
	// 1. Run KeyGen first
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

				// t.Logf("Party %d processing message from %s (Round %d)", i, msg.From().ID(), msg.RoundNumber())
				next, newOut, err := sms[i].Update(msg)
				if err != nil {
					t.Fatalf("Party %d failed: %v", i, err)
				}
				// if next != sms[i] {
				// 	t.Logf("Party %d advanced to %s", i, next.Details())
				// }
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

	// 2. Run Refresh
	refreshSMs := make([]tss.StateMachine, 3)
	refreshOutMsgs := make([][]tss.Message, 3)

	for i := 0; i < 3; i++ {
		params := &tss.Parameters{
			PartyID:   parties[i],
			Parties:   parties,
			Threshold: 1,
			Curve:     "secp256k1",
			SessionID: []byte("test-session-refresh"),
		}
		refreshSMs[i], refreshOutMsgs[i], err = NewStateMachine(params, params, keyData[i])
		if err != nil {
			t.Fatalf("Failed to create refresh state machine: %v", err)
		}
	}

	// Run Refresh rounds (1, 2, 3, 4)
	for r := 1; r <= 4; r++ {
		refreshSMs, refreshOutMsgs = route(refreshSMs, refreshOutMsgs)
	}

	// Collect Refresh results
	newKeyData := make([]*keygen.LocalPartySaveData, 3)
	for i := 0; i < 3; i++ {
		res := refreshSMs[i].Result()
		if res == nil {
			t.Fatalf("Refresh failed for party %d", i)
		}
		newKeyData[i] = res.(*keygen.LocalPartySaveData)

		// Verify Public Key is unchanged
		if newKeyData[i].PublicKeyX.Cmp(keyData[i].PublicKeyX) != 0 ||
			newKeyData[i].PublicKeyY.Cmp(keyData[i].PublicKeyY) != 0 {
			t.Fatalf("Public Key changed for party %d", i)
		}

		// Verify Secret Share changed (likely)
		if newKeyData[i].Xi.Cmp(keyData[i].Xi) == 0 {
			t.Logf("Warning: Secret Share did not change for party %d (unlikely but possible)", i)
		}

		// Verify Paillier Key changed
		if newKeyData[i].PaillierPk.N.Cmp(keyData[i].PaillierPk.N) == 0 {
			t.Fatalf("Paillier Key did not change for party %d", i)
		}
	}
}
