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

func TestReshareE2E(t *testing.T) {
	// Scenario: Committee Change
	// Old: 1, 2, 3 (t=1)
	// New: 1, 2, 4 (t=1)

	allIDs := []string{"1", "2", "3", "4"}
	allParties := make(map[string]tss.PartyID)
	for _, id := range allIDs {
		allParties[id] = &MockPartyID{id: id}
	}

	oldCommitteeIDs := []string{"1", "2", "3"}
	newCommitteeIDs := []string{"1", "2", "4"}

	// 1. KeyGen on Old Committee
	keygenParties := make([]tss.PartyID, 3)
	for i, id := range oldCommitteeIDs {
		keygenParties[i] = allParties[id]
	}

	keygenSMs := make(map[string]tss.StateMachine)
	outMsgs := make(map[string][]tss.Message)

	for _, id := range oldCommitteeIDs {
		p := allParties[id]
		params := &tss.Parameters{
			PartyID:   p,
			Parties:   keygenParties,
			Threshold: 1,
			Curve:     "secp256k1",
			SessionID: []byte("test-session-keygen"),
		}
		sm, msgs, err := keygen.NewStateMachine(params)
		if err != nil {
			t.Fatalf("Failed to create keygen state machine for %s: %v", id, err)
		}
		keygenSMs[id] = sm
		outMsgs[id] = msgs
	}

	// Helper Router for Map-based SMs
	route := func(sms map[string]tss.StateMachine, currentOutMsgs map[string][]tss.Message) (map[string]tss.StateMachine, map[string][]tss.Message) {
		allPendingMsgs := []tss.Message{}
		for _, msgs := range currentOutMsgs {
			allPendingMsgs = append(allPendingMsgs, msgs...)
		}
		newOutMsgs := make(map[string][]tss.Message)

		// Map ID -> SM
		// Iterate in sorted order to be deterministic
		sortedIDs := make([]string, 0, len(sms))
		for id := range sms {
			sortedIDs = append(sortedIDs, id)
		}
		// Sort basic string sort
		for i := 0; i < len(sortedIDs); i++ {
			for j := i + 1; j < len(sortedIDs); j++ {
				if sortedIDs[i] > sortedIDs[j] {
					sortedIDs[i], sortedIDs[j] = sortedIDs[j], sortedIDs[i]
				}
			}
		}

		for _, id := range sortedIDs {
			sm := sms[id]
			if sm == nil {
				continue
			}

			for _, msg := range allPendingMsgs {
				senderID := msg.From().ID()
				if senderID == id {
					continue // Don't receive own messages
				}

				shouldReceive := false
				if msg.IsBroadcast() {
					shouldReceive = true
					// For broadcast, we ideally check if I am in the session?
					// Simplified: everyone receives broadcast.
				} else {
					for _, dest := range msg.To() {
						if dest.ID() == id {
							shouldReceive = true
							break
						}
					}
				}

				if !shouldReceive {
					continue
				}

				next, newOut, err := sm.Update(msg)
				if err != nil {
					t.Fatalf("Party %s failed at round %d processing msg from %s: %v", id, chainMsgRound(msg), senderID, err)
				}
				if next == nil {
					t.Fatalf("Party %s Update returned nil next state (msg From: %s Round: %d)", id, senderID, chainMsgRound(msg))
				}
				sms[id] = next
				if newOut != nil {
					newOutMsgs[id] = append(newOutMsgs[id], newOut...)
				}
			}
		}
		return sms, newOutMsgs
	}

	// Run KeyGen (4 rounds)
	for r := 1; r <= 4; r++ {
		keygenSMs, outMsgs = route(keygenSMs, outMsgs)
	}

	// Collect Old Keys
	oldKeyData := make(map[string]*keygen.LocalPartySaveData)
	for _, id := range oldCommitteeIDs {
		res := keygenSMs[id].Result()
		if res == nil {
			t.Fatalf("KeyGen failed for party %s", id)
		}
		oldKeyData[id] = res.(*keygen.LocalPartySaveData)
	}

	// 2. Reshare Logic
	reshareParties := make([]tss.PartyID, 3)
	for i, id := range newCommitteeIDs {
		reshareParties[i] = allParties[id]
	}

	oldParams := &tss.Parameters{
		Parties:   keygenParties,
		Threshold: 1,
		Curve:     "secp256k1",
	}

	reshareSMs := make(map[string]tss.StateMachine)
	reshareOutMsgs := make(map[string][]tss.Message)

	// Initialize Reshare for ALL involved parties (Union of Old and New)
	// Union: 1, 2, 3, 4
	unionIDs := []string{"1", "2", "3", "4"}

	for _, id := range unionIDs {
		p := allParties[id]

		newParams := &tss.Parameters{
			PartyID:   p,
			Parties:   reshareParties, // The NEW committee list
			Threshold: 1,
			Curve:     "secp256k1",
			SessionID: []byte("test-session-reshare"),
		}

		// Prepare old data if this party was in old committee
		var myOldData *keygen.LocalPartySaveData
		if contains(oldCommitteeIDs, id) {
			myOldData = oldKeyData[id]
		}

		sm, msgs, err := NewStateMachine(newParams, oldParams, myOldData)
		if err != nil {
			// It is expected to fail if party is NOT in Old AND NOT in New?
			// But here {1,2,3,4} are all involved.
			// 3 is Old-Only. 4 is New-Only. 1,2 are Both.
			t.Fatalf("Failed to create reshare SM for %s: %v", id, err)
		}
		reshareSMs[id] = sm
		reshareOutMsgs[id] = msgs
	}

	// Run Reshare Rounds (1 to 4)
	for r := 1; r <= 4; r++ {
		// Optimization: Check if all finished?
		reshareSMs, reshareOutMsgs = route(reshareSMs, reshareOutMsgs)
	}

	// 3. Verify Results
	// Check New Committee Members (1, 2, 4)
	for _, id := range newCommitteeIDs {
		res := reshareSMs[id].Result()
		if res == nil {
			t.Fatalf("Reshare failed for new party %s", id)
		}
		newData := res.(*keygen.LocalPartySaveData)

		// 1. Validate Public Key is preserved
		originalPK := oldKeyData["1"].PublicKeyX // assume 1 was in old
		if newData.PublicKeyX.Cmp(originalPK) != 0 {
			t.Fatalf("Public Key changed for party %s", id)
		}

		// 2. Validate New Secret Shares are present
		if newData.Xi == nil {
			t.Fatalf("Party %s missing new secret share", id)
		}
	}
}

func contains(list []string, item string) bool {
	for _, x := range list {
		if x == item {
			return true
		}
	}
	return false
}

func chainMsgRound(msg tss.Message) uint32 {
	if msg == nil {
		return 0
	}
	return msg.RoundNumber()
}
