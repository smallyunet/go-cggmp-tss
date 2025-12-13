package keygen

import (
	"testing"

	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

type MockPartyID struct {
	id string
}

func (m *MockPartyID) ID() string      { return m.id }
func (m *MockPartyID) Moniker() string { return m.id }
func (m *MockPartyID) Key() []byte     { return []byte(m.id) }

func TestRound1(t *testing.T) {
	p1 := &MockPartyID{id: "1"}
	p2 := &MockPartyID{id: "2"}
	p3 := &MockPartyID{id: "3"}

	params := &tss.Parameters{
		PartyID:   p1,
		Parties:   []tss.PartyID{p1, p2, p3},
		Threshold: 2,
		Curve:     "secp256k1",
		SessionID: []byte("test-session"),
	}

	sm, msgs, err := NewStateMachine(params)
	if err != nil {
		t.Fatalf("Failed to create state machine: %v", err)
	}

	if len(msgs) != 1 {
		t.Errorf("Expected 1 message, got %d", len(msgs))
	}

	msg := msgs[0]
	if msg.RoundNumber() != 1 {
		t.Errorf("Expected round 1, got %d", msg.RoundNumber())
	}
	if !msg.IsBroadcast() {
		t.Errorf("Expected broadcast message")
	}

	// Check internal state
	s, ok := sm.(*state)
	if !ok {
		t.Fatal("StateMachine is not of type *state")
	}

	if s.saveData.PaillierSk == nil {
		t.Error("Paillier key not generated")
	}
	if _, ok := s.tempData["round1_decommit"]; !ok {
		t.Error("Decommitment not stored")
	}
}

func TestRound2Transition(t *testing.T) {
	p1 := &MockPartyID{id: "1"}
	p2 := &MockPartyID{id: "2"}
	p3 := &MockPartyID{id: "3"}

	params := &tss.Parameters{
		PartyID:   p1,
		Parties:   []tss.PartyID{p1, p2, p3},
		Threshold: 2,
		Curve:     "secp256k1",
		SessionID: []byte("test-session"),
	}

	// Start Round 1
	sm, _, err := NewStateMachine(params)
	if err != nil {
		t.Fatalf("Failed to create state machine: %v", err)
	}

	// Simulate receiving Round 1 messages from p2 and p3
	// In reality, these would be valid commitments, but for this test, 
	// the state machine only checks existence and round number currently.
	msg2 := &KeyGenMessage{
		FromParty:  p2,
		IsBcast:    true,
		Data:       []byte("commitment_from_2"),
		TypeString: "KeyGenRound1",
		RoundNum:   1,
	}
	msg3 := &KeyGenMessage{
		FromParty:  p3,
		IsBcast:    true,
		Data:       []byte("commitment_from_3"),
		TypeString: "KeyGenRound1",
		RoundNum:   1,
	}

	// Update with msg2
	nextSm, outMsgs, err := sm.Update(msg2)
	if err != nil {
		t.Fatalf("Failed to update with msg2: %v", err)
	}
	if outMsgs != nil {
		t.Error("Expected no output messages yet")
	}
	// State should still be same object (conceptually, though implementation returns 's')
	// but round should still be 1

	// Update with msg3 (should trigger transition)
	nextSm, outMsgs, err = nextSm.Update(msg3)
	if err != nil {
		t.Fatalf("Failed to update with msg3: %v", err)
	}

	if len(outMsgs) == 0 {
		t.Fatal("Expected output messages for Round 2")
	}

	// Expect 1 broadcast (Decommit) + 2 P2P (Shares) = 3 messages
	// Wait, we send shares to ALL other parties. n=3, so 2 peers.
	if len(outMsgs) != 3 {
		t.Errorf("Expected 3 messages, got %d", len(outMsgs))
	}

	// Check message types
	broadcastCount := 0
	p2pCount := 0
	for _, m := range outMsgs {
		if m.RoundNumber() != 2 {
			t.Errorf("Expected round 2 message, got %d", m.RoundNumber())
		}
		if m.IsBroadcast() {
			broadcastCount++
			if m.Type() != "KeyGenRound2_Decommit" {
				t.Errorf("Expected Decommit message type, got %s", m.Type())
			}
		} else {
			p2pCount++
			if m.Type() != "KeyGenRound2_Share" {
				t.Errorf("Expected Share message type, got %s", m.Type())
			}
		}
	}

	if broadcastCount != 1 {
		t.Errorf("Expected 1 broadcast message, got %d", broadcastCount)
	}
	if p2pCount != 2 {
		t.Errorf("Expected 2 P2P messages, got %d", p2pCount)
	}

	// Check new state
	s, ok := nextSm.(*state)
	if !ok {
		t.Fatal("New state is not *state")
	}
	if s.round != 2 {
		t.Errorf("Expected state to be in round 2, got %d", s.round)
	}
}
