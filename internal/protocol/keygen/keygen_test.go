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
