package tss

import (
	"testing"
)

// MockPartyID implements PartyID for testing purposes.
type MockPartyID struct {
	id      string
	moniker string
	key     []byte
}

func (m *MockPartyID) ID() string {
	return m.id
}

func (m *MockPartyID) Moniker() string {
	return m.moniker
}

func (m *MockPartyID) Key() []byte {
	return m.key
}

// MockMessage implements Message for testing purposes.
type MockMessage struct {
	msgType     string
	from        PartyID
	to          []PartyID
	isBroadcast bool
	payload     []byte
	round       uint32
}

func (m *MockMessage) Type() string {
	return m.msgType
}

func (m *MockMessage) From() PartyID {
	return m.from
}

func (m *MockMessage) To() []PartyID {
	return m.to
}

func (m *MockMessage) IsBroadcast() bool {
	return m.isBroadcast
}

func (m *MockMessage) Payload() []byte {
	return m.payload
}

func (m *MockMessage) RoundNumber() uint32 {
	return m.round
}

func TestInterfaces(t *testing.T) {
	// Verify MockPartyID implements PartyID
	var _ PartyID = &MockPartyID{}

	// Verify MockMessage implements Message
	var _ Message = &MockMessage{}

	// Test basic usage
	pid := &MockPartyID{id: "p1", moniker: "party1", key: []byte("key1")}
	if pid.ID() != "p1" {
		t.Errorf("expected p1, got %s", pid.ID())
	}

	msg := &MockMessage{
		msgType:     "test",
		from:        pid,
		isBroadcast: true,
		round:       1,
	}

	if msg.Type() != "test" {
		t.Errorf("expected test, got %s", msg.Type())
	}
	if !msg.IsBroadcast() {
		t.Error("expected broadcast message")
	}
}
