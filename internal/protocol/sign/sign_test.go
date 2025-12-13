package sign

import (
	"crypto/sha256"
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

func TestSignE2E(t *testing.T) {
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
			for _, msg := range allMsgs {
				if msg.From().ID() == parties[i].ID() { continue }
				if !msg.IsBroadcast() {
					found := false
					for _, dest := range msg.To() {
						if dest.ID() == parties[i].ID() {
							found = true
							break
						}
					}
					if !found { continue }
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

	// 2. Run Sign
	msg := []byte("hello world")
	hash := sha256.Sum256(msg)
	
	signSMs := make([]tss.StateMachine, 3)
	signOutMsgs := make([][]tss.Message, 3)
	
	for i := 0; i < 3; i++ {
		params := &tss.Parameters{
			PartyID:   parties[i],
			Parties:   parties,
			Threshold: 1,
			Curve:     "secp256k1",
			SessionID: []byte("sign-session"),
		}
		signSMs[i], signOutMsgs[i], err = NewStateMachine(params, keyData[i], hash[:])
		if err != nil {
			t.Fatalf("Failed to create sign state machine: %v", err)
		}
	}

	// Run Sign rounds (1 to 5)
	for r := 1; r <= 5; r++ {
		t.Logf("Routing Sign Round %d...", r)
		signSMs, signOutMsgs = route(signSMs, signOutMsgs)
	}

	// Check results
	for i := 0; i < 3; i++ {
		res := signSMs[i].Result()
		if res == nil {
			t.Errorf("Sign failed for party %d", i)
			continue
		}
		sig := res.(*Signature)
		t.Logf("Party %d Signature: (R: %x, S: %x)", i, sig.R, sig.S)
	}
}
