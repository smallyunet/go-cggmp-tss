package sign

import (
	"crypto/sha256"
	"testing"

	"github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

func TestBatchSign(t *testing.T) {
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

	// 2. Test Batch Signing with multiple messages
	messages := [][]byte{
		sha256Hash([]byte("message 1")),
		sha256Hash([]byte("message 2")),
		sha256Hash([]byte("message 3")),
	}

	t.Run("BatchSignFirstMessage", func(t *testing.T) {
		// Create batch sign state machines for all parties
		batchSMs := make([]tss.StateMachine, 3)
		batchOutMsgs := make([][]tss.Message, 3)

		for i := 0; i < 3; i++ {
			params := &tss.Parameters{
				PartyID:   parties[i],
				Parties:   parties,
				Threshold: 1,
				Curve:     "secp256k1",
				SessionID: []byte("test-session-batch"),
			}
			batchSMs[i], batchOutMsgs[i], err = NewBatchSignStateMachine(params, keyData[i], messages[:1])
			if err != nil {
				t.Fatalf("Failed to create batch sign state machine: %v", err)
			}
		}

		// Run signing rounds
		for r := 1; r <= 5; r++ {
			batchSMs, batchOutMsgs = route(batchSMs, batchOutMsgs)
		}

		// Verify results
		for i := 0; i < 3; i++ {
			res := batchSMs[i].Result()
			if res == nil {
				t.Fatalf("Batch signing failed for party %d", i)
			}
			sig, ok := res.(*Signature)
			if !ok {
				t.Fatalf("Expected *Signature, got %T", res)
			}
			if sig.R == nil || sig.S == nil {
				t.Fatalf("Invalid signature")
			}
		}
	})
}

func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
