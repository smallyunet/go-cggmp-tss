package keygen

import (
	"testing"

	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

func TestDirectKeyGen(t *testing.T) {
	// Setup 3 parties
	pIDs := []string{"1", "2", "3"}
	parties := make([]tss.PartyID, 3)
	for i, id := range pIDs {
		parties[i] = &MockPartyID{id: id}
	}

	// Create state machines with OneRoundKeyGen = true
	sms := make([]tss.StateMachine, 3)
	outMsgs := make([][]tss.Message, 3)
	var err error

	for i := 0; i < 3; i++ {
		params := &tss.Parameters{
			PartyID:        parties[i],
			Parties:        parties,
			Threshold:      1, // t=1, n=3
			Curve:          "secp256k1",
			SessionID:      []byte("test-session-direct"),
			OneRoundKeyGen: true,
		}
		sms[i], outMsgs[i], err = NewStateMachine(params)
		if err != nil {
			t.Fatalf("Failed to create state machine for party %d: %v", i, err)
		}

		// Expect Round 1 Direct messages (Broadcast + P2P)
		// n=3, so 2 peers. 1 Broadcast, 2 P2P. Total 3 messages.
		if len(outMsgs[i]) != 3 {
			t.Errorf("Party %d: Expected 3 messages, got %d", i, len(outMsgs[i]))
		}
	}

	// Helper to route messages
	route := func(round int) {
		t.Logf("Routing Round %d messages...", round)
		// Collect all messages
		allMsgs := []tss.Message{}
		for _, msgs := range outMsgs {
			allMsgs = append(allMsgs, msgs...)
		}

		// Clear output buffers
		outMsgs = make([][]tss.Message, 3)

		// Deliver to each party
		for i := 0; i < 3; i++ {
			for _, msg := range allMsgs {
				// Skip own messages
				if msg.From().ID() == parties[i].ID() {
					continue
				}
				// Check destination
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

				// Update state machine
				// Should finish after 1 round of updates (Processing Round 1 messages -> Finish)
				next, newOut, err := sms[i].Update(msg)
				if err != nil {
					t.Fatalf("Party %d failed at round %d update: %v", i, round, err)
				}

				// In Direct mode, after receiving all Round 1 messages, it should transition to Finished immediately.
				// next can be nil if finished?
				// The generic interface says: "next: The new state machine (nil if protocol finished or failed)."
				// But our `finishedState` implementation returns itself until result is retrieved?
				// Let's check `round_2_direct.go`: it returns `&finishedState{...}`.
				// So `next` should be `*finishedState`.

				sms[i] = next
				if newOut != nil {
					outMsgs[i] = append(outMsgs[i], newOut...)
				}
			}
		}
	}

	// Round 1 -> Finish
	route(1)

	// Check results
	for i := 0; i < 3; i++ {
		if sms[i] == nil {
			t.Errorf("Party %d state machine became nil", i)
			continue
		}
		res := sms[i].Result()
		if res == nil {
			t.Errorf("Party %d did not finish", i)
			continue
		}
		data := res.(*LocalPartySaveData)
		if data.Xi == nil {
			t.Errorf("Party %d has no secret share", i)
		}
		if data.PublicKeyX == nil {
			t.Errorf("Party %d has no public key", i)
		}
		t.Logf("Party %d finished. PubKey: (%s, %s)", i, data.PublicKeyX, data.PublicKeyY)
	}

	// Verify all parties have same public key
	res0 := sms[0].Result()
	if res0 == nil {
		t.Fatal("Party 0 result is nil")
	}
	pkX := res0.(*LocalPartySaveData).PublicKeyX
	pkY := res0.(*LocalPartySaveData).PublicKeyY

	for i := 1; i < 3; i++ {
		res := sms[i].Result()
		if res == nil {
			t.Errorf("Party %d result is nil", i)
			continue
		}
		d := res.(*LocalPartySaveData)
		if d.PublicKeyX.Cmp(pkX) != 0 || d.PublicKeyY.Cmp(pkY) != 0 {
			t.Errorf("Party %d has different public key", i)
		}
	}
}
