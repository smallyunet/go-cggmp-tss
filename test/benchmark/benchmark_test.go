package benchmark

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/smallyu/go-cggmp-tss/internal/protocol/identify"
	"github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
	"github.com/smallyu/go-cggmp-tss/internal/protocol/refresh"
	"github.com/smallyu/go-cggmp-tss/internal/protocol/sign"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

type MockPartyID struct {
	id string
}

func (m *MockPartyID) ID() string      { return m.id }
func (m *MockPartyID) Moniker() string { return m.id }
func (m *MockPartyID) Key() []byte     { return []byte(m.id) }

// setupParties creates n parties for testing.
func setupParties(n int) []tss.PartyID {
	parties := make([]tss.PartyID, n)
	for i := 0; i < n; i++ {
		parties[i] = &MockPartyID{id: fmt.Sprintf("%d", i+1)}
	}
	return parties
}

// route simulates message routing between parties.
func route(parties []tss.PartyID, sms []tss.StateMachine, outMsgs [][]tss.Message) ([]tss.StateMachine, [][]tss.Message) {
	allMsgs := []tss.Message{}
	for _, msgs := range outMsgs {
		allMsgs = append(allMsgs, msgs...)
	}
	newOutMsgs := make([][]tss.Message, len(sms))

	for i := 0; i < len(sms); i++ {
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
				panic(fmt.Sprintf("party %d error: %v", i, err))
			}
			sms[i] = next
			if newOut != nil {
				newOutMsgs[i] = append(newOutMsgs[i], newOut...)
			}
		}
	}
	return sms, newOutMsgs
}

// runKeyGen runs key generation and returns the key data for all parties.
func runKeyGen(parties []tss.PartyID, threshold int, sessionID string) []*keygen.LocalPartySaveData {
	n := len(parties)
	keygenSMs := make([]tss.StateMachine, n)
	outMsgs := make([][]tss.Message, n)

	for i := 0; i < n; i++ {
		params := &tss.Parameters{
			PartyID:   parties[i],
			Parties:   parties,
			Threshold: threshold,
			Curve:     "secp256k1",
			SessionID: []byte(sessionID),
		}
		var err error
		keygenSMs[i], outMsgs[i], err = keygen.NewStateMachine(params)
		if err != nil {
			panic(err)
		}
	}

	for r := 1; r <= 4; r++ {
		keygenSMs, outMsgs = route(parties, keygenSMs, outMsgs)
	}

	keyData := make([]*keygen.LocalPartySaveData, n)
	for i := 0; i < n; i++ {
		keyData[i] = keygenSMs[i].Result().(*keygen.LocalPartySaveData)
	}
	return keyData
}

// BenchmarkKeyGen benchmarks the key generation protocol.
func BenchmarkKeyGen3of3(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		parties := setupParties(3)
		runKeyGen(parties, 1, fmt.Sprintf("keygen-session-%d", i))
	}
}

// BenchmarkSign benchmarks the full signing protocol.
func BenchmarkSign3of3(b *testing.B) {
	parties := setupParties(3)
	keyData := runKeyGen(parties, 1, "sign-setup-session")

	msg := sha256.Sum256([]byte("benchmark message"))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		signSMs := make([]tss.StateMachine, 3)
		outMsgs := make([][]tss.Message, 3)

		for j := 0; j < 3; j++ {
			params := &tss.Parameters{
				PartyID:   parties[j],
				Parties:   parties,
				Threshold: 1,
				Curve:     "secp256k1",
				SessionID: []byte(fmt.Sprintf("sign-session-%d", i)),
			}
			var err error
			signSMs[j], outMsgs[j], err = sign.NewStateMachine(params, keyData[j], msg[:])
			if err != nil {
				b.Fatal(err)
			}
		}

		for r := 1; r <= 5; r++ {
			signSMs, outMsgs = route(parties, signSMs, outMsgs)
		}

		// Verify all parties got a result
		for j := 0; j < 3; j++ {
			if signSMs[j].Result() == nil {
				b.Fatal("Sign failed")
			}
		}
	}
}

// BenchmarkPreSign benchmarks the presigning (offline) phase.
func BenchmarkPreSign3of3(b *testing.B) {
	parties := setupParties(3)
	keyData := runKeyGen(parties, 1, "presign-setup-session")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		preSMs := make([]tss.StateMachine, 3)
		outMsgs := make([][]tss.Message, 3)

		for j := 0; j < 3; j++ {
			params := &tss.Parameters{
				PartyID:   parties[j],
				Parties:   parties,
				Threshold: 1,
				Curve:     "secp256k1",
				SessionID: []byte(fmt.Sprintf("presign-session-%d", i)),
			}
			var err error
			preSMs[j], outMsgs[j], err = sign.NewPreSignStateMachine(params, keyData[j])
			if err != nil {
				b.Fatal(err)
			}
		}

		for r := 1; r <= 4; r++ {
			preSMs, outMsgs = route(parties, preSMs, outMsgs)
		}

		// Verify all parties got a result
		for j := 0; j < 3; j++ {
			if preSMs[j].Result() == nil {
				b.Fatal("PreSign failed")
			}
		}
	}
}

// BenchmarkOnlineSign benchmarks the online signing phase.
func BenchmarkOnlineSign3of3(b *testing.B) {
	parties := setupParties(3)
	keyData := runKeyGen(parties, 1, "online-setup-session")

	// Run presign once to get presignatures
	preSMs := make([]tss.StateMachine, 3)
	outMsgs := make([][]tss.Message, 3)

	for j := 0; j < 3; j++ {
		params := &tss.Parameters{
			PartyID:   parties[j],
			Parties:   parties,
			Threshold: 1,
			Curve:     "secp256k1",
			SessionID: []byte("online-presign-session"),
		}
		var err error
		preSMs[j], outMsgs[j], err = sign.NewPreSignStateMachine(params, keyData[j])
		if err != nil {
			b.Fatal(err)
		}
	}

	for r := 1; r <= 4; r++ {
		preSMs, outMsgs = route(parties, preSMs, outMsgs)
	}

	preSignatures := make([]*sign.PreSignature, 3)
	for j := 0; j < 3; j++ {
		preSignatures[j] = preSMs[j].Result().(*sign.PreSignature)
	}

	msg := sha256.Sum256([]byte("benchmark message"))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		onlineSMs := make([]tss.StateMachine, 3)
		onlineOutMsgs := make([][]tss.Message, 3)

		for j := 0; j < 3; j++ {
			params := &tss.Parameters{
				PartyID:   parties[j],
				Parties:   parties,
				Threshold: 1,
				Curve:     "secp256k1",
				SessionID: []byte(fmt.Sprintf("online-session-%d", i)),
			}
			var err error
			onlineSMs[j], onlineOutMsgs[j], err = sign.NewOnlineStateMachine(params, keyData[j], preSignatures[j], msg[:])
			if err != nil {
				b.Fatal(err)
			}
		}

		// Online phase is just 1 round
		onlineSMs, onlineOutMsgs = route(parties, onlineSMs, onlineOutMsgs)

		for j := 0; j < 3; j++ {
			if onlineSMs[j].Result() == nil {
				b.Fatal("Online sign failed")
			}
		}
	}
}

// BenchmarkRefresh benchmarks the key refresh protocol.
func BenchmarkRefresh3of3(b *testing.B) {
	parties := setupParties(3)
	keyData := runKeyGen(parties, 1, "refresh-setup-session")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		refreshSMs := make([]tss.StateMachine, 3)
		outMsgs := make([][]tss.Message, 3)

		for j := 0; j < 3; j++ {
			params := &tss.Parameters{
				PartyID:   parties[j],
				Parties:   parties,
				Threshold: 1,
				Curve:     "secp256k1",
				SessionID: []byte(fmt.Sprintf("refresh-session-%d", i)),
			}
			var err error
			refreshSMs[j], outMsgs[j], err = refresh.NewStateMachine(params, keyData[j])
			if err != nil {
				b.Fatal(err)
			}
		}

		for r := 1; r <= 4; r++ {
			refreshSMs, outMsgs = route(parties, refreshSMs, outMsgs)
		}

		for j := 0; j < 3; j++ {
			if refreshSMs[j].Result() == nil {
				b.Fatal("Refresh failed")
			}
		}
	}
}

// BenchmarkIdentify benchmarks the identification protocol.
func BenchmarkIdentify3of3(b *testing.B) {
	parties := setupParties(3)
	keyData := runKeyGen(parties, 1, "identify-setup-session")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		proofs := make([]*identify.IdentifyProof, 3)

		for j := 0; j < 3; j++ {
			params := &tss.Parameters{
				PartyID:   parties[j],
				Parties:   parties,
				Threshold: 1,
				Curve:     "secp256k1",
				SessionID: []byte(fmt.Sprintf("identify-session-%d", i)),
			}
			var err error
			proofs[j], err = identify.NewIdentifyProof(params, keyData[j])
			if err != nil {
				b.Fatal(err)
			}
		}

		// Verify all proofs
		for j := 0; j < 3; j++ {
			if !identify.VerifyIdentifyProof(proofs[j]) {
				b.Fatal("Identify verification failed")
			}
		}
	}
}
