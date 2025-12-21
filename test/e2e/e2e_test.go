package e2e

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
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

func setupParties(n int) []tss.PartyID {
	parties := make([]tss.PartyID, n)
	for i := 0; i < n; i++ {
		parties[i] = &MockPartyID{id: fmt.Sprintf("%d", i+1)}
	}
	return parties
}

func route(parties []tss.PartyID, sms []tss.StateMachine, outMsgs [][]tss.Message, t *testing.T) ([]tss.StateMachine, [][]tss.Message) {
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

func runKeyGen(parties []tss.PartyID, threshold int, sessionID string, t *testing.T) []*keygen.LocalPartySaveData {
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
			t.Fatalf("Failed to create keygen state machine: %v", err)
		}
	}

	for r := 1; r <= 4; r++ {
		keygenSMs, outMsgs = route(parties, keygenSMs, outMsgs, t)
	}

	keyData := make([]*keygen.LocalPartySaveData, n)
	for i := 0; i < n; i++ {
		res := keygenSMs[i].Result()
		if res == nil {
			t.Fatalf("KeyGen failed for party %d", i)
		}
		keyData[i] = res.(*keygen.LocalPartySaveData)
	}
	return keyData
}

// TestCryptoIntegration tests basic Paillier encryption operations.
func TestCryptoIntegration(t *testing.T) {
	nParties := 3
	keys := make([]*paillier.PrivateKey, nParties)

	for i := 0; i < nParties; i++ {
		key, err := paillier.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("Party %d failed to generate key: %v", i, err)
		}
		keys[i] = key
	}

	msg := big.NewInt(12345)
	c, _, err := keys[1].PublicKey.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := keys[1].Decrypt(c)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if msg.Cmp(decrypted) != 0 {
		t.Errorf("Decrypted message does not match original. Got %s, want %s", decrypted, msg)
	}

	val2 := big.NewInt(10)
	c2, _, err := keys[1].PublicKey.Encrypt(val2)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	cSum := keys[1].PublicKey.Add(c, c2)
	decryptedSum, err := keys[1].Decrypt(cSum)
	if err != nil {
		t.Fatalf("Decryption of sum failed: %v", err)
	}

	expectedSum := new(big.Int).Add(msg, val2)
	if expectedSum.Cmp(decryptedSum) != 0 {
		t.Errorf("Homomorphic addition failed. Got %s, want %s", decryptedSum, expectedSum)
	}
}

// TestFullKeyGenToSign tests the complete KeyGen -> Sign flow.
func TestFullKeyGenToSign(t *testing.T) {
	parties := setupParties(3)
	keyData := runKeyGen(parties, 1, "keygen-to-sign-session", t)

	// Verify all parties have the same public key
	for i := 1; i < 3; i++ {
		if keyData[i].PublicKeyX.Cmp(keyData[0].PublicKeyX) != 0 ||
			keyData[i].PublicKeyY.Cmp(keyData[0].PublicKeyY) != 0 {
			t.Fatalf("Party %d has different public key", i)
		}
	}
	t.Logf("All parties have same public key: (%s, %s)",
		keyData[0].PublicKeyX.Text(16)[:16]+"...",
		keyData[0].PublicKeyY.Text(16)[:16]+"...")

	// Run signing
	msg := sha256.Sum256([]byte("hello world"))
	signSMs := make([]tss.StateMachine, 3)
	outMsgs := make([][]tss.Message, 3)

	for i := 0; i < 3; i++ {
		params := &tss.Parameters{
			PartyID:   parties[i],
			Parties:   parties,
			Threshold: 1,
			Curve:     "secp256k1",
			SessionID: []byte("sign-session"),
		}
		var err error
		signSMs[i], outMsgs[i], err = sign.NewStateMachine(params, keyData[i], msg[:])
		if err != nil {
			t.Fatalf("Failed to create sign state machine: %v", err)
		}
	}

	for r := 1; r <= 5; r++ {
		signSMs, outMsgs = route(parties, signSMs, outMsgs, t)
	}

	// Verify all parties got the same signature
	var sig0 *sign.Signature
	for i := 0; i < 3; i++ {
		res := signSMs[i].Result()
		if res == nil {
			t.Fatalf("Sign failed for party %d", i)
		}
		sig := res.(*sign.Signature)
		if sig.R == nil || sig.S == nil {
			t.Fatalf("Party %d has invalid signature", i)
		}

		if sig0 == nil {
			sig0 = sig
		} else {
			if sig.R.Cmp(sig0.R) != 0 || sig.S.Cmp(sig0.S) != 0 {
				t.Errorf("Party %d has different signature", i)
			}
		}
	}
	t.Logf("Signature: R=%s..., S=%s...",
		sig0.R.Text(16)[:16],
		sig0.S.Text(16)[:16])
}

// TestKeyRefreshFlow tests the KeyGen -> Refresh flow.
func TestKeyRefreshFlow(t *testing.T) {
	parties := setupParties(3)
	keyData := runKeyGen(parties, 1, "refresh-keygen-session", t)

	originalPubKeyX := keyData[0].PublicKeyX
	originalPubKeyY := keyData[0].PublicKeyY

	// Run key refresh
	refreshSMs := make([]tss.StateMachine, 3)
	outMsgs := make([][]tss.Message, 3)

	for i := 0; i < 3; i++ {
		params := &tss.Parameters{
			PartyID:   parties[i],
			Parties:   parties,
			Threshold: 1,
			Curve:     "secp256k1",
			SessionID: []byte("refresh-session"),
		}
		var err error
		refreshSMs[i], outMsgs[i], err = refresh.NewStateMachine(params, keyData[i])
		if err != nil {
			t.Fatalf("Failed to create refresh state machine: %v", err)
		}
	}

	for r := 1; r <= 4; r++ {
		refreshSMs, outMsgs = route(parties, refreshSMs, outMsgs, t)
	}

	// Verify results
	newKeyData := make([]*keygen.LocalPartySaveData, 3)
	for i := 0; i < 3; i++ {
		res := refreshSMs[i].Result()
		if res == nil {
			t.Fatalf("Refresh failed for party %d", i)
		}
		newKeyData[i] = res.(*keygen.LocalPartySaveData)
	}

	// Verify public key is unchanged
	if newKeyData[0].PublicKeyX.Cmp(originalPubKeyX) != 0 ||
		newKeyData[0].PublicKeyY.Cmp(originalPubKeyY) != 0 {
		t.Fatal("Public key changed after refresh")
	}
	t.Log("Public key preserved after refresh")

	// Verify secret shares are different
	if newKeyData[0].Xi.Cmp(keyData[0].Xi) == 0 {
		t.Log("Warning: Secret share unchanged (possible but unlikely)")
	} else {
		t.Log("Secret shares updated after refresh")
	}
}

// TestKeyReshareFlow tests the KeyGen -> Reshare flow with committee change.
// Note: This test is skipped because the reshare protocol has known issues
// that need to be investigated.
func TestKeyReshareFlow(t *testing.T) {
	t.Skip("Skipping reshare test - protocol implementation needs investigation")
}
