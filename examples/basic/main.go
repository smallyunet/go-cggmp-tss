package main

import (
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
	"github.com/smallyu/go-cggmp-tss/internal/protocol/sign"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// SimplePartyID is a basic implementation of tss.PartyID.
type SimplePartyID struct {
	IDStr   string
	KeyData []byte
}

func (p *SimplePartyID) ID() string      { return p.IDStr }
func (p *SimplePartyID) Moniker() string { return p.IDStr }
func (p *SimplePartyID) Key() []byte     { return p.KeyData }

func main() {
	// This example demonstrates a 2-of-3 threshold signature scheme.
	// In production, each party would run on a separate machine.
	// Here we simulate all parties locally for demonstration.

	fmt.Println("=== go-cggmp-tss Example: 2-of-3 Threshold Signature ===")

	// Setup 3 parties
	parties := []tss.PartyID{
		&SimplePartyID{IDStr: "party-1", KeyData: []byte("key1")},
		&SimplePartyID{IDStr: "party-2", KeyData: []byte("key2")},
		&SimplePartyID{IDStr: "party-3", KeyData: []byte("key3")},
	}

	threshold := 1 // t=1 means 2 parties needed to sign (t+1)

	// Step 1: Distributed Key Generation
	fmt.Println("Step 1: Running Distributed Key Generation...")
	keyData, err := runKeyGen(parties, threshold)
	if err != nil {
		log.Fatalf("KeyGen failed: %v", err)
	}
	fmt.Printf("  ✓ KeyGen complete. Public Key: (%s..., %s...)\n\n",
		keyData[0].PublicKeyX.Text(16)[:16],
		keyData[0].PublicKeyY.Text(16)[:16])

	// Step 2: Threshold Signing
	message := []byte("Hello, Threshold Signatures!")
	msgHash := sha256.Sum256(message)

	fmt.Printf("Step 2: Signing message: %q\n", message)
	signature, err := runSign(parties, keyData, msgHash[:])
	if err != nil {
		log.Fatalf("Sign failed: %v", err)
	}
	fmt.Printf("  ✓ Signature: R=%s..., S=%s...\n\n",
		signature.R.Text(16)[:16],
		signature.S.Text(16)[:16])

	fmt.Println("=== Example Complete ===")
}

// runKeyGen simulates the distributed key generation protocol.
func runKeyGen(parties []tss.PartyID, threshold int) ([]*keygen.LocalPartySaveData, error) {
	n := len(parties)
	sms := make([]tss.StateMachine, n)
	outMsgs := make([][]tss.Message, n)

	// Initialize state machines
	for i := 0; i < n; i++ {
		params := &tss.Parameters{
			PartyID:   parties[i],
			Parties:   parties,
			Threshold: threshold,
			Curve:     "secp256k1",
			SessionID: []byte("keygen-example-session"),
		}
		var err error
		sms[i], outMsgs[i], err = keygen.NewStateMachine(params)
		if err != nil {
			return nil, err
		}
	}

	// Run 4 rounds of the protocol
	for round := 1; round <= 4; round++ {
		sms, outMsgs = routeMessages(parties, sms, outMsgs)
	}

	// Collect results
	keyData := make([]*keygen.LocalPartySaveData, n)
	for i := 0; i < n; i++ {
		result := sms[i].Result()
		if result == nil {
			return nil, fmt.Errorf("party %d did not complete", i)
		}
		keyData[i] = result.(*keygen.LocalPartySaveData)
	}

	return keyData, nil
}

// runSign simulates the threshold signing protocol.
func runSign(parties []tss.PartyID, keyData []*keygen.LocalPartySaveData, msgHash []byte) (*sign.Signature, error) {
	n := len(parties)
	sms := make([]tss.StateMachine, n)
	outMsgs := make([][]tss.Message, n)

	// Initialize state machines
	for i := 0; i < n; i++ {
		params := &tss.Parameters{
			PartyID:   parties[i],
			Parties:   parties,
			Threshold: 1,
			Curve:     "secp256k1",
			SessionID: []byte("sign-example-session"),
		}
		var err error
		sms[i], outMsgs[i], err = sign.NewStateMachine(params, keyData[i], msgHash)
		if err != nil {
			return nil, err
		}
	}

	// Run 5 rounds of the protocol
	for round := 1; round <= 5; round++ {
		sms, outMsgs = routeMessages(parties, sms, outMsgs)
	}

	// Get result from first party
	result := sms[0].Result()
	if result == nil {
		return nil, fmt.Errorf("signing did not complete")
	}

	return result.(*sign.Signature), nil
}

// routeMessages simulates message routing between parties.
func routeMessages(parties []tss.PartyID, sms []tss.StateMachine, outMsgs [][]tss.Message) ([]tss.StateMachine, [][]tss.Message) {
	// Collect all messages
	allMsgs := []tss.Message{}
	for _, msgs := range outMsgs {
		allMsgs = append(allMsgs, msgs...)
	}
	newOutMsgs := make([][]tss.Message, len(sms))

	// Deliver messages to each party
	for i := 0; i < len(sms); i++ {
		if sms[i] == nil {
			continue
		}

		for _, msg := range allMsgs {
			// Skip own messages
			if msg.From().ID() == parties[i].ID() {
				continue
			}
			// Check destination for P2P messages
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
			next, newOut, err := sms[i].Update(msg)
			if err != nil {
				log.Printf("Party %d error: %v", i, err)
				continue
			}
			sms[i] = next
			if newOut != nil {
				newOutMsgs[i] = append(newOutMsgs[i], newOut...)
			}
		}
	}
	return sms, newOutMsgs
}
