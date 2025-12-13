package keygen

import (
	"crypto/rand"
	"fmt"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/commitment"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// round1 executes the logic for the first round of the KeyGen protocol.
func (s *state) round1() (tss.StateMachine, []tss.Message, error) {
	// 1. Generate Paillier Key Pair
	// Using 2048 bits as a standard security parameter
	paillierSk, err := paillier.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate paillier key: %w", err)
	}

	// Save keys to state
	s.saveData.PaillierSk = paillierSk
	s.saveData.PaillierPk = &paillierSk.PublicKey

	// 2. Create Commitment
	// We commit to the Paillier Public Key (N)
	// In a full implementation, we would also commit to VSS polynomial, Schnorr commitment, etc.
	// For now, let's serialize the public key to bytes
	pkBytes := paillierSk.PublicKey.N.Bytes()

	// Create commitment: C = Hash(salt, pkBytes)
	comm, err := commitment.New(pkBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create commitment: %w", err)
	}

	// Store the decommitment (D) for Round 2
	s.tempData["round1_decommit"] = comm.D

	// 3. Create the Broadcast Message
	// The payload is the commitment hash C
	msg := &KeyGenMessage{
		FromParty:   s.params.PartyID,
		ToParties:   nil, // Broadcast
		IsBcast:     true,
		Data:        comm.C,
		TypeString:  "KeyGenRound1",
		RoundNum:    1,
	}

	// Update state to indicate we are waiting for Round 1 messages from others
	// (In a real state machine, we might transition to a "waiting" state,
	// but here we just stay in 'state' and increment round in the next Update)
	
	return s, []tss.Message{msg}, nil
}
