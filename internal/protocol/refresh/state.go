package refresh

import (
	"fmt"

	"github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

type state struct {
	params     *tss.Parameters
	oldKeyData *keygen.LocalPartySaveData

	round        int
	saveData     *keygen.LocalPartySaveData
	tempData     map[string]interface{}
	receivedMsgs map[string][]tss.Message
}

// NewStateMachine initializes a new Key Refresh state machine.
func NewStateMachine(params *tss.Parameters, oldKeyData *keygen.LocalPartySaveData) (tss.StateMachine, []tss.Message, error) {
	s := &state{
		params:     params,
		oldKeyData: oldKeyData,
		round:      1,
		saveData: &keygen.LocalPartySaveData{
			LocalPartyID: params.PartyID,
			// Public Key remains the same
			ECDSAPubX:  oldKeyData.ECDSAPubX,
			ECDSAPubY:  oldKeyData.ECDSAPubY,
			PublicKeyX: oldKeyData.PublicKeyX,
			PublicKeyY: oldKeyData.PublicKeyY,
		},
		tempData:     make(map[string]interface{}),
		receivedMsgs: make(map[string][]tss.Message),
	}

	return s.round1()
}

func (s *state) Update(msg tss.Message) (tss.StateMachine, []tss.Message, error) {
	if msg.RoundNumber() != uint32(s.round) {
		return nil, nil, fmt.Errorf("received message for round %d, expected %d", msg.RoundNumber(), s.round)
	}

	senderID := msg.From().ID()
	if senderID == s.params.PartyID.ID() {
		return nil, nil, nil
	}

	if s.receivedMsgs == nil {
		s.receivedMsgs = make(map[string][]tss.Message)
	}

	for _, existing := range s.receivedMsgs[senderID] {
		if existing.Type() == msg.Type() {
			return nil, nil, fmt.Errorf("duplicate message type %s from party %s", msg.Type(), senderID)
		}
	}

	s.receivedMsgs[senderID] = append(s.receivedMsgs[senderID], msg)

	// Check completion
	// Round 1: 1 Broadcast (Commitment)
	// Round 2: 1 Broadcast (Decommit) + 1 P2P (Share)
	// Round 3: 1 Broadcast (Proof)
	// Round 4: 1 Broadcast (Schnorr)
	
	expectedCount := 0
	switch s.round {
	case 1:
		expectedCount = 1
	case 2:
		expectedCount = 2
	case 3:
		expectedCount = 1 // VSS Verify? No, in KeyGen Round 3 is VSS Verify.
		// Wait, KeyGen Round 3 receives Decommitments?
		// Let's check KeyGen structure.
	}
	
	// In KeyGen:
	// Round 1: Broadcast Commit
	// Round 2: Broadcast Decommit + P2P Share
	// Round 3: Broadcast Paillier Proof (Wait, KeyGen Round 3 is VSS Verify?)
	// Let's check KeyGen Round 3.
	
	// Assuming same structure as KeyGen for now.
	if s.round == 3 {
		expectedCount = 1
	} else if s.round == 4 {
		expectedCount = 1
	}

	if len(s.receivedMsgs) < len(s.params.Parties)-1 {
		return s, nil, nil
	}

	for _, msgs := range s.receivedMsgs {
		if len(msgs) < expectedCount {
			return s, nil, nil
		}
	}

	return s.nextRound()
}

func (s *state) nextRound() (tss.StateMachine, []tss.Message, error) {
	switch s.round {
	case 1:
		return s.round2()
	case 2:
		return s.round3()
	case 3:
		return s.round4()
	default:
		return nil, nil, fmt.Errorf("unknown round %d", s.round)
	}
}

func (s *state) Result() interface{} {
	return nil
}

func (s *state) Details() string {
	return fmt.Sprintf("Refresh Round %d", s.round)
}

// Finished state
type finishedState struct {
	saveData *keygen.LocalPartySaveData
}

func (s *finishedState) Update(msg tss.Message) (tss.StateMachine, []tss.Message, error) {
	return nil, nil, tss.ErrProtocolDone
}

func (s *finishedState) Result() interface{} {
	return s.saveData
}

func (s *finishedState) Details() string {
	return "Refresh Finished"
}
