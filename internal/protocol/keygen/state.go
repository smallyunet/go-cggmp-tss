package keygen

import (
	"fmt"

	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

type state struct {
	params *tss.Parameters

	// Current round number (1-based)
	round int

	// Data being built up
	saveData *LocalPartySaveData

	// Temporary data to be carried over to next rounds
	tempData map[string]interface{}

	// Messages received in the current round
	// Map: PartyID.ID() -> []Message
	receivedMsgs map[string][]tss.Message
}

// NewStateMachine initializes a new KeyGen state machine.
// It immediately executes Round 1 logic to generate the first set of messages.
func NewStateMachine(params *tss.Parameters) (tss.StateMachine, []tss.Message, error) {
	s := &state{
		params: params,
		round:  1,
		saveData: &LocalPartySaveData{
			LocalPartyID: params.PartyID,
		},
		tempData:     make(map[string]interface{}),
		receivedMsgs: make(map[string][]tss.Message),
	}

	// Check initialization logic
	if params.OneRoundKeyGen {
		return s.round1Direct()
	}

	return s.round1()
}

func (s *state) Update(msg tss.Message) (tss.StateMachine, []tss.Message, error) {
	// Validate message round
	if msg.RoundNumber() != uint32(s.round) {
		return nil, nil, fmt.Errorf("received message for round %d, expected %d", msg.RoundNumber(), s.round)
	}

	// Validate sender
	senderID := msg.From().ID()
	if senderID == s.params.PartyID.ID() {
		return nil, nil, nil // Ignore own messages if looped back
	}

	// Store message
	if s.receivedMsgs == nil {
		s.receivedMsgs = make(map[string][]tss.Message)
	}

	// Check for duplicates (simple check based on type)
	for _, existing := range s.receivedMsgs[senderID] {
		if existing.Type() == msg.Type() {
			return nil, nil, fmt.Errorf("duplicate message type %s from party %s", msg.Type(), senderID)
		}
	}

	s.receivedMsgs[senderID] = append(s.receivedMsgs[senderID], msg)

	// Check if we have received all expected messages from all other parties
	// Check if we have received all expected messages from all other parties
	// Standard:
	// Round 1: 1 Broadcast per peer
	// Round 2: 1 Broadcast + 1 P2P per peer
	// Round 3: 1 Broadcast per peer

	// OneRoundKeyGen:
	// Round 1: 1 Broadcast + 1 P2P per peer

	expectedCount := 0
	if s.params.OneRoundKeyGen {
		switch s.round {
		case 1:
			expectedCount = 2 // Broadcast + Share
		}
	} else {
		switch s.round {
		case 1:
			expectedCount = 1
		case 2:
			expectedCount = 2
		case 3:
			expectedCount = 1
		}
	}

	// Check if all peers have sent enough messages
	// We need to hear from ALL n-1 peers
	if len(s.receivedMsgs) < len(s.params.Parties)-1 {
		return s, nil, nil
	}

	for _, msgs := range s.receivedMsgs {
		if len(msgs) < expectedCount {
			return s, nil, nil
		}
	}

	// Round complete, transition to next round
	return s.nextRound()
}

func (s *state) nextRound() (tss.StateMachine, []tss.Message, error) {
	if s.params.OneRoundKeyGen {
		switch s.round {
		case 1:
			return s.round2Direct()
		// No further rounds
		default:
			return nil, nil, fmt.Errorf("unknown round %d in direct mode", s.round)
		}
	}

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
	// Only return result when finished (which we aren't yet)
	// For now, we can return nil or the partial data if needed for debugging
	return nil
}

func (s *state) Details() string {
	return fmt.Sprintf("KeyGen Round %d", s.round)
}

type finishedState struct {
	data *LocalPartySaveData
}

func (s *finishedState) Update(msg tss.Message) (tss.StateMachine, []tss.Message, error) {
	return nil, nil, tss.ErrProtocolDone
}

func (s *finishedState) Result() interface{} {
	return s.data
}

func (s *finishedState) Details() string {
	return "KeyGen Finished"
}
