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
	// Map: PartyID.ID() -> Message
	receivedMsgs map[string]tss.Message
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
		receivedMsgs: make(map[string]tss.Message),
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
	// In a real immutable design, we'd copy the map. For simplicity here, we mutate.
	if s.receivedMsgs == nil {
		s.receivedMsgs = make(map[string]tss.Message)
	}
	if _, exists := s.receivedMsgs[senderID]; exists {
		return nil, nil, fmt.Errorf("duplicate message from party %s", senderID)
	}
	s.receivedMsgs[senderID] = msg

	// Check if we have received messages from all other parties
	// Total parties = n, we need n-1 messages
	if len(s.receivedMsgs) == len(s.params.Parties)-1 {
		// Round complete, transition to next round
		return s.nextRound()
	}

	return s, nil, nil
}

func (s *state) nextRound() (tss.StateMachine, []tss.Message, error) {
	switch s.round {
	case 1:
		return s.round2()
	// case 2:
	// 	return s.round3()
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
