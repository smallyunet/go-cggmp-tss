package sign

import (
	"fmt"

	"github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

type state struct {
	params   *tss.Parameters
	keyData  *keygen.LocalPartySaveData
	msgToSign []byte // The message (hash) to sign. Nil if PreSign mode.
	preSignature *PreSignature // Populated in Online mode

	round    int
	tempData map[string]interface{}
	
	// Messages received in the current round
	receivedMsgs map[string][]tss.Message
}

// NewStateMachine initializes a new Signing state machine.
func NewStateMachine(params *tss.Parameters, keyData *keygen.LocalPartySaveData, msg []byte) (tss.StateMachine, []tss.Message, error) {
	s := &state{
		params:       params,
		keyData:      keyData,
		msgToSign:    msg,
		round:        1,
		tempData:     make(map[string]interface{}),
		receivedMsgs: make(map[string][]tss.Message),
	}

	return s.round1()
}

// NewPreSignStateMachine initializes a new Pre-Signing state machine (Offline phase).
func NewPreSignStateMachine(params *tss.Parameters, keyData *keygen.LocalPartySaveData) (tss.StateMachine, []tss.Message, error) {
	s := &state{
		params:       params,
		keyData:      keyData,
		msgToSign:    nil, // Indicates PreSign mode
		round:        1,
		tempData:     make(map[string]interface{}),
		receivedMsgs: make(map[string][]tss.Message),
	}
	return s.round1()
}

// NewOnlineStateMachine initializes a new Online Signing state machine.
func NewOnlineStateMachine(params *tss.Parameters, keyData *keygen.LocalPartySaveData, preSig *PreSignature, msg []byte) (tss.StateMachine, []tss.Message, error) {
	s := &state{
		params:       params,
		keyData:      keyData,
		msgToSign:    msg,
		preSignature: preSig,
		round:        4, // We start by sending Round 4 message (s_i) and waiting for others
		tempData:     make(map[string]interface{}),
		receivedMsgs: make(map[string][]tss.Message),
	}
	return s.roundOnline1()
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
	
	// Check for duplicates
	for _, existing := range s.receivedMsgs[senderID] {
		if existing.Type() == msg.Type() {
			return nil, nil, fmt.Errorf("duplicate message type %s from party %s", msg.Type(), senderID)
		}
	}
	
	s.receivedMsgs[senderID] = append(s.receivedMsgs[senderID], msg)

	// Check completion
	// We need messages from all t+1 parties (including self, but self is implicit)
	// Actually, we need messages from all OTHER parties in the signing set.
	// The `params.Parties` should contain the subset of parties participating in signing.
	// Size of `params.Parties` should be >= t+1.
	
	if len(s.receivedMsgs) < len(s.params.Parties)-1 {
		return s, nil, nil
	}
	
	// Check if we have all expected messages per peer
	expectedCount := 0
	switch s.round {
	case 1:
		expectedCount = 1 // Broadcast K, G commitments
	case 2:
		expectedCount = 1 // P2P MtA shares (actually multiple P2P messages? or one bundled?)
		// In MtA, we exchange with everyone.
		// Let's assume 1 message per peer containing all MtA data.
	case 3:
		expectedCount = 1 // Partial Signature (s_i)
	case 4:
		expectedCount = 1 // We expect s_j from everyone in Round 4
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
	case 4:
		return s.round5()
	default:
		return nil, nil, fmt.Errorf("unknown round %d", s.round)
	}
}

func (s *state) Result() interface{} {
	return nil
}

func (s *state) Details() string {
	return fmt.Sprintf("Sign Round %d", s.round)
}

// Finished state
type finishedState struct {
	signature    *Signature
	preSignature *PreSignature
}

func (s *finishedState) Update(msg tss.Message) (tss.StateMachine, []tss.Message, error) {
	return nil, nil, tss.ErrProtocolDone
}

func (s *finishedState) Result() interface{} {
	if s.signature != nil {
		return s.signature
	}
	return s.preSignature
}

func (s *finishedState) Details() string {
	return "Sign Finished"
}
