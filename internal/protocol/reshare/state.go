package reshare

import (
	"fmt"

	"github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

type state struct {
	params     *tss.Parameters // New parameters (t', n')
	oldParams  *tss.Parameters // Old parameters (t, n)
	oldKeyData *keygen.LocalPartySaveData

	round        int
	saveData     *keygen.LocalPartySaveData
	tempData     map[string]interface{}
	receivedMsgs map[string][]tss.Message

	isOldCommittee bool
	isNewCommittee bool
}

// NewStateMachine initializes a new Key Reshariing state machine.
// params: The configuration for the NEW committee.
// oldParams: The configuration for the OLD committee.
// oldKeyData: Existing key data (required for old committee members).
func NewStateMachine(params *tss.Parameters, oldParams *tss.Parameters, oldKeyData *keygen.LocalPartySaveData) (tss.StateMachine, []tss.Message, error) {
	// Identify role
	myID := params.PartyID.ID()

	isOld := false
	for _, p := range oldParams.Parties {
		if p.ID() == myID {
			isOld = true
			break
		}
	}

	isNew := false
	for _, p := range params.Parties {
		if p.ID() == myID {
			isNew = true
			break
		}
	}

	if !isOld && !isNew {
		return nil, nil, fmt.Errorf("party %s is not in old or new committee", myID)
	}

	if isOld && oldKeyData == nil {
		return nil, nil, fmt.Errorf("party %s is in old committee but missing key data", myID)
	}

	s := &state{
		params:         params,
		oldParams:      oldParams,
		oldKeyData:     oldKeyData,
		round:          1,
		isOldCommittee: isOld,
		isNewCommittee: isNew,
		tempData:       make(map[string]interface{}),
		receivedMsgs:   make(map[string][]tss.Message),
	}

	// Create initial save data for new committee members
	if isNew {
		if oldKeyData != nil {
			// Reuse public key info
			s.saveData = &keygen.LocalPartySaveData{
				LocalPartyID: params.PartyID,
				ECDSAPubX:    oldKeyData.ECDSAPubX,
				ECDSAPubY:    oldKeyData.ECDSAPubY,
				PublicKeyX:   oldKeyData.PublicKeyX,
				PublicKeyY:   oldKeyData.PublicKeyY,
			}
		} else {
			// Will be populated later
			s.saveData = &keygen.LocalPartySaveData{
				LocalPartyID: params.PartyID,
			}
		}
	}

	return s.round1()
}

func (s *state) Update(msg tss.Message) (tss.StateMachine, []tss.Message, error) {
	if msg.RoundNumber() < uint32(s.round) {
		return s, nil, nil
	}
	if msg.RoundNumber() > uint32(s.round) {
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

	// Check completion logic
	// This is more complex in resharing because messages come from specific sets (Old vs New).
	// For simplicity, we'll wait for messages from ALL relevant parties.

	// Round 1: Old Parties broadcast Commitments.
	// Receivers: New Parties (and Old Parties for consistency check if they are also New).

	// Round 2: Old Parties send Shares to New Parties.

	ready := false
	switch s.round {
	case 1:
		// Expect commitments from ALL parties (Old U New, excluding self)
		// Old parties commit VSS. New parties commit Paillier.

		// 1. Calculate Expected Count (Union of Old and New - Self)
		expectedCount := 0
		allIDs := make(map[string]bool)
		for _, p := range s.oldParams.Parties {
			allIDs[p.ID()] = true
		}
		for _, p := range s.params.Parties {
			allIDs[p.ID()] = true
		}
		delete(allIDs, s.params.PartyID.ID())
		expectedCount = len(allIDs)

		// 2. Count distinct parties we received from
		receivedFromIDs := make(map[string]bool)
		for id := range s.receivedMsgs {
			receivedFromIDs[id] = true
		}

		if len(receivedFromIDs) >= expectedCount {
			ready = true
		}

	case 2:
		// Expect Decommit from ALL parties (Old U New, excluding self)
		// AND Shares from Old Parties (if I am in New Committee)

		// 1. Calculate Expected Decommits (same as Round 1)
		allIDs := make(map[string]bool)
		for _, p := range s.oldParams.Parties {
			allIDs[p.ID()] = true
		}
		for _, p := range s.params.Parties {
			allIDs[p.ID()] = true
		}
		delete(allIDs, s.params.PartyID.ID())
		expectedDecommits := len(allIDs)

		distinctDecommits := 0
		sharesReceived := 0

		// Expected Shares = Old Committee Size (minus self if I am Old)
		// Used only if I am New Committee
		expectedShares := 0
		if s.isNewCommittee {
			expectedShares = len(s.oldParams.Parties)
			if s.isOldCommittee {
				expectedShares--
			}
		}

		for _, msgs := range s.receivedMsgs {
			hasDecommit := false
			hasShare := false
			for _, m := range msgs {
				if m.Type() == "ReshareRound2_Decommit" {
					hasDecommit = true
				} else if m.Type() == "ReshareRound2_Share" {
					hasShare = true
				}
			}

			if hasDecommit {
				distinctDecommits++
			}
			if hasShare {
				sharesReceived++
			}
		}

		if distinctDecommits >= expectedDecommits {
			if !s.isNewCommittee {
				// Old-Only: Just needs decommits (to finish? or wait?)
				// Actually Old-Only doesn't produce output, just helps.
				ready = true
			} else {
				// New Committee: Needs Shares too
				if sharesReceived >= expectedShares {
					ready = true
				}
			}
		}

	default:
		// Fallback to simple count for later rounds (internal to new committee)
		if len(s.receivedMsgs) >= len(s.params.Parties)-1 {
			ready = true
		}
	}

	if !ready {
		return s, nil, nil
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
	return fmt.Sprintf("Reshare Round %d", s.round)
}

// Finished state
type finishedState struct {
	saveData *keygen.LocalPartySaveData
}

func (s *finishedState) Update(msg tss.Message) (tss.StateMachine, []tss.Message, error) {
	return s, nil, nil
}

func (s *finishedState) Result() interface{} {
	return s.saveData
}

func (s *finishedState) Details() string {
	return "Reshare Finished"
}
