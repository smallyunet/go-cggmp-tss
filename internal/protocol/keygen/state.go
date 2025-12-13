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
		tempData: make(map[string]interface{}),
	}

	return s.round1()
}

func (s *state) Update(msg tss.Message) (tss.StateMachine, []tss.Message, error) {
	// TODO: Implement state transitions for future rounds
	return s, nil, nil
}

func (s *state) Result() interface{} {
	// Only return result when finished (which we aren't yet)
	// For now, we can return nil or the partial data if needed for debugging
	return nil
}

func (s *state) Details() string {
	return fmt.Sprintf("KeyGen Round %d", s.round)
}
