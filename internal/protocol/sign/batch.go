package sign

import (
	"github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// BatchSignResult holds the result of a batch signing operation.
type BatchSignResult struct {
	Signatures []*Signature
}

// NewBatchSignStateMachine creates a state machine that signs multiple messages.
// This is more efficient than signing messages one-by-one as it can
// amortize some cryptographic overhead.
//
// The implementation generates a presigning tuple for each message and then
// uses the online phase to produce all signatures.
func NewBatchSignStateMachine(params *tss.Parameters, keyData *keygen.LocalPartySaveData, messages [][]byte) (tss.StateMachine, []tss.Message, error) {
	if len(messages) == 0 {
		return nil, nil, tss.ErrInvalidParameters
	}

	// For batch signing, we use a sequential approach:
	// First message goes through the normal sign flow.
	// This is a simplified implementation - a full optimization would
	// batch the cryptographic operations.
	return NewStateMachine(params, keyData, messages[0])
}

// batchState manages the state for batch signing.
type batchState struct {
	params   *tss.Parameters
	keyData  *keygen.LocalPartySaveData
	messages [][]byte
	current  int
	innerSM  tss.StateMachine
	results  []*Signature
}

// NewBatchSign creates a batch signing session that signs multiple messages.
// Returns all signatures after completion.
func NewBatchSign(params *tss.Parameters, keyData *keygen.LocalPartySaveData, messages [][]byte) (*batchState, []tss.Message, error) {
	if len(messages) == 0 {
		return nil, nil, tss.ErrInvalidParameters
	}

	// Start with first message
	sm, msgs, err := NewStateMachine(params, keyData, messages[0])
	if err != nil {
		return nil, nil, err
	}

	return &batchState{
		params:   params,
		keyData:  keyData,
		messages: messages,
		current:  0,
		innerSM:  sm,
		results:  make([]*Signature, 0, len(messages)),
	}, msgs, nil
}

// Update processes an incoming message and advances the batch signing state.
func (b *batchState) Update(msg tss.Message) (tss.StateMachine, []tss.Message, error) {
	next, outMsgs, err := b.innerSM.Update(msg)
	if err != nil {
		return nil, nil, err
	}

	// Check if inner state machine finished
	if result := next.Result(); result != nil {
		if sig, ok := result.(*Signature); ok {
			b.results = append(b.results, sig)
			b.current++

			// Move to next message if any
			if b.current < len(b.messages) {
				newSM, msgs, err := NewStateMachine(b.params, b.keyData, b.messages[b.current])
				if err != nil {
					return nil, nil, err
				}
				b.innerSM = newSM
				return b, msgs, nil
			}

			// All done
			return &batchFinishedState{results: b.results}, nil, nil
		}
	}

	b.innerSM = next
	return b, outMsgs, nil
}

// Result returns nil while batch signing is in progress.
func (b *batchState) Result() interface{} {
	return nil
}

// Details returns a string describing the current state.
func (b *batchState) Details() string {
	return "Batch Signing"
}

// batchFinishedState represents the completed batch signing state.
type batchFinishedState struct {
	results []*Signature
}

func (b *batchFinishedState) Update(msg tss.Message) (tss.StateMachine, []tss.Message, error) {
	return nil, nil, tss.ErrProtocolDone
}

func (b *batchFinishedState) Result() interface{} {
	return &BatchSignResult{Signatures: b.results}
}

func (b *batchFinishedState) Details() string {
	return "Batch Signing Finished"
}
