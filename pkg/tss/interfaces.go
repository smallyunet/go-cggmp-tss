package tss

import "errors"

// Common errors returned by the TSS library
var (
	ErrRoundTimeout = errors.New("protocol round timeout")
	ErrInvalidMsg   = errors.New("invalid message received")
	ErrProtocolDone = errors.New("protocol already finished")
)

// PartyID represents a participant in the MPC protocol.
// It must be unique within a session.
type PartyID interface {
	// ID returns the unique string identifier for the party.
	ID() string

	// Moniker returns a human-readable name for the party (optional).
	Moniker() string

	// Key returns the public key associated with this party's identity.
	// This is used to verify the authenticity of messages sent by this party.
	Key() []byte
}

// Message is the generic interface for all protocol messages.
// All wire messages (e.g., Protobuf structs) must implement this interface.
type Message interface {
	// Type returns a string identifier for the message type.
	Type() string

	// From returns the sender's PartyID.
	From() PartyID

	// To returns the intended recipients.
	// If nil or empty, the message is treated as a broadcast message.
	To() []PartyID

	// IsBroadcast returns true if the message is intended for all parties.
	IsBroadcast() bool

	// Payload returns the serialized data of the message.
	Payload() []byte

	// RoundNumber returns the protocol round this message belongs to.
	RoundNumber() uint32
}

// StateMachine is the core engine that drives the protocol.
// It follows a functional state transition pattern.
type StateMachine interface {
	// Update applies an incoming message to the current state.
	// It returns:
	// - next: The new state machine (nil if protocol finished or failed).
	// - out: A slice of messages to be sent to other parties.
	// - err: An error if the transition failed.
	Update(msg Message) (next StateMachine, out []Message, err error)

	// Result returns the final output of the protocol (e.g., KeyGen output or Signature).
	// Returns nil if the protocol is not yet finished.
	Result() interface{}

	// Details returns metadata about the current state (e.g., "KeyGen Round 2").
	Details() string
}

// Parameters holds the configuration for a TSS protocol session.
type Parameters struct {
	PartyID    PartyID   // The identity of the local party
	Parties    []PartyID // List of all participants (sorted)
	Threshold  int       // The threshold (t)
	Curve      string    // The elliptic curve to use (e.g., "secp256k1")
	SessionID  []byte    // Unique session identifier to prevent replay attacks
}

// ProtocolInitializer defines the function signature for starting a new protocol.
type ProtocolInitializer func(params *Parameters) (StateMachine, []Message, error)
