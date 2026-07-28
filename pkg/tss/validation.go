package tss

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
)

const maxProtocolPayloadSize = 4 << 20

// ValidateParameters validates the invariants shared by all protocol sessions.
func ValidateParameters(params *Parameters) error {
	return validateParameters(params, true)
}

// ValidateCommitteeParameters validates a committee definition without
// requiring the local party to be a member. Resharing uses this for old-only
// and new-only participants.
func ValidateCommitteeParameters(params *Parameters) error {
	return validateParameters(params, false)
}

func validateParameters(params *Parameters, requireLocal bool) error {
	if params == nil {
		return fmt.Errorf("%w: parameters are nil", ErrInvalidParameters)
	}
	if requireLocal && (params.PartyID == nil || params.PartyID.ID() == "") {
		return fmt.Errorf("%w: local party is missing", ErrInvalidParameters)
	}
	if len(params.Parties) < 2 {
		return fmt.Errorf("%w: at least two parties are required", ErrInvalidParameters)
	}
	if params.Threshold < 1 || params.Threshold >= len(params.Parties) {
		return fmt.Errorf("%w: threshold must be in [1, parties-1]", ErrInvalidParameters)
	}
	if params.Curve != "secp256k1" {
		return fmt.Errorf("%w: unsupported curve %q", ErrInvalidParameters, params.Curve)
	}
	if len(params.SessionID) < 16 {
		return fmt.Errorf("%w: session ID must be at least 16 bytes", ErrInvalidParameters)
	}

	seen := make(map[string]struct{}, len(params.Parties))
	localFound := false
	previousID := ""
	for _, party := range params.Parties {
		if party == nil || party.ID() == "" {
			return fmt.Errorf("%w: party ID is missing", ErrInvalidParameters)
		}
		if _, exists := seen[party.ID()]; exists {
			return fmt.Errorf("%w: duplicate party ID %q", ErrInvalidParameters, party.ID())
		}
		if previousID != "" && party.ID() <= previousID {
			return fmt.Errorf("%w: parties must be sorted by ID", ErrInvalidParameters)
		}
		seen[party.ID()] = struct{}{}
		previousID = party.ID()
		if params.PartyID != nil && party.ID() == params.PartyID.ID() {
			localFound = true
		}
	}
	if requireLocal && !localFound {
		return fmt.Errorf("%w: local party is not in the participant set", ErrInvalidParameters)
	}
	return nil
}

// PartyIndex returns the non-zero polynomial coordinate assigned to a party.
// Parameters require every participant to use the same ID-sorted party list.
func PartyIndex(parties []PartyID, partyID string) (*big.Int, error) {
	for index, party := range parties {
		if party != nil && party.ID() == partyID {
			return big.NewInt(int64(index + 1)), nil
		}
	}
	return nil, fmt.Errorf("%w: party %q is not in the participant set", ErrInvalidParameters, partyID)
}

// ValidateMessage validates the session envelope before protocol-specific
// payload processing. Message authenticity must already have been established
// by the caller's transport.
func ValidateMessage(params *Parameters, msg Message, expectedRound uint32, allowedTypes ...string) error {
	if params == nil {
		return fmt.Errorf("%w: parameters are nil", ErrInvalidMsg)
	}
	return ValidateMessageForParties(
		params.PartyID,
		params.Parties,
		params.SessionID,
		msg,
		expectedRound,
		allowedTypes...,
	)
}

// ValidateMessageForParties is ValidateMessage with an explicit participant
// set, used by resharing where old and new committees overlap.
func ValidateMessageForParties(
	local PartyID,
	parties []PartyID,
	sessionID []byte,
	msg Message,
	expectedRound uint32,
	allowedTypes ...string,
) error {
	if msg == nil || msg.From() == nil {
		return fmt.Errorf("%w: message or sender is nil", ErrInvalidMsg)
	}
	if msg.RoundNumber() != expectedRound {
		return fmt.Errorf("%w: received round %d, expected %d", ErrInvalidMsg, msg.RoundNumber(), expectedRound)
	}
	bound, ok := msg.(SessionBoundMessage)
	if !ok || !bytes.Equal(bound.SessionID(), sessionID) {
		return fmt.Errorf("%w: session ID mismatch", ErrInvalidMsg)
	}
	if msg.Type() == "" {
		return fmt.Errorf("%w: message type is empty", ErrInvalidMsg)
	}
	if len(allowedTypes) > 0 {
		allowed := false
		for _, typ := range allowedTypes {
			if msg.Type() == typ {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: message type %q is not valid for round %d", ErrInvalidMsg, msg.Type(), expectedRound)
		}
	}
	if len(msg.Payload()) == 0 || len(msg.Payload()) > maxProtocolPayloadSize {
		return fmt.Errorf("%w: payload size is invalid", ErrInvalidMsg)
	}

	senderFound := false
	for _, party := range parties {
		if party != nil && party.ID() == msg.From().ID() {
			senderFound = true
			break
		}
	}
	if !senderFound {
		return fmt.Errorf("%w: sender %q is not a participant", ErrInvalidMsg, msg.From().ID())
	}

	directType := strings.HasSuffix(msg.Type(), "_Share") || strings.HasSuffix(msg.Type(), "_MtA")
	if msg.IsBroadcast() {
		if directType {
			return fmt.Errorf("%w: direct message type %q was marked broadcast", ErrInvalidMsg, msg.Type())
		}
		if len(msg.To()) != 0 {
			return fmt.Errorf("%w: broadcast message has direct recipients", ErrInvalidMsg)
		}
		return nil
	}
	if !directType {
		return fmt.Errorf("%w: broadcast message type %q was marked direct", ErrInvalidMsg, msg.Type())
	}
	if local == nil || len(msg.To()) != 1 || msg.To()[0] == nil || msg.To()[0].ID() != local.ID() {
		return fmt.Errorf("%w: direct message is not addressed to the local party", ErrInvalidMsg)
	}
	return nil
}
