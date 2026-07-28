package cggmp_test

import (
	"errors"
	"testing"

	"github.com/smallyu/go-cggmp-tss/cggmp"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

type party struct{ id string }

func (p *party) ID() string      { return p.id }
func (p *party) Moniker() string { return p.id }
func (p *party) Key() []byte     { return nil }

func TestPublicFacadeValidatesParameters(t *testing.T) {
	p1 := &party{id: "p1"}
	p2 := &party{id: "p2"}
	params := &cggmp.Parameters{
		PartyID:   p1,
		Parties:   []cggmp.PartyID{p1, p2},
		Threshold: 1,
		Curve:     "secp256k1",
		SessionID: []byte("short"),
	}
	if _, _, err := cggmp.NewKeygen(params); !errors.Is(err, tss.ErrInvalidParameters) {
		t.Fatalf("expected public constructor to validate parameters, got %v", err)
	}
}

func TestParseKeyShareRejectsWrongOwner(t *testing.T) {
	p1 := &party{id: "p1"}
	data := []byte(`{"localPartyID":"p2"}`)
	if _, err := cggmp.ParseKeyShare(data, p1); err == nil {
		t.Fatal("expected key-share owner mismatch to be rejected")
	}
}

func TestPublicKeygenAndKeyShareCodec(t *testing.T) {
	p1 := &party{id: "p1"}
	p2 := &party{id: "p2"}
	parties := []cggmp.PartyID{p1, p2}
	states := map[string]cggmp.StateMachine{}
	var queue []cggmp.Message

	for _, local := range parties {
		state, messages, err := cggmp.NewKeygen(&cggmp.Parameters{
			PartyID:   local,
			Parties:   parties,
			Threshold: 1,
			Curve:     "secp256k1",
			SessionID: []byte("public-api-test-01"),
		})
		if err != nil {
			t.Fatalf("start public keygen: %v", err)
		}
		states[local.ID()] = state
		queue = append(queue, messages...)
	}

	for len(queue) > 0 {
		message := queue[0]
		queue = queue[1:]
		for _, recipient := range messageRecipients(message, parties) {
			next, output, err := states[recipient.ID()].Update(message)
			if err != nil {
				t.Fatalf("route public message: %v", err)
			}
			states[recipient.ID()] = next
			queue = append(queue, output...)
		}
	}

	for _, local := range parties {
		result := states[local.ID()].Result()
		share, ok := result.(*cggmp.KeyShare)
		if !ok {
			t.Fatalf("party %s did not produce a key share", local.ID())
		}
		encoded, err := cggmp.MarshalKeyShare(share)
		if err != nil {
			t.Fatalf("marshal public key share: %v", err)
		}
		restored, err := cggmp.ParseKeyShare(encoded, local)
		if err != nil {
			t.Fatalf("parse public key share: %v", err)
		}
		if restored.Xi.Cmp(share.Xi) != 0 || restored.PublicKeyX.Cmp(share.PublicKeyX) != 0 {
			t.Fatal("restored key share differs from original")
		}
	}
}

func messageRecipients(message cggmp.Message, parties []cggmp.PartyID) []cggmp.PartyID {
	if !message.IsBroadcast() {
		return message.To()
	}
	recipients := make([]cggmp.PartyID, 0, len(parties)-1)
	for _, candidate := range parties {
		if candidate.ID() != message.From().ID() {
			recipients = append(recipients, candidate)
		}
	}
	return recipients
}
