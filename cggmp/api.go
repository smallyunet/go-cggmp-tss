// Package cggmp provides the supported public API for protocol sessions.
//
// The package is intentionally a facade over the implementation packages so
// callers never need to import internal paths.
package cggmp

import (
	"github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
	"github.com/smallyu/go-cggmp-tss/internal/protocol/refresh"
	"github.com/smallyu/go-cggmp-tss/internal/protocol/reshare"
	"github.com/smallyu/go-cggmp-tss/internal/protocol/sign"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

const Version = "v0.1.0"

type (
	PartyID      = tss.PartyID
	Message      = tss.Message
	StateMachine = tss.StateMachine
	Parameters   = tss.Parameters
	KeyShare     = keygen.LocalPartySaveData
	Signature    = sign.Signature
	PreSignature = sign.PreSignature
)

// NewKeygen starts distributed key generation.
func NewKeygen(params *Parameters) (StateMachine, []Message, error) {
	return keygen.NewStateMachine(params)
}

// NewSigner starts threshold signing for a message digest.
func NewSigner(params *Parameters, share *KeyShare, digest []byte) (StateMachine, []Message, error) {
	return sign.NewStateMachine(params, share, digest)
}

// NewPresigner starts the offline signing phase.
func NewPresigner(params *Parameters, share *KeyShare) (StateMachine, []Message, error) {
	return sign.NewPreSignStateMachine(params, share)
}

// NewOnlineSigner completes signing with an unused presignature.
func NewOnlineSigner(
	params *Parameters,
	share *KeyShare,
	preSignature *PreSignature,
	digest []byte,
) (StateMachine, []Message, error) {
	return sign.NewOnlineStateMachine(params, share, preSignature, digest)
}

// NewRefresh starts proactive key refresh.
func NewRefresh(params *Parameters, share *KeyShare) (StateMachine, []Message, error) {
	return refresh.NewStateMachine(params, share)
}

// NewReshare changes the committee and/or threshold while preserving the
// public key. Existing committee members must provide their key share.
func NewReshare(
	newParams *Parameters,
	oldParams *Parameters,
	oldShare *KeyShare,
) (StateMachine, []Message, error) {
	return reshare.NewStateMachine(newParams, oldParams, oldShare)
}
