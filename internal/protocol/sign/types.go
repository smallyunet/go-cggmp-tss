package sign

import (
	"math/big"

	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// Signature represents the result of the signing protocol.
type Signature struct {
	R *big.Int
	S *big.Int
	RecID int // Recovery ID (optional)
}

// SignMessage is the concrete message type for Signing.
type SignMessage struct {
	FromParty   tss.PartyID
	ToParties   []tss.PartyID
	IsBcast     bool
	Data        []byte
	TypeString  string
	RoundNum    uint32
}

func (m *SignMessage) Type() string {
	return m.TypeString
}

func (m *SignMessage) From() tss.PartyID {
	return m.FromParty
}

func (m *SignMessage) To() []tss.PartyID {
	return m.ToParties
}

func (m *SignMessage) IsBroadcast() bool {
	return m.IsBcast
}

func (m *SignMessage) Payload() []byte {
	return m.Data
}

func (m *SignMessage) RoundNumber() uint32 {
	return m.RoundNum
}
