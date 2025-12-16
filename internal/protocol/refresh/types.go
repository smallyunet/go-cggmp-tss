package refresh

import (
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// RefreshMessage is the concrete message type for Key Refresh.
type RefreshMessage struct {
	FromParty   tss.PartyID
	ToParties   []tss.PartyID
	IsBcast     bool
	Data        []byte
	TypeString  string
	RoundNum    uint32
}

func (m *RefreshMessage) Type() string {
	return m.TypeString
}

func (m *RefreshMessage) From() tss.PartyID {
	return m.FromParty
}

func (m *RefreshMessage) To() []tss.PartyID {
	return m.ToParties
}

func (m *RefreshMessage) IsBroadcast() bool {
	return m.IsBcast
}

func (m *RefreshMessage) Payload() []byte {
	return m.Data
}

func (m *RefreshMessage) RoundNumber() uint32 {
	return m.RoundNum
}
