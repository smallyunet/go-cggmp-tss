package reshare

import (
	"math/big"

	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// CommitData is the data committed to in Round 1 and decommitted in Round 2.
type CommitData struct {
	PaillierN  []byte     `json:"paillier_n,omitempty"`
	VSS        []*big.Int `json:"vss,omitempty"`
	GlobalPubX []byte     `json:"global_pub_x,omitempty"`
	GlobalPubY []byte     `json:"global_pub_y,omitempty"`
}

// ReshareMessage is the concrete message type for Key Resharing.
type ReshareMessage struct {
	FromParty  tss.PartyID
	ToParties  []tss.PartyID
	IsBcast    bool
	Data       []byte
	TypeString string
	RoundNum   uint32
}

func (m *ReshareMessage) Type() string {
	return m.TypeString
}

func (m *ReshareMessage) From() tss.PartyID {
	return m.FromParty
}

func (m *ReshareMessage) To() []tss.PartyID {
	return m.ToParties
}

func (m *ReshareMessage) IsBroadcast() bool {
	return m.IsBcast
}

func (m *ReshareMessage) Payload() []byte {
	return m.Data
}

func (m *ReshareMessage) RoundNumber() uint32 {
	return m.RoundNum
}
