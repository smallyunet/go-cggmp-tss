package keygen

import (
	"math/big"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// LocalPartySaveData contains the final result of the KeyGen protocol
// that needs to be persisted by the local party.
type LocalPartySaveData struct {
	LocalPartyID tss.PartyID

	// Public Key (X)
	// For now we store coordinates, later we might use a specific Point type
	ECDSAPubX *big.Int
	ECDSAPubY *big.Int

	// Private Key Share (x_i)
	ShareID *big.Int
	Xi      *big.Int

	// Paillier Keys
	PaillierSk *paillier.PrivateKey
	PaillierPk *paillier.PublicKey

	// Our share of the secret key (u_i)
	// This is the constant term of our polynomial F_i(x)
	Ui *big.Int
}

// KeyGenMessage is a concrete implementation of tss.Message for KeyGen
type KeyGenMessage struct {
	FromParty   tss.PartyID
	ToParties   []tss.PartyID
	IsBcast     bool
	Data        []byte
	TypeString  string
	RoundNum    uint32
}

func (m *KeyGenMessage) Type() string {
	return m.TypeString
}

func (m *KeyGenMessage) From() tss.PartyID {
	return m.FromParty
}

func (m *KeyGenMessage) To() []tss.PartyID {
	return m.ToParties
}

func (m *KeyGenMessage) IsBroadcast() bool {
	return m.IsBcast
}

func (m *KeyGenMessage) Payload() []byte {
	return m.Data
}

func (m *KeyGenMessage) RoundNumber() uint32 {
	return m.RoundNum
}
