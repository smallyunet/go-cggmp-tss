package mobile

import "encoding/json"

// ParamsInput is the JSON schema to initialize a protocol session.
type ParamsInput struct {
	PartyID        string   `json:"partyID"`
	AllParties     []string `json:"allParties"`
	Threshold      int      `json:"threshold"`
	SessionID      string   `json:"sessionID"`
	OneRoundKeyGen bool     `json:"oneRoundKeyGen"`
}

// SignParamsInput is the JSON schema to initialize a Signing session.
type SignParamsInput struct {
	ParamsInput
	KeyData   json.RawMessage `json:"keyData"`   // LocalPartySaveDataDTO
	MsgToSign string          `json:"msgToSign"` // Hex string (hash)
}

// RefreshParamsInput is the JSON schema to initialize a Refresh session.
type RefreshParamsInput struct {
	ParamsInput
	KeyData json.RawMessage `json:"keyData"` // LocalPartySaveDataDTO
}

// MessageDTO is the JSON schema for wire messages.
type MessageDTO struct {
	From        string   `json:"from"`
	To          []string `json:"to"`
	IsBroadcast bool     `json:"isBroadcast"`
	Data        string   `json:"data"` // Hex encoded
	Type        string   `json:"type"`
	Round       uint32   `json:"round"`
}

// LocalPartySaveDataDTO uses strings for big.Int values.
type LocalPartySaveDataDTO struct {
	LocalPartyID string `json:"LocalPartyID"`

	ECDSAPubX string `json:"ECDSAPubX"`
	ECDSAPubY string `json:"ECDSAPubY"`

	ShareID string `json:"ShareID"`

	PaillierN string `json:"PaillierN"`

	PeerPaillierPks map[string]string `json:"PeerPaillierPks"`

	Ui  string `json:"Ui"`
	Xi  string `json:"Xi"`
	XiX string `json:"XiX"`
	XiY string `json:"XiY"`

	PublicKeyX string `json:"PublicKeyX"`
	PublicKeyY string `json:"PublicKeyY"`

	PaillierLambda string `json:"PaillierLambda"`
	PaillierMu     string `json:"PaillierMu"`
}

// SignatureDTO represents an ECDSA signature with big.Int fields encoded as strings.
type SignatureDTO struct {
	R     string `json:"R"`
	S     string `json:"S"`
	RecID int    `json:"RecID"`
}
