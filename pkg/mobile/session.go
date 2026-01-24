package mobile

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
	"github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
	"github.com/smallyu/go-cggmp-tss/internal/protocol/sign"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// Version is the library version for bindings.
const Version = "v0.0.9"

// VersionString returns the current library version.
func VersionString() string {
	return Version
}

type protocolType string

const (
	protocolKeyGen protocolType = "keygen"
	protocolSign   protocolType = "sign"
)

// Session is a gomobile-friendly wrapper over a protocol state machine.
//
// All inputs/outputs are JSON strings to keep the mobile bindings simple.
// See docs/MOBILE.md for the JSON schema.
type Session struct {
	mu       sync.Mutex
	protocol protocolType
	sm       tss.StateMachine
	pending  []tss.Message
}

// NewKeyGenSession starts a KeyGen session.
func NewKeyGenSession(paramsJSON string) (*Session, error) {
	var input ParamsInput
	if err := json.Unmarshal([]byte(paramsJSON), &input); err != nil {
		return nil, fmt.Errorf("invalid params json: %w", err)
	}

	params, err := cleanParams(input)
	if err != nil {
		return nil, err
	}

	sm, outMsgs, err := keygen.NewStateMachine(params)
	if err != nil {
		return nil, fmt.Errorf("create keygen state machine: %w", err)
	}

	return &Session{
		protocol: protocolKeyGen,
		sm:       sm,
		pending:  outMsgs,
	}, nil
}

// NewSigningSession starts a Signing session.
func NewSigningSession(paramsJSON string) (*Session, error) {
	var input SignParamsInput
	if err := json.Unmarshal([]byte(paramsJSON), &input); err != nil {
		return nil, fmt.Errorf("invalid params json: %w", err)
	}

	params, err := cleanParams(input.ParamsInput)
	if err != nil {
		return nil, err
	}

	msgBytes, err := hex.DecodeString(input.MsgToSign)
	if err != nil {
		return nil, fmt.Errorf("invalid msgToSign hex: %w", err)
	}

	keyData, err := unmarshalKeyData(input.KeyData)
	if err != nil {
		return nil, fmt.Errorf("invalid keyData: %w", err)
	}

	sm, outMsgs, err := sign.NewStateMachine(params, keyData, msgBytes)
	if err != nil {
		return nil, fmt.Errorf("create signing state machine: %w", err)
	}

	return &Session{
		protocol: protocolSign,
		sm:       sm,
		pending:  outMsgs,
	}, nil
}

// TakeMessages returns any pending outgoing messages as a JSON array and clears them.
func (s *Session) TakeMessages() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	msgs := s.pending
	s.pending = nil

	return marshalMessages(msgs)
}

// Update applies an incoming wire message (JSON) and returns produced outgoing messages (JSON array).
func (s *Session) Update(msgJSON string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sm == nil {
		return "", tss.ErrProtocolDone
	}

	realMsg, err := s.decodeMessage([]byte(msgJSON))
	if err != nil {
		return "", err
	}

	nextSm, outMsgs, err := s.sm.Update(realMsg)
	if err != nil {
		return "", err
	}

	if nextSm != nil {
		s.sm = nextSm
	} else {
		s.sm = nil
	}

	return marshalMessages(outMsgs)
}

// Result returns the final output of the session as a JSON string.
// Returns an empty string if the protocol is not finished.
func (s *Session) Result() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sm == nil {
		return "", errors.New("session has no state")
	}

	res := s.sm.Result()
	if res == nil {
		return "", nil
	}

	switch v := res.(type) {
	case *keygen.LocalPartySaveData:
		b, err := json.Marshal(marshalKeyData(v))
		if err != nil {
			return "", fmt.Errorf("marshal keyData: %w", err)
		}
		return string(b), nil
	case *sign.Signature:
		b, err := json.Marshal(SignatureDTO{
			R:     v.R.String(),
			S:     v.S.String(),
			RecID: v.RecID,
		})
		if err != nil {
			return "", fmt.Errorf("marshal signature: %w", err)
		}
		return string(b), nil
	default:
		b, err := json.Marshal(res)
		if err != nil {
			return "", fmt.Errorf("marshal result: %w", err)
		}
		return string(b), nil
	}
}

// Details returns human-readable state details.
func (s *Session) Details() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sm == nil {
		return "Finished"
	}
	return s.sm.Details()
}

// Close releases the session state.
//
// After calling Close, Update will return tss.ErrProtocolDone.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sm = nil
	s.pending = nil
}

func (s *Session) decodeMessage(msgJSON []byte) (tss.Message, error) {
	var dto MessageDTO
	if err := json.Unmarshal(msgJSON, &dto); err != nil {
		return nil, fmt.Errorf("invalid message dto: %w", err)
	}

	dataBytes, err := hex.DecodeString(dto.Data)
	if err != nil {
		return nil, fmt.Errorf("invalid message data hex: %w", err)
	}

	fromParty := &SimplePartyID{IDVal: dto.From, MonikerVal: dto.From}
	var toParties []tss.PartyID
	for _, to := range dto.To {
		toParties = append(toParties, &SimplePartyID{IDVal: to, MonikerVal: to})
	}

	switch s.protocol {
	case protocolKeyGen:
		return &keygen.KeyGenMessage{
			FromParty:  fromParty,
			ToParties:  toParties,
			IsBcast:    dto.IsBroadcast,
			Data:       dataBytes,
			TypeString: dto.Type,
			RoundNum:   dto.Round,
		}, nil
	case protocolSign:
		return &sign.SignMessage{
			FromParty:  fromParty,
			ToParties:  toParties,
			IsBcast:    dto.IsBroadcast,
			Data:       dataBytes,
			TypeString: dto.Type,
			RoundNum:   dto.Round,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", s.protocol)
	}
}

func marshalMessages(msgs []tss.Message) (string, error) {
	encoded := encodeMessages(msgs)
	b, err := json.Marshal(encoded)
	if err != nil {
		return "", fmt.Errorf("marshal messages: %w", err)
	}
	return string(b), nil
}

func encodeMessages(msgs []tss.Message) []MessageDTO {
	out := make([]MessageDTO, 0, len(msgs))
	for _, m := range msgs {
		var toIDs []string
		for _, p := range m.To() {
			toIDs = append(toIDs, p.ID())
		}
		out = append(out, MessageDTO{
			From:        m.From().ID(),
			To:          toIDs,
			IsBroadcast: m.IsBroadcast(),
			Data:        hex.EncodeToString(m.Payload()),
			Type:        m.Type(),
			Round:       m.RoundNumber(),
		})
	}
	return out
}

func cleanParams(input ParamsInput) (*tss.Parameters, error) {
	parties := make([]tss.PartyID, len(input.AllParties))
	var localParty tss.PartyID

	for i, pid := range input.AllParties {
		p := &SimplePartyID{IDVal: pid, MonikerVal: pid}
		parties[i] = p
		if pid == input.PartyID {
			localParty = p
		}
	}

	if localParty == nil {
		return nil, errors.New("local party ID not found in allParties")
	}

	return &tss.Parameters{
		PartyID:        localParty,
		Parties:        parties,
		Threshold:      input.Threshold,
		Curve:          "secp256k1",
		SessionID:      []byte(input.SessionID),
		OneRoundKeyGen: input.OneRoundKeyGen,
	}, nil
}

// SimplePartyID is a minimal PartyID implementation for bindings.
type SimplePartyID struct {
	IDVal      string
	MonikerVal string
}

func (p *SimplePartyID) ID() string      { return p.IDVal }
func (p *SimplePartyID) Moniker() string { return p.MonikerVal }
func (p *SimplePartyID) Key() []byte     { return []byte(p.IDVal) }

func marshalKeyData(data *keygen.LocalPartySaveData) LocalPartySaveDataDTO {
	dto := LocalPartySaveDataDTO{
		LocalPartyID:    data.LocalPartyID.ID(),
		ECDSAPubX:       data.ECDSAPubX.String(),
		ECDSAPubY:       data.ECDSAPubY.String(),
		ShareID:         data.ShareID.String(),
		Ui:              data.Ui.String(),
		Xi:              data.Xi.String(),
		XiX:             data.XiX.String(),
		XiY:             data.XiY.String(),
		PublicKeyX:      data.PublicKeyX.String(),
		PublicKeyY:      data.PublicKeyY.String(),
		PeerPaillierPks: map[string]string{},
	}
	if data.PaillierPk != nil {
		dto.PaillierN = data.PaillierPk.N.String()
	}
	if data.PaillierSk != nil {
		dto.PaillierLambda = data.PaillierSk.Lambda.String()
		dto.PaillierMu = data.PaillierSk.Mu.String()
	}
	for pid, pk := range data.PeerPaillierPks {
		dto.PeerPaillierPks[pid] = pk.N.String()
	}
	return dto
}

func unmarshalKeyData(raw json.RawMessage) (*keygen.LocalPartySaveData, error) {
	var dto LocalPartySaveDataDTO
	if err := json.Unmarshal(raw, &dto); err != nil {
		return nil, err
	}

	toBig := func(s string) *big.Int {
		if s == "" {
			return nil
		}
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil
		}
		return n
	}

	data := &keygen.LocalPartySaveData{
		LocalPartyID: &SimplePartyID{IDVal: dto.LocalPartyID, MonikerVal: dto.LocalPartyID},
		ECDSAPubX:    toBig(dto.ECDSAPubX),
		ECDSAPubY:    toBig(dto.ECDSAPubY),
		ShareID:      toBig(dto.ShareID),
		Ui:           toBig(dto.Ui),
		Xi:           toBig(dto.Xi),
		XiX:          toBig(dto.XiX),
		XiY:          toBig(dto.XiY),
		PublicKeyX:   toBig(dto.PublicKeyX),
		PublicKeyY:   toBig(dto.PublicKeyY),
	}

	if dto.PaillierN != "" {
		n := toBig(dto.PaillierN)
		if n == nil {
			return nil, errors.New("invalid paillier N")
		}
		n2 := new(big.Int).Mul(n, n)
		pk := &paillier.PublicKey{N: n, N2: n2}
		data.PaillierPk = pk

		if dto.PaillierLambda != "" && dto.PaillierMu != "" {
			lambda := toBig(dto.PaillierLambda)
			mu := toBig(dto.PaillierMu)
			if lambda == nil || mu == nil {
				return nil, errors.New("invalid paillier private params")
			}
			data.PaillierSk = &paillier.PrivateKey{
				PublicKey: *pk,
				Lambda:    lambda,
				Mu:        mu,
			}
		}
	}

	data.PeerPaillierPks = make(map[string]*paillier.PublicKey)
	for pid, nStr := range dto.PeerPaillierPks {
		n := toBig(nStr)
		if n == nil {
			return nil, fmt.Errorf("invalid peer paillier N for %s", pid)
		}
		n2 := new(big.Int).Mul(n, n)
		data.PeerPaillierPks[pid] = &paillier.PublicKey{N: n, N2: n2}
	}

	return data, nil
}
