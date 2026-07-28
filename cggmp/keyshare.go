package cggmp

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
)

// KeyShareJSON is the stable, decimal-string JSON representation of KeyShare.
// The encoded value contains secret material and must be encrypted at rest.
type KeyShareJSON struct {
	LocalPartyID string `json:"localPartyID"`

	ECDSAPubX string `json:"ecdsaPubX"`
	ECDSAPubY string `json:"ecdsaPubY"`
	ShareID   string `json:"shareID"`

	PaillierN      string            `json:"paillierN"`
	PaillierLambda string            `json:"paillierLambda"`
	PaillierMu     string            `json:"paillierMu"`
	PeerPaillier   map[string]string `json:"peerPaillier"`

	Ui         string `json:"ui"`
	Xi         string `json:"xi"`
	XiX        string `json:"xiX"`
	XiY        string `json:"xiY"`
	PublicKeyX string `json:"publicKeyX"`
	PublicKeyY string `json:"publicKeyY"`
}

// MarshalKeyShare serializes a key share without losing big-integer precision.
func MarshalKeyShare(share *KeyShare) ([]byte, error) {
	if err := validateKeyShare(share); err != nil {
		return nil, err
	}
	dto := KeyShareJSON{
		LocalPartyID:   share.LocalPartyID.ID(),
		ECDSAPubX:      share.ECDSAPubX.String(),
		ECDSAPubY:      share.ECDSAPubY.String(),
		ShareID:        share.ShareID.String(),
		PaillierN:      share.PaillierPk.N.String(),
		PaillierLambda: share.PaillierSk.Lambda.String(),
		PaillierMu:     share.PaillierSk.Mu.String(),
		PeerPaillier:   make(map[string]string, len(share.PeerPaillierPks)),
		Ui:             share.Ui.String(),
		Xi:             share.Xi.String(),
		XiX:            share.XiX.String(),
		XiY:            share.XiY.String(),
		PublicKeyX:     share.PublicKeyX.String(),
		PublicKeyY:     share.PublicKeyY.String(),
	}
	for id, key := range share.PeerPaillierPks {
		if id == "" || key == nil || key.N == nil {
			return nil, errors.New("cggmp: invalid peer Paillier key")
		}
		dto.PeerPaillier[id] = key.N.String()
	}
	return json.Marshal(dto)
}

// ParseKeyShare restores a key share for the supplied local party.
func ParseKeyShare(data []byte, localParty PartyID) (*KeyShare, error) {
	if localParty == nil || localParty.ID() == "" {
		return nil, errors.New("cggmp: local party is required")
	}
	var dto KeyShareJSON
	if err := json.Unmarshal(data, &dto); err != nil {
		return nil, fmt.Errorf("cggmp: decode key share: %w", err)
	}
	if dto.LocalPartyID != localParty.ID() {
		return nil, errors.New("cggmp: key share belongs to a different party")
	}

	parse := func(name, value string) (*big.Int, error) {
		n, ok := new(big.Int).SetString(value, 10)
		if !ok || n.Sign() < 0 {
			return nil, fmt.Errorf("cggmp: invalid %s", name)
		}
		return n, nil
	}
	values := make(map[string]*big.Int)
	for name, value := range map[string]string{
		"ecdsaPubX": dto.ECDSAPubX, "ecdsaPubY": dto.ECDSAPubY,
		"shareID": dto.ShareID, "paillierN": dto.PaillierN,
		"paillierLambda": dto.PaillierLambda, "paillierMu": dto.PaillierMu,
		"ui": dto.Ui, "xi": dto.Xi, "xiX": dto.XiX, "xiY": dto.XiY,
		"publicKeyX": dto.PublicKeyX, "publicKeyY": dto.PublicKeyY,
	} {
		n, err := parse(name, value)
		if err != nil {
			return nil, err
		}
		values[name] = n
	}

	n := values["paillierN"]
	if n.BitLen() < 2040 {
		return nil, errors.New("cggmp: Paillier modulus is smaller than 2048 bits")
	}
	inverse := new(big.Int).ModInverse(values["paillierLambda"], n)
	if inverse == nil || inverse.Cmp(values["paillierMu"]) != 0 {
		return nil, errors.New("cggmp: inconsistent Paillier private key")
	}
	if !validPoint(values["ecdsaPubX"], values["ecdsaPubY"]) ||
		!validPoint(values["xiX"], values["xiY"]) ||
		!validPoint(values["publicKeyX"], values["publicKeyY"]) {
		return nil, errors.New("cggmp: invalid secp256k1 point")
	}

	n2 := new(big.Int).Mul(n, n)
	publicKey := &paillier.PublicKey{N: n, N2: n2}
	privateKey := &paillier.PrivateKey{
		PublicKey: *publicKey,
		Lambda:    values["paillierLambda"],
		Mu:        values["paillierMu"],
	}
	peers := make(map[string]*paillier.PublicKey, len(dto.PeerPaillier))
	for id, encodedN := range dto.PeerPaillier {
		peerN, err := parse("peer Paillier modulus", encodedN)
		if err != nil || id == "" || peerN.BitLen() < 2040 {
			return nil, errors.New("cggmp: invalid peer Paillier key")
		}
		peers[id] = &paillier.PublicKey{
			N:  peerN,
			N2: new(big.Int).Mul(peerN, peerN),
		}
	}

	share := &KeyShare{
		LocalPartyID:    localParty,
		ECDSAPubX:       values["ecdsaPubX"],
		ECDSAPubY:       values["ecdsaPubY"],
		ShareID:         values["shareID"],
		PaillierSk:      privateKey,
		PaillierPk:      publicKey,
		PeerPaillierPks: peers,
		Ui:              values["ui"],
		Xi:              values["xi"],
		XiX:             values["xiX"],
		XiY:             values["xiY"],
		PublicKeyX:      values["publicKeyX"],
		PublicKeyY:      values["publicKeyY"],
	}
	if err := validateKeyShare(share); err != nil {
		return nil, err
	}
	return share, nil
}

func validateKeyShare(share *KeyShare) error {
	if share == nil || share.LocalPartyID == nil || share.LocalPartyID.ID() == "" {
		return errors.New("cggmp: key share and local party are required")
	}
	required := []*big.Int{
		share.ECDSAPubX, share.ECDSAPubY, share.ShareID, share.Ui, share.Xi,
		share.XiX, share.XiY, share.PublicKeyX, share.PublicKeyY,
	}
	for _, value := range required {
		if value == nil || value.Sign() < 0 {
			return errors.New("cggmp: key share is incomplete")
		}
	}
	if share.PaillierSk == nil || share.PaillierPk == nil ||
		share.PaillierPk.N == nil || share.PaillierSk.Lambda == nil ||
		share.PaillierSk.Mu == nil {
		return errors.New("cggmp: Paillier key is incomplete")
	}
	if share.PaillierPk.N.BitLen() < 2040 ||
		share.PaillierSk.N == nil ||
		share.PaillierSk.N.Cmp(share.PaillierPk.N) != 0 {
		return errors.New("cggmp: Paillier key is invalid")
	}
	inverse := new(big.Int).ModInverse(share.PaillierSk.Lambda, share.PaillierPk.N)
	if inverse == nil || inverse.Cmp(share.PaillierSk.Mu) != 0 {
		return errors.New("cggmp: inconsistent Paillier private key")
	}
	if !validPoint(share.ECDSAPubX, share.ECDSAPubY) ||
		!validPoint(share.XiX, share.XiY) ||
		!validPoint(share.PublicKeyX, share.PublicKeyY) {
		return errors.New("cggmp: invalid secp256k1 point")
	}
	return nil
}

func validPoint(x, y *big.Int) bool {
	return x != nil && y != nil && secp256k1.S256().IsOnCurve(x, y)
}
