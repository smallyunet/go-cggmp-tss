package mobile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

type testWireMessage struct {
	ToParty string
	JSON    string
}

func TestMobileWrapper_KeyGenAndSign(t *testing.T) {
	party1 := "1"
	party2 := "2"
	all := []string{party1, party2}
	sessionID := "sid"

	p1Params, _ := json.Marshal(ParamsInput{
		PartyID:        party1,
		AllParties:     all,
		Threshold:      1,
		SessionID:      sessionID,
		OneRoundKeyGen: false,
	})
	p2Params, _ := json.Marshal(ParamsInput{
		PartyID:        party2,
		AllParties:     all,
		Threshold:      1,
		SessionID:      sessionID,
		OneRoundKeyGen: false,
	})

	s1, err := NewKeyGenSession(string(p1Params))
	if err != nil {
		t.Fatalf("NewKeyGenSession p1: %v", err)
	}
	s2, err := NewKeyGenSession(string(p2Params))
	if err != nil {
		t.Fatalf("NewKeyGenSession p2: %v", err)
	}

	wire := make([]testWireMessage, 0)
	wire = append(wire, takeAndRoute(t, party1, s1)...) // p1 initial
	wire = append(wire, takeAndRoute(t, party2, s2)...) // p2 initial

	keyData1, keyData2 := runUntilKeyGenDone(t, s1, s2, wire)

	msgHash := sha256.Sum256([]byte("hello"))
	msgHex := hex.EncodeToString(msgHash[:])

	sign1 := newSigningSession(t, party1, all, sessionID, keyData1, msgHex)
	sign2 := newSigningSession(t, party2, all, sessionID, keyData2, msgHex)

	wire = nil
	wire = append(wire, takeAndRoute(t, party1, sign1)...) // initial
	wire = append(wire, takeAndRoute(t, party2, sign2)...) // initial

	runUntilSignDone(t, sign1, sign2, wire)
}

func runUntilKeyGenDone(t *testing.T, s1, s2 *Session, wire []testWireMessage) (string, string) {
	steps := 0
	for len(wire) > 0 {
		if steps > 10_000 {
			t.Fatal("too many steps (possible deadlock)")
		}
		steps++

		item := wire[0]
		wire = wire[1:]

		var target *Session
		switch item.ToParty {
		case "1":
			target = s1
		case "2":
			target = s2
		default:
			t.Fatalf("unknown target party %q", item.ToParty)
		}

		outJSON, err := target.Update(item.JSON)
		if err != nil {
			t.Fatalf("Update party %s: %v", item.ToParty, err)
		}

		wire = append(wire, routeOutgoing(t, outJSON)...)

		res1, err := s1.Result()
		if err == nil && res1 != "" {
			res2, err := s2.Result()
			if err == nil && res2 != "" {
				return res1, res2
			}
		}
	}

	res1, err1 := s1.Result()
	res2, err2 := s2.Result()
	if err1 != nil || err2 != nil || res1 == "" || res2 == "" {
		t.Fatalf("keygen not finished: res1=%v err1=%v res2=%v err2=%v", res1 != "", err1, res2 != "", err2)
	}

	return res1, res2
}

func newSigningSession(t *testing.T, party string, all []string, sessionID string, keyDataJSON string, msgHex string) *Session {
	rawKey := json.RawMessage(keyDataJSON)

	params, err := json.Marshal(SignParamsInput{
		ParamsInput: ParamsInput{
			PartyID:        party,
			AllParties:     all,
			Threshold:      1,
			SessionID:      sessionID,
			OneRoundKeyGen: false,
		},
		KeyData:   rawKey,
		MsgToSign: msgHex,
	})
	if err != nil {
		t.Fatalf("marshal signing params: %v", err)
	}

	s, err := NewSigningSession(string(params))
	if err != nil {
		t.Fatalf("NewSigningSession party %s: %v", party, err)
	}
	return s
}

func runUntilSignDone(t *testing.T, s1, s2 *Session, wire []testWireMessage) {
	steps := 0
	for len(wire) > 0 {
		if steps > 10_000 {
			t.Fatal("too many steps (possible deadlock)")
		}
		steps++

		item := wire[0]
		wire = wire[1:]

		var target *Session
		switch item.ToParty {
		case "1":
			target = s1
		case "2":
			target = s2
		default:
			t.Fatalf("unknown target party %q", item.ToParty)
		}

		outJSON, err := target.Update(item.JSON)
		if err != nil {
			t.Fatalf("Update party %s: %v", item.ToParty, err)
		}

		wire = append(wire, routeOutgoing(t, outJSON)...)

		res1, err := s1.Result()
		if err == nil && res1 != "" {
			res2, err := s2.Result()
			if err == nil && res2 != "" {
				assertSignatureJSON(t, res1)
				assertSignatureJSON(t, res2)
				return
			}
		}
	}

	res1, err1 := s1.Result()
	res2, err2 := s2.Result()
	if err1 != nil || err2 != nil || res1 == "" || res2 == "" {
		t.Fatalf("sign not finished: res1=%v err1=%v res2=%v err2=%v", res1 != "", err1, res2 != "", err2)
	}

	assertSignatureJSON(t, res1)
	assertSignatureJSON(t, res2)
}

func assertSignatureJSON(t *testing.T, s string) {
	var dto SignatureDTO
	if err := json.Unmarshal([]byte(s), &dto); err != nil {
		t.Fatalf("invalid signature json: %v", err)
	}
	if dto.R == "" || dto.S == "" {
		t.Fatalf("empty signature fields: r=%q s=%q", dto.R, dto.S)
	}
}

func takeAndRoute(t *testing.T, fromParty string, s *Session) []testWireMessage {
	out, err := s.TakeMessages()
	if err != nil {
		t.Fatalf("TakeMessages party %s: %v", fromParty, err)
	}
	return routeOutgoing(t, out)
}

func routeOutgoing(t *testing.T, outJSON string) []testWireMessage {
	if outJSON == "" {
		return nil
	}

	var msgs []MessageDTO
	if err := json.Unmarshal([]byte(outJSON), &msgs); err != nil {
		t.Fatalf("invalid outgoing messages json: %v\njson=%s", err, outJSON)
	}

	var out []testWireMessage
	for _, m := range msgs {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal message dto: %v", err)
		}
		msgJSON := string(b)

		toParties := m.To
		if m.IsBroadcast || len(toParties) == 0 {
			toParties = []string{"1", "2"}
		}

		for _, to := range toParties {
			if to == m.From {
				continue
			}
			out = append(out, testWireMessage{ToParty: to, JSON: msgJSON})
		}
	}

	return out
}

func (m MessageDTO) String() string {
	b, _ := json.Marshal(m)
	return fmt.Sprintf("%s", b)
}
