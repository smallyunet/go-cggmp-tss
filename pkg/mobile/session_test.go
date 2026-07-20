package mobile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func TestMobileWrapper_KeyGenRefreshAndSign(t *testing.T) {
	party1 := "1"
	party2 := "2"
	party3 := "3"
	all := []string{party1, party2, party3}
	sessionID := "sid-refresh"

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
	p3Params, _ := json.Marshal(ParamsInput{
		PartyID:        party3,
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
	s3, err := NewKeyGenSession(string(p3Params))
	if err != nil {
		t.Fatalf("NewKeyGenSession p3: %v", err)
	}

	sessions := map[string]*Session{
		party1: s1,
		party2: s2,
		party3: s3,
	}

	wire := make([]testWireMessage, 0)
	for _, party := range all {
		wire = append(wire, takeAndRouteForParties(t, party, sessions[party], all)...)
	}

	keyData := runUntilDoneMulti(t, sessions, wire, all, "keygen", nil)

	refreshSessions := map[string]*Session{
		party1: newRefreshSession(t, party1, all, sessionID+"-refresh", keyData[party1]),
		party2: newRefreshSession(t, party2, all, sessionID+"-refresh", keyData[party2]),
		party3: newRefreshSession(t, party3, all, sessionID+"-refresh", keyData[party3]),
	}

	wire = nil
	for _, party := range all {
		wire = append(wire, takeAndRouteForParties(t, party, refreshSessions[party], all)...)
	}

	refreshed := runUntilDoneMulti(t, refreshSessions, wire, all, "refresh", nil)
	for _, party := range all {
		assertRefreshedKeyData(t, keyData[party], refreshed[party])
	}

	msgHash := sha256.Sum256([]byte("hello-after-refresh"))
	msgHex := hex.EncodeToString(msgHash[:])

	signSessions := map[string]*Session{
		party1: newSigningSession(t, party1, all, sessionID+"-sign", refreshed[party1], msgHex),
		party2: newSigningSession(t, party2, all, sessionID+"-sign", refreshed[party2], msgHex),
		party3: newSigningSession(t, party3, all, sessionID+"-sign", refreshed[party3], msgHex),
	}

	wire = nil
	for _, party := range all {
		wire = append(wire, takeAndRouteForParties(t, party, signSessions[party], all)...)
	}

	runUntilDoneMulti(t, signSessions, wire, all, "sign", assertSignatureJSON)
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

func newRefreshSession(t *testing.T, party string, all []string, sessionID string, keyDataJSON string) *Session {
	rawKey := json.RawMessage(keyDataJSON)

	params, err := json.Marshal(RefreshParamsInput{
		ParamsInput: ParamsInput{
			PartyID:        party,
			AllParties:     all,
			Threshold:      1,
			SessionID:      sessionID,
			OneRoundKeyGen: false,
		},
		KeyData: rawKey,
	})
	if err != nil {
		t.Fatalf("marshal refresh params: %v", err)
	}

	s, err := NewRefreshSession(string(params))
	if err != nil {
		t.Fatalf("NewRefreshSession party %s: %v", party, err)
	}
	return s
}

func runUntilDoneMulti(t *testing.T, sessions map[string]*Session, allWire []testWireMessage, parties []string, protocol string, validate func(*testing.T, string)) map[string]string {
	steps := 0
	wire := allWire
	for len(wire) > 0 {
		if steps > 20_000 {
			t.Fatalf("too many steps in %s (possible deadlock)", protocol)
		}
		steps++

		item := wire[0]
		wire = wire[1:]

		target := sessions[item.ToParty]
		if target == nil {
			t.Fatalf("unknown target party %q", item.ToParty)
		}

		outJSON, err := target.Update(item.JSON)
		if err != nil {
			t.Fatalf("Update party %s: %v", item.ToParty, err)
		}

		wire = append(wire, routeOutgoingForParties(t, outJSON, parties)...)

		results, complete := collectResults(t, sessions, validate)
		if complete {
			return results
		}
	}

	results, complete := collectResults(t, sessions, validate)
	if !complete {
		t.Fatalf("%s not finished for all parties", protocol)
	}

	return results
}

func collectResults(t *testing.T, sessions map[string]*Session, validate func(*testing.T, string)) (map[string]string, bool) {
	results := make(map[string]string, len(sessions))
	for party, session := range sessions {
		resultJSON, err := session.Result()
		if err != nil || resultJSON == "" {
			return nil, false
		}
		if validate != nil {
			validate(t, resultJSON)
		}
		results[party] = resultJSON
	}
	return results, true
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

func assertRefreshedKeyData(t *testing.T, beforeJSON string, afterJSON string) {
	var before LocalPartySaveDataDTO
	if err := json.Unmarshal([]byte(beforeJSON), &before); err != nil {
		t.Fatalf("invalid pre-refresh key json: %v", err)
	}

	var after LocalPartySaveDataDTO
	if err := json.Unmarshal([]byte(afterJSON), &after); err != nil {
		t.Fatalf("invalid refreshed key json: %v", err)
	}

	if before.PublicKeyX != after.PublicKeyX || before.PublicKeyY != after.PublicKeyY {
		t.Fatalf("public key changed across refresh")
	}
	if before.PaillierN == after.PaillierN {
		t.Fatalf("paillier public key did not rotate")
	}
}

func takeAndRoute(t *testing.T, fromParty string, s *Session) []testWireMessage {
	out, err := s.TakeMessages()
	if err != nil {
		t.Fatalf("TakeMessages party %s: %v", fromParty, err)
	}
	return routeOutgoing(t, out)
}

func takeAndRouteForParties(t *testing.T, fromParty string, s *Session, parties []string) []testWireMessage {
	out, err := s.TakeMessages()
	if err != nil {
		t.Fatalf("TakeMessages party %s: %v", fromParty, err)
	}
	return routeOutgoingForParties(t, out, parties)
}

func routeOutgoing(t *testing.T, outJSON string) []testWireMessage {
	return routeOutgoingForParties(t, outJSON, []string{"1", "2"})
}

func routeOutgoingForParties(t *testing.T, outJSON string, parties []string) []testWireMessage {
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
			toParties = parties
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
	return string(b)
}
