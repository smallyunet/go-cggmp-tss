package tss

import "fmt"

// Blame represents an error caused by a specific party.
// It allows the protocol to identify and exclude malicious or faulty parties.
type Blame struct {
	PartyID PartyID
	Reason  string
	Err     error
}

func (b *Blame) Error() string {
	if b.Err != nil {
		return fmt.Sprintf("blame party %s: %s: %v", b.PartyID.ID(), b.Reason, b.Err)
	}
	return fmt.Sprintf("blame party %s: %s", b.PartyID.ID(), b.Reason)
}

func (b *Blame) Unwrap() error {
	return b.Err
}

// NewBlame creates a new Blame error.
func NewBlame(party PartyID, reason string, err error) *Blame {
	return &Blame{
		PartyID: party,
		Reason:  reason,
		Err:     err,
	}
}
