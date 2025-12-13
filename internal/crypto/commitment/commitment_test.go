package commitment

import (
"bytes"
"math/big"
"testing"
)

func TestCommitment(t *testing.T) {
	msg := []byte("Hello, MPC!")

	// 1. Commit
	comm, err := New(msg)
	if err != nil {
		t.Fatalf("Failed to create commitment: %v", err)
	}

	if len(comm.C) != 32 {
		t.Errorf("Expected commitment length 32, got %d", len(comm.C))
	}
	if len(comm.D) != 32 {
		t.Errorf("Expected decommitment length 32, got %d", len(comm.D))
	}

	// 2. Verify
	if !Verify(comm.C, comm.D, msg) {
		t.Fatal("Verification failed for valid commitment")
	}
}

func TestCommitmentVerifyFailed(t *testing.T) {
	msg := []byte("Secret Message")
	comm, _ := New(msg)

	// Case 1: Wrong message
	wrongMsg := []byte("Wrong Message")
	if Verify(comm.C, comm.D, wrongMsg) {
		t.Fatal("Verification passed for wrong message")
	}

	// Case 2: Wrong salt
	wrongSalt := make([]byte, 32)
	copy(wrongSalt, comm.D)
	wrongSalt[0] ^= 0xFF // Flip a bit
	if Verify(comm.C, wrongSalt, msg) {
		t.Fatal("Verification passed for wrong salt")
	}

	// Case 3: Wrong commitment
	wrongC := make([]byte, 32)
	copy(wrongC, comm.C)
	wrongC[0] ^= 0xFF
	if Verify(wrongC, comm.D, msg) {
		t.Fatal("Verification passed for wrong commitment")
	}
}

func TestComplexCommitment(t *testing.T) {
	part1 := []byte("Part 1")
	part2 := big.NewInt(12345).Bytes()
	part3 := []byte("Part 3")

	comm, err := NewComplex(part1, part2, part3)
	if err != nil {
		t.Fatalf("Failed to create complex commitment: %v", err)
	}

	if !VerifyComplex(comm.C, comm.D, part1, part2, part3) {
		t.Fatal("Complex verification failed")
	}

	// Verify failure if one part changes
	part2Modified := big.NewInt(12346).Bytes()
	if VerifyComplex(comm.C, comm.D, part1, part2Modified, part3) {
		t.Fatal("Complex verification passed for modified part")
	}
}

func TestIntToBytes(t *testing.T) {
	i := big.NewInt(100)
	b := IntToBytes(i)
	if !bytes.Equal(b, i.Bytes()) {
		t.Error("IntToBytes failed")
	}

	bNil := IntToBytes(nil)
	if len(bNil) != 0 {
		t.Error("IntToBytes(nil) should return empty slice")
	}
}
