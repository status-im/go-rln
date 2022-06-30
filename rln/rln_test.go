package rln_test

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/decanus/go-rln/rln"
)

func TestNew(t *testing.T) {

	_, err := rln.NewRLNWithDepth(32)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerateKey(t *testing.T) {
	r, err := rln.NewRLNWithDepth(32)
	if err != nil {
		t.Fatal(err)
	}

	k, err := r.MembershipKeyGen()
	if err != nil {
		t.Fatal(err)
	}

	if reflect.DeepEqual(k.IDKey, [32]byte{}) {
		t.Fatal("k.IDKey was empty")
	}

	if reflect.DeepEqual(k.IDCommitment, [32]byte{}) {
		t.Fatal("k.IDCommitment was empty")
	}
}

func TestRLN_Hash(t *testing.T) {
	// This test is based on tests from:
	// https://github.com/status-im/nim-waku/blob/b7998de09d1ef04599a699938da69aecfa63cc6f/tests/v2/test_waku_rln_relay.nim#L527

	r, err := rln.NewRLNWithDepth(32)
	if err != nil {
		t.Fatal(err)
	}

	input := byteArray(32, 1)

	output, err := r.Hash(input)
	if err != nil {
		t.Fatal(err)
	}

	expected := "9b581442bb7fe1bc29b5cfbc29377c0b080549bcd902d1290288d93fc773bb20"
	if expected != hex.EncodeToString(output[:]) {
		t.Fatalf("value %x did not match expected %s", output, expected)
	}
}

func TestRLN_GetRoot(t *testing.T) {
	// This test is based on tests from:
	// https://github.com/status-im/nim-waku/blob/b7998de09d1ef04599a699938da69aecfa63cc6f/tests/v2/test_waku_rln_relay.nim#L320

	r, err := rln.NewRLNWithDepth(32)
	if err != nil {
		t.Fatal(err)
	}

	root1, err := r.GetMerkleRoot()
	if err != nil {
		t.Fatal(err)
	}

	root2, err := r.GetMerkleRoot()
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(root1[:]) != hex.EncodeToString(root2[:]) {
		t.Fatalf("value %x did not match expected %x", root1, root2)
	}
}

func byteArray(length int, value byte) []byte {
	arr := make([]byte, length)

	for i := 0; i < length; i++ {
		arr[i] = value
	}

	return arr
}
