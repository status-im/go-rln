// Package rln contains bindings for https://github.com/kilic/rln
package rln

/*
#include "./librln.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// RLN represents the context used for rln.
type RLN struct {
	ptr *C.RLN_Bn256
}

// KeyPair generated by the GenerateKey function for RLN values.
type KeyPair struct {
	// Key represents the secret key.
	Key [32]byte

	// Commitment hash of the Key generated by a hash function in the rln lib.
	Commitment [32]byte
}

// @TODO THINK ABOUT AUTH OBJECT

// New returns a new RLN generated from the passed depth and parameters.
func New(depth int, parameters []byte) (*RLN, error) {
	r := &RLN{}

	buf := toBuffer(parameters)

	size := int(unsafe.Sizeof(buf))
	in := (*C.Buffer)(C.malloc(C.size_t(size)))
	*in = buf

	if !bool(C.new_circuit_from_params(C.ulong(depth), in, &r.ptr)) {
		return nil, errors.New("failed to initialize")
	}

	return r, nil
}

// GenerateKey generates a KeyPair for an RLN.
func (r *RLN) GenerateKey() (*KeyPair, error) {
	buffer := toBuffer([]byte{})
	if !bool(C.key_gen(r.ptr, &buffer)) {
		return nil, errors.New("failed to genenrate key")
	}

	key := &KeyPair{
		Key:        [32]byte{},
		Commitment: [32]byte{},
	}

	b := C.GoBytes(unsafe.Pointer(buffer.ptr), C.int(buffer.len))

	copy(key.Key[:], b[:32])
	copy(key.Commitment[:], b[32:64])

	return key, nil
}

// Hash hashes a given input using the underlying function.
func (r *RLN) Hash(input []byte) ([]byte, error) {
	size := int(unsafe.Sizeof(C.Buffer{}))
	in := (*C.Buffer)(C.malloc(C.size_t(size)))
	*in = toBuffer(input)

	out := (*C.Buffer)(C.malloc(C.size_t(size)))
	if !bool(C.hash(r.ptr, in, in.len, out)) {
		return nil, errors.New("failed to hash")
	}

	return C.GoBytes(unsafe.Pointer(out.ptr), C.int(out.len)), nil
}

// GenerateProof generates a proof for the RLN given a KeyPair and the index in a merkle tree.
func (r *RLN) GenerateProof(input []byte, key *KeyPair, index uint) ([]byte, error) {
	inputBuf := toBuffer(input)

	var output []byte
	out := toBuffer(output)

	keybuf := toBuffer(key.Key[:])
	auth := &C.Auth{
		secret_buffer: &keybuf,
		index:         C.ulong(index),
	}

	if !bool(C.generate_proof(r.ptr, &inputBuf, auth, &out)) {
		return nil, errors.New("failed to generate proof")
	}

	return C.GoBytes(unsafe.Pointer(out.ptr), C.int(out.len)), nil
}

// Verify verifies a proof generated for the RLN.
func (r *RLN) Verify(proof []byte) bool {
	proofBuf := toBuffer(proof)

	result := uint32(0)
	res := C.uint(result)
	if !bool(C.verify(r.ptr, &proofBuf, &res)) {
		// @TODO THINK ABOUT ERROR?
		return false
	}

	return uint32(res) == 0
}

func (r *RLN) UpdateNextMember(input []byte) error {
	buf := toBuffer(input)
	if !bool(C.update_next_member(r.ptr, &buf)) {
		return errors.New("failed to update next member")
	}

	return nil
}

func (r *RLN) DeleteMember(index int) error {
	if !bool(C.delete_member(r.ptr, C.ulong(index))) {
		return errors.New("failed to delete member")
	}

	return nil
}

func (r *RLN) GetRoot() ([]byte, error) {
	var output []byte
	out := toBuffer(output)

	if !bool(C.get_root(r.ptr, &out)) {
		return nil, errors.New("failed to get root")
	}

	return C.GoBytes(unsafe.Pointer(out.ptr), C.int(out.len)), nil
}

func toBuffer(data []byte) C.Buffer {
	dataPtr, dataLen := sliceToPtr(data)
	return C.Buffer{
		ptr: dataPtr,
		len: C.ulong(dataLen),
	}
}

func sliceToPtr(slice []byte) (*C.uchar, C.int) {
	if len(slice) == 0 {
		return nil, 0
	} else {
		return (*C.uchar)(unsafe.Pointer(&slice[0])), C.int(len(slice))
	}
}
