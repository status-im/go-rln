// Package rln contains bindings for https://github.com/kilic/rln
package rln

/*
#include "./librln.h"
*/
import "C"
import (
	"encoding/binary"
	"errors"
	"io/ioutil"
	"unsafe"

	"github.com/decanus/go-rln/rln/pb"
)

// RLN represents the context used for rln.
type RLN struct {
	ptr *C.RLN_Bn256
}

// New returns a new RLN generated using the default merkle tree depth
func NewRLN() (*RLN, error) {
	return NewRLNWithDepth(MERKLE_TREE_DEPTH)
}

// NewRLNWithDepth generates an instance of RLN. An instance supports both zkSNARKs logics
// and Merkle tree data structure and operations. The parameter `depth`` indicates the depth of Merkle tree
func NewRLNWithDepth(depth int) (*RLN, error) {
	r := &RLN{}

	// parameters.key contains the prover and verifier keys
	// to generate this file, clone this repo https://github.com/kilic/rln
	// and run the following command in the root directory of the cloned project
	// cargo run --example export_test_keys
	// the file is generated separately and copied here
	// parameters are function of tree depth and poseidon hasher
	// to generate parameters for a different tree depth, change the tree size in the following line of rln library
	// https://github.com/kilic/rln/blob/3bbec368a4adc68cd5f9bfae80b17e1bbb4ef373/examples/export_test_keys/main.rs#L4
	// and then proceed as explained above
	params, err := ioutil.ReadFile("./testdata/parameters.key")
	if err != nil {
		return nil, err
	}

	if len(params) == 0 {
		return nil, errors.New("error in parameters.key")
	}

	buf := toBuffer(params)

	size := int(unsafe.Sizeof(buf))
	in := (*C.Buffer)(C.malloc(C.size_t(size)))
	*in = buf

	if !bool(C.new_circuit_from_params(C.ulong(depth), in, &r.ptr)) {
		return nil, errors.New("failed to initialize")
	}

	return r, nil
}

// MembershipKeyGen generates a MembershipKeyPair that can be used for the registration into the rln membership contract
func (r *RLN) MembershipKeyGen() (*MembershipKeyPair, error) {
	buffer := toBuffer([]byte{})
	if !bool(C.key_gen(r.ptr, &buffer)) {
		return nil, errors.New("error in key generation")
	}

	key := &MembershipKeyPair{
		IDKey:        [32]byte{},
		IDCommitment: [32]byte{},
	}

	// the public and secret keys together are 64 bytes
	generatedKeys := C.GoBytes(unsafe.Pointer(buffer.ptr), C.int(buffer.len))
	if len(generatedKeys) != 64 {
		return nil, errors.New("the generated keys are invalid")
	}

	copy(key.IDKey[:], generatedKeys[:32])
	copy(key.IDCommitment[:], generatedKeys[32:64])

	return key, nil
}

// appendLength returns length prefixed version of the input with the following format
// [len<8>|input<var>], the len is a 8 byte value serialized in little endian
func appendLength(input []byte) []byte {
	inputLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(inputLen, uint64(len(input)))
	return append(inputLen, input...)
}

// toBuffer converts the input to a buffer object that is used to communicate data with the rln lib
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

// Hash hashes the plain text supplied in inputs_buffer and then maps it to a field element
// this proc is used to map arbitrary signals to field element for the sake of proof generation
// inputs holds the hash input as a byte slice, the output slice will contain a 32 byte slice
func (r *RLN) Hash(data []byte) (MerkleNode, error) {
	//  a thin layer on top of the Nim wrapper of the Poseidon hasher
	lenPrefData := appendLength(data)

	hashInputBuffer := toBuffer(lenPrefData)
	size := int(unsafe.Sizeof(hashInputBuffer))
	in := (*C.Buffer)(C.malloc(C.size_t(size)))
	*in = hashInputBuffer

	var output []byte
	out := toBuffer(output)

	if !bool(C.signal_to_field(r.ptr, in, &out)) {
		return MerkleNode{}, errors.New("failed to hash")
	}

	b := C.GoBytes(unsafe.Pointer(out.ptr), C.int(out.len))

	var result MerkleNode
	copy(result[:], b)

	return result, nil
}

// GenerateProof generates a proof for the RLN given a KeyPair and the index in a merkle tree.
// The output will containt the proof data and should be parsed as |proof<256>|root<32>|epoch<32>|share_x<32>|share_y<32>|nullifier<32>|
// integers wrapped in <> indicate value sizes in bytes
func (r *RLN) GenerateProof(data []byte, key MembershipKeyPair, index MembershipIndex, epoch Epoch) (*RateLimitProof, error) {
	input := serialize(key.IDKey, index, epoch, data)
	inputBuf := toBuffer(input)
	size := int(unsafe.Sizeof(inputBuf))
	in := (*C.Buffer)(C.malloc(C.size_t(size)))
	*in = inputBuf

	var output []byte
	out := toBuffer(output)

	if !bool(C.generate_proof(r.ptr, in, &out)) {
		return nil, errors.New("could not generate the proof")
	}

	proofBytes := C.GoBytes(unsafe.Pointer(out.ptr), C.int(out.len))

	if len(proofBytes) != 416 {
		return nil, errors.New("invalid proof generated")
	}

	// parse the proof as |zkSNARKs<256>|root<32>|epoch<32>|share_x<32>|share_y<32>|nullifier<32>|

	proofOffset := 256
	rootOffset := proofOffset + 32
	epochOffset := rootOffset + 32
	shareXOffset := epochOffset + 32
	shareYOffset := shareXOffset + 32
	nullifierOffset := shareYOffset + 32

	var zkproof ZKSNARK
	var proofRoot, shareX, shareY MerkleNode
	var epochR Epoch
	var nullifier Nullifier

	copy(zkproof[:], proofBytes[0:proofOffset])
	copy(proofRoot[:], proofBytes[proofOffset:rootOffset])
	copy(epochR[:], proofBytes[rootOffset:epochOffset])
	copy(shareX[:], proofBytes[epochOffset:shareXOffset])
	copy(shareY[:], proofBytes[shareXOffset:shareYOffset])
	copy(nullifier[:], proofBytes[shareYOffset:nullifierOffset])

	return &RateLimitProof{
		Proof:      zkproof,
		MerkleRoot: proofRoot,
		Epoch:      epochR,
		ShareX:     shareX,
		ShareY:     shareY,
		Nullifier:  nullifier,
	}, nil
}

// Verify verifies a proof generated for the RLN.
// proof [ proof<256>| root<32>| epoch<32>| share_x<32>| share_y<32>| nullifier<32> | signal_len<8> | signal<var> ]
func (r *RLN) Verify(data []byte, proof RateLimitProof) bool {
	proofBytes := proof.serialize(data)
	proofBuf := toBuffer(proofBytes)
	size := int(unsafe.Sizeof(proofBuf))
	in := (*C.Buffer)(C.malloc(C.size_t(size)))
	*in = proofBuf

	result := uint32(0)
	res := C.uint(result)
	if !bool(C.verify(r.ptr, in, &res)) {
		return false
	}

	return uint32(res) == 0
}

// InsertMember adds the member to the tree
func (r *RLN) InsertMember(idComm IDCommitment) bool {
	buf := toBuffer(idComm[:])

	size := int(unsafe.Sizeof(buf))
	in := (*C.Buffer)(C.malloc(C.size_t(size)))
	*in = buf

	res := C.update_next_member(r.ptr, in)
	return bool(res)
}

// index is the position of the id commitment key to be deleted from the tree
// the deleted id commitment key is replaced with a zero leaf
func (r *RLN) DeleteMember(index MembershipIndex) bool {
	deletionSuccess := bool(C.delete_member(r.ptr, C.ulong(index)))
	return deletionSuccess
}

// GetMerkleRoot reads the Merkle Tree root after insertion
func (r *RLN) GetMerkleRoot() (MerkleNode, error) {
	var output []byte
	out := toBuffer(output)

	if !bool(C.get_root(r.ptr, &out)) {
		return MerkleNode{}, errors.New("could not get the root")
	}

	b := C.GoBytes(unsafe.Pointer(out.ptr), C.int(out.len))

	if len(b) != 32 {
		return MerkleNode{}, errors.New("wrong output size")
	}

	var result MerkleNode
	copy(result[:], b)

	return result, nil
}

// AddAll adds members to the Merkle tree
func (r *RLN) AddAll(list []IDCommitment) bool {
	for _, member := range list {
		if !r.InsertMember(member) {
			return false
		}
	}
	return true
}

func ToRLNSignal(wakuMessage *pb.WakuMessage) []byte {
	if wakuMessage == nil {
		return []byte{}
	}

	contentTopicBytes := []byte(wakuMessage.ContentTopic)
	return append(wakuMessage.Payload, contentTopicBytes...)
}
