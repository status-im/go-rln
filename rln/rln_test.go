package rln

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"

	"github.com/stretchr/testify/suite"
)

func TestWakuRLNRelaySuite(t *testing.T) {
	suite.Run(t, new(WakuRLNRelaySuite))
}

type WakuRLNRelaySuite struct {
	suite.Suite
}

// SetupTest is used here for reinitializing the mock before every
// test function to avoid faulty execution.
func (s *WakuRLNRelaySuite) SetupTest() {
}

func (s *WakuRLNRelaySuite) TearDownTest() {
	//
}

func (s *WakuRLNRelaySuite) TestMembershipKeyGen() {
	rln, err := NewRLNWithDepth(32)
	s.NoError(err)

	key, err := rln.MembershipKeyGen()
	s.NoError(err)
	s.Len(key.IDKey, 32)
	s.Len(key.IDCommitment, 32)
	s.NotEmpty(key.IDKey)
	s.NotEmpty(key.IDCommitment)
	s.False(bytes.Equal(key.IDCommitment[:], make([]byte, 32)))
	s.False(bytes.Equal(key.IDKey[:], make([]byte, 32)))
}

func (s *WakuRLNRelaySuite) TestGetMerkleRoot() {
	rln, err := NewRLNWithDepth(32)
	s.NoError(err)

	root1, err := rln.GetMerkleRoot()
	s.NoError(err)
	s.Len(root1, 32)

	root2, err := rln.GetMerkleRoot()
	s.NoError(err)
	s.Len(root2, 32)

	s.Equal(root1, root2)
}

func (s *WakuRLNRelaySuite) TestInsertMember() {
	rln, err := NewRLNWithDepth(32)
	s.NoError(err)

	keypair, err := rln.MembershipKeyGen()
	s.NoError(err)

	inserted := rln.InsertMember(keypair.IDCommitment)
	s.True(inserted)
}

func (s *WakuRLNRelaySuite) TestRemoveMember() {
	rln, err := NewRLNWithDepth(32)
	s.NoError(err)

	deleted := rln.DeleteMember(MembershipIndex(0))
	s.True(deleted)
}

func (s *WakuRLNRelaySuite) TestMerkleTreeConsistenceBetweenDeletionAndInsertion() {
	rln, err := NewRLNWithDepth(32)
	s.NoError(err)

	root1, err := rln.GetMerkleRoot()
	s.NoError(err)
	s.Len(root1, 32)

	keypair, err := rln.MembershipKeyGen()
	s.NoError(err)

	inserted := rln.InsertMember(keypair.IDCommitment)
	s.True(inserted)

	// read the Merkle Tree root after insertion
	root2, err := rln.GetMerkleRoot()
	s.NoError(err)
	s.Len(root2, 32)

	// delete the first member
	deleted_member_index := MembershipIndex(0)
	deleted := rln.DeleteMember(deleted_member_index)
	s.True(deleted)

	// read the Merkle Tree root after the deletion
	root3, err := rln.GetMerkleRoot()
	s.NoError(err)
	s.Len(root3, 32)

	// the root must change after the insertion
	s.NotEqual(root1, root2)

	// The initial root of the tree (empty tree) must be identical to
	// the root of the tree after one insertion followed by a deletion
	s.Equal(root1, root3)
}

func (s *WakuRLNRelaySuite) TestHash() {
	rln, err := NewRLNWithDepth(32)
	s.NoError(err)

	// prepare the input
	msg := []byte("Hello")

	hash, err := rln.Hash(msg)
	s.NoError(err)

	expectedHash, _ := hex.DecodeString("efb8ac39dc22eaf377fe85b405b99ba78dbc2f3f32494add4501741df946bd1d")
	s.Equal(expectedHash, hash[:])
}

func (s *WakuRLNRelaySuite) TestCreateListMembershipKeysAndCreateMerkleTreeFromList() {
	groupSize := 100
	list, root, err := createMembershipList(groupSize)
	s.NoError(err)
	s.Len(list, groupSize)
	s.Len(root, HASH_HEX_SIZE) // check the size of the calculated tree root
}

func (s *WakuRLNRelaySuite) TestCheckCorrectness() {
	groupKeys := STATIC_GROUP_KEYS

	// create a set of MembershipKeyPair objects from groupKeys
	groupKeyPairs, err := toMembershipKeyPairs(groupKeys)
	s.NoError(err)

	// extract the id commitments
	var groupIDCommitments []IDCommitment
	for _, c := range groupKeyPairs {
		groupIDCommitments = append(groupIDCommitments, c.IDCommitment)
	}

	// calculate the Merkle tree root out of the extracted id commitments
	root, err := CalcMerkleRoot(groupIDCommitments)
	s.NoError(err)

	expectedRoot, _ := hex.DecodeString(STATIC_GROUP_MERKLE_ROOT)

	s.Len(groupKeyPairs, STATIC_GROUP_SIZE)
	s.Equal(expectedRoot, root[:])
}

func (s *WakuRLNRelaySuite) TestValidProof() {
	rln, err := NewRLN()
	s.NoError(err)

	memKeys, err := rln.MembershipKeyGen()
	s.NoError(err)

	//peer's index in the Merkle Tree
	index := 5

	// Create a Merkle tree with random members
	for i := 0; i < 10; i++ {
		memberIsAdded := false
		if i == index {
			// insert the current peer's pk
			memberIsAdded = rln.InsertMember(memKeys.IDCommitment)
		} else {
			// create a new key pair
			memberKeys, err := rln.MembershipKeyGen()
			s.NoError(err)

			memberIsAdded = rln.InsertMember(memberKeys.IDCommitment)
		}
		s.True(memberIsAdded)
	}

	// prepare the message
	msg := []byte("Hello")

	// prepare the epoch
	var epoch Epoch

	// generate proof
	proofRes, err := rln.GenerateProof(msg, *memKeys, MembershipIndex(index), epoch)
	s.NoError(err)

	// verify the proof
	verified := rln.Verify(msg, *proofRes)

	s.True(verified)
}

func (s *WakuRLNRelaySuite) TestInvalidProof() {
	rln, err := NewRLN()
	s.NoError(err)

	memKeys, err := rln.MembershipKeyGen()
	s.NoError(err)

	//peer's index in the Merkle Tree
	index := 5

	// Create a Merkle tree with random members
	for i := 0; i < 10; i++ {
		memberIsAdded := false
		if i == index {
			// insert the current peer's pk
			memberIsAdded = rln.InsertMember(memKeys.IDCommitment)
		} else {
			// create a new key pair
			memberKeys, err := rln.MembershipKeyGen()
			s.NoError(err)

			memberIsAdded = rln.InsertMember(memberKeys.IDCommitment)
		}
		s.True(memberIsAdded)
	}

	// prepare the message
	msg := []byte("Hello")

	// prepare the epoch
	var epoch Epoch

	badIndex := 4

	// generate proof
	proofRes, err := rln.GenerateProof(msg, *memKeys, MembershipIndex(badIndex), epoch)
	s.NoError(err)

	// verify the proof (should not be verified)
	verified := rln.Verify(msg, *proofRes)

	s.False(verified)
}

func (s *WakuRLNRelaySuite) TestEpochConsistency() {
	// check edge cases
	var epoch uint64 = math.MaxUint64
	epochBytes := ToEpoch(epoch)
	decodedEpoch := epochBytes.Uint64()

	s.Equal(epoch, decodedEpoch)
}

func (s *WakuRLNRelaySuite) TestEpochComparison() {
	// check edge cases
	var time1 uint64 = math.MaxUint64
	var time2 uint64 = math.MaxUint64 - 1

	epoch1 := ToEpoch(time1)
	epoch2 := ToEpoch(time2)

	s.Equal(int64(1), Diff(epoch1, epoch2))
	s.Equal(int64(-1), Diff(epoch2, epoch1))
}
