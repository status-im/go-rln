package rln

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"

	"github.com/decanus/go-rln/rln/pb"
)

type WakuRLNRelay struct {
	MembershipKeyPair MembershipKeyPair
	// membershipIndex denotes the index of a leaf in the Merkle tree
	// that contains the pk of the current peer
	// this index is used to retrieve the peer's authentication path
	MembershipIndex MembershipIndex
	// MembershipContractAddress*: Address
	//ethClientAddress*: string
	//ethAccountAddress*: Address
	// this field is required for signing transactions
	// TODO may need to erase this ethAccountPrivateKey when is not used
	// TODO may need to make ethAccountPrivateKey mandatory
	//ethAccountPrivateKey*: PrivateKey
	RLNInstance *RLN
	// the pubsub topic for which rln relay is mounted
	PubsubTopic string
	// contentTopic should be of type waku_message.ContentTopic, however, due to recursive module dependency, the underlying type of ContentTopic is used instead
	// TODO a long-term solution is to place types with recursive dependency inside one file
	ContentTopic string
	// the log of nullifiers and Shamir shares of the past messages grouped per epoch
	NullifierLog map[Epoch][]ProofMetadata
}

func CalcMerkleRoot(list []IDCommitment) (MerkleNode, error) {
	// returns the root of the Merkle tree that is computed from the supplied list

	rln, err := NewRLN()
	if err != nil {
		return MerkleNode{}, err
	}

	// create a Merkle tree
	for _, c := range list {
		if !rln.InsertMember(c) {
			return MerkleNode{}, errors.New("could not add member")
		}
	}

	return rln.GetMerkleRoot()
}

func createMembershipList(n int) ([][]string, string, error) {
	// createMembershipList produces a sequence of membership key pairs in the form of (identity key, id commitment keys) in the hexadecimal format
	// this proc also returns the root of a Merkle tree constructed out of the identity commitment keys of the generated list
	// the output of this proc is used to initialize a static group keys (to test waku-rln-relay in the off-chain mode)

	// initialize a Merkle tree
	rln, err := NewRLN()
	if err != nil {
		return nil, "", err
	}

	var output [][]string
	for i := 0; i < n; i++ {
		// generate a keypair
		keypair, err := rln.MembershipKeyGen()
		if err != nil {
			return nil, "", err
		}

		output = append(output, []string{hex.EncodeToString(keypair.IDKey[:]), hex.EncodeToString(keypair.IDCommitment[:])})

		// insert the key to the Merkle tree
		if !rln.InsertMember(keypair.IDCommitment) {
			return nil, "", errors.New("could not insert member")
		}
	}

	root, err := rln.GetMerkleRoot()
	if err != nil {
		return nil, "", err
	}

	return output, hex.EncodeToString(root[:]), nil
}

func RLNRelayStaticSetUp(rlnRelayMemIndex MembershipIndex) ([]IDCommitment, MembershipKeyPair, MembershipIndex, error) {
	// static group
	groupKeys := STATIC_GROUP_KEYS
	groupSize := STATIC_GROUP_SIZE

	// validate the user-supplied membership index
	if rlnRelayMemIndex < MembershipIndex(0) || rlnRelayMemIndex >= MembershipIndex(groupSize) {
		return nil, MembershipKeyPair{}, 0, errors.New("wrong membership index")
	}

	// prepare the outputs from the static group keys

	// create a sequence of MembershipKeyPairs from the group keys (group keys are in string format)
	groupKeyPairs, err := toMembershipKeyPairs(groupKeys)
	if err != nil {
		return nil, MembershipKeyPair{}, 0, errors.New("invalid data on group keypairs")
	}

	// extract id commitment keys
	var groupOpt []IDCommitment
	for _, c := range groupKeyPairs {
		groupOpt = append(groupOpt, c.IDCommitment)
	}

	//  user selected membership key pair
	memKeyPairOpt := groupKeyPairs[rlnRelayMemIndex]
	memIndexOpt := rlnRelayMemIndex

	return groupOpt, memKeyPairOpt, memIndexOpt, nil
}

func (rln *WakuRLNRelay) HasDuplicate(msg *pb.WakuMessage) (bool, error) {
	// returns true if there is another message in the  `nullifierLog` of the `rlnPeer` with the same
	// epoch and nullifier as `msg`'s epoch and nullifier but different Shamir secret shares
	// otherwise, returns false

	if msg == nil {
		return false, errors.New("nil message")
	}

	msgProof := ToRateLimitProof(msg)

	// extract the proof metadata of the supplied `msg`
	proofMD := ProofMetadata{
		Nullifier: msgProof.Nullifier,
		ShareX:    msgProof.ShareX,
		ShareY:    msgProof.ShareY,
	}

	proofs, ok := rln.NullifierLog[msgProof.Epoch]

	// check if the epoch exists
	if !ok {
		return false, nil
	}

	for _, p := range proofs {
		if p.Equals(proofMD) {
			// there is an identical record, ignore rhe mag
			return false, nil
		}
	}

	// check for a message with the same nullifier but different secret shares
	matched := false
	for _, it := range proofs {
		if bytes.Equal(it.Nullifier[:], proofMD.Nullifier[:]) && (!bytes.Equal(it.ShareX[:], proofMD.ShareX[:]) || !bytes.Equal(it.ShareY[:], proofMD.ShareY[:])) {
			matched = true
			break
		}
	}

	return matched, nil
}

func (rln *WakuRLNRelay) UpdateLog(msg *pb.WakuMessage) (bool, error) {
	// extracts  the `ProofMetadata` of the supplied messages `msg` and
	// saves it in the `nullifierLog` of the `rlnPeer`

	if msg == nil {
		return false, errors.New("nil message")
	}

	msgProof := ToRateLimitProof(msg)

	proofMD := ProofMetadata{
		Nullifier: msgProof.Nullifier,
		ShareX:    msgProof.ShareX,
		ShareY:    msgProof.ShareY,
	}

	proofs, ok := rln.NullifierLog[msgProof.Epoch]

	// check if the epoch exists
	if !ok {
		rln.NullifierLog[msgProof.Epoch] = []ProofMetadata{proofMD}
		return true, nil
	}

	// check if an identical record exists
	for _, p := range proofs {
		if p.Equals(proofMD) {
			return true, nil
		}
	}

	// add proofMD to the log
	proofs = append(proofs, proofMD)
	rln.NullifierLog[msgProof.Epoch] = proofs

	return true, nil
}

// TODO: change optionalTime data type
func (rln *WakuRLNRelay) ValidateMessage(msg *pb.WakuMessage, optionalTime float64) (MessageValidationResult, error) {
	// validate the supplied `msg` based on the waku-rln-relay routing protocol i.e.,
	// the `msg`'s epoch is within MAX_EPOCH_GAP of the current epoch
	// the `msg` has valid rate limit proof
	// the `msg` does not violate the rate limit
	// `timeOption` indicates Unix epoch time (fractional part holds sub-seconds)
	// if `timeOption` is supplied, then the current epoch is calculated based on that

	if msg == nil {
		return MessageValidationResult_Unknown, errors.New("nil message")
	}

	//  checks if the `msg`'s epoch is far from the current epoch
	// it corresponds to the validation of rln external nullifier
	var epoch Epoch
	if optionalTime != 0 {
		epoch = CalcEpoch(optionalTime)
	} else {
		// get current rln epoch
		epoch = GetCurrentEpoch()
	}

	msgProof := ToRateLimitProof(msg)

	// calculate the gaps
	gap := Diff(epoch, msgProof.Epoch)

	// validate the epoch
	if int64(math.Abs(float64(gap))) >= MAX_EPOCH_GAP {
		// message's epoch is too old or too ahead
		// accept messages whose epoch is within +-MAX_EPOCH_GAP from the current epoch
		//debug "invalid message: epoch gap exceeds a threshold", gap = gap, payload = string.fromBytes(msg.payload)
		return MessageValidationResult_Invalid, nil
	}

	// verify the proof
	contentTopicBytes := []byte(msg.ContentTopic)
	input := append(msg.Payload, contentTopicBytes...)
	if !rln.RLNInstance.Verify(input, *msgProof) {
		// invalid proof
		//debug "invalid message: invalid proof", payload = string.fromBytes(msg.payload)
		return MessageValidationResult_Invalid, nil
	}

	// check if double messaging has happened
	hasDup, err := rln.HasDuplicate(msg)
	if err != nil {
		return MessageValidationResult_Unknown, err
	}

	if hasDup {
		// debug "invalid message: message is a spam", payload = string.fromBytes(msg.payload)
		return MessageValidationResult_Spam, nil
	}

	// insert the message to the log
	// the result of `updateLog` is discarded because message insertion is guaranteed by the implementation i.e.,
	// it will never error out
	_, err = rln.UpdateLog(msg)
	if err != nil {
		return MessageValidationResult_Unknown, err
	}

	//debug "message is valid", payload = string.fromBytes(msg.payload)
	return MessageValidationResult_Valid, nil
}

// TODO: change senderEpochTIme datatype
func (rln *WakuRLNRelay) AppendRLNProof(msg *pb.WakuMessage, senderEpochTime float64) error {
	// returns error if it could not create and append a `RateLimitProof` to the supplied `msg`
	// `senderEpochTime` indicates the number of seconds passed since Unix epoch. The fractional part holds sub-seconds.
	// The `epoch` field of `RateLimitProof` is derived from the provided `senderEpochTime` (using `calcEpoch()`)

	if msg == nil {
		return errors.New("nil message")
	}

	input := ToRLNSignal(msg)

	proof, err := rln.RLNInstance.GenerateProof(input, rln.MembershipKeyPair, rln.MembershipIndex, CalcEpoch(senderEpochTime))
	if err != nil {
		return err
	}

	msg.RateLimitProof = &pb.RateLimitProof{
		Proof:      proof.Proof[:],
		MerkleRoot: proof.MerkleRoot[:],
		Epoch:      proof.Epoch[:],
		ShareX:     proof.ShareX[:],
		ShareY:     proof.ShareY[:],
		Nullifier:  proof.Nullifier[:],
	}

	return nil
}
