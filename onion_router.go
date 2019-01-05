package sphinx

import (
	"crypto/ecdsa"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

// ProcessCode is an enum-like type which describes to the high-level package
// user which action should be taken after processing a Sphinx packet.
type ProcessCode int

const (
	// ExitNode indicates that the node which processed the Sphinx packet
	// is the destination hop in the route.
	ExitNode = iota

	// MoreHops indicates that there are additional hops left within the
	// route. Therefore the caller should forward the packet to the node
	// denoted as the "NextHop".
	MoreHops

	// Failure indicates that a failure occurred during packet processing.
	Failure
)

// String returns a human readable string for each of the ProcessCodes.
func (p ProcessCode) String() string {
	switch p {
	case ExitNode:
		return "ExitNode"
	case MoreHops:
		return "MoreHops"
	case Failure:
		return "Failure"
	default:
		return "Unknown"
	}
}

// ProcessedPacket encapsulates the resulting state generated after processing
// an OnionPacket. A processed packet communicates to the caller what action
// should be taken after processing.
type ProcessedPacket struct {
	// Action represents the action the caller should take after processing
	// the packet.
	Action ProcessCode

	// ForwardingInstructions is the per-hop payload recovered from the
	// initial encrypted onion packet. It details how the packet should be
	// forwarded and also includes information that allows the processor of
	// the packet to authenticate the information passed within the HTLC.
	//
	// NOTE: This field will only be populated iff the above Action is
	// MoreHops.
	ForwardingInstructions HopData

	// Extra contains any extra onion data that we were able to uncover
	// during packet unwrapping.
	ExtraData ExtraHopData

	// NextPacket is the onion packet that should be forwarded to the next
	// hop as denoted by the ForwardingInstructions field.
	//
	// NOTE: This field will only be populated iff the above Action is
	// MoreHops.
	NextPacket *OnionPacket
}

// Router is an onion router within the Sphinx network. The router is capable
// of processing incoming Sphinx onion packets thereby "peeling" a layer off
// the onion encryption which the packet is wrapped with.
type Router struct {
	nodeID   [AddressSize]byte
	nodeAddr *btcutil.AddressPubKeyHash

	onionKey *btcec.PrivateKey

	log ReplayLog
}

// NewRouter creates a new instance of a Sphinx onion Router given the node's
// currently advertised onion private key, and the target Bitcoin network.
func NewRouter(nodeKey *btcec.PrivateKey, net *chaincfg.Params, log ReplayLog) *Router {
	var nodeID [AddressSize]byte
	copy(nodeID[:], btcutil.Hash160(nodeKey.PubKey().SerializeCompressed()))

	// Safe to ignore the error here, nodeID is 20 bytes.
	nodeAddr, _ := btcutil.NewAddressPubKeyHash(nodeID[:], net)

	return &Router{
		nodeID:   nodeID,
		nodeAddr: nodeAddr,
		onionKey: &btcec.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: btcec.S256(),
				X:     nodeKey.X,
				Y:     nodeKey.Y,
			},
			D: nodeKey.D,
		},
		log: log,
	}
}

// Start starts / opens the ReplayLog's channeldb and its accompanying
// garbage collector goroutine.
func (r *Router) Start() error {
	return r.log.Start()
}

// Stop stops / closes the ReplayLog's channeldb and its accompanying
// garbage collector goroutine.
func (r *Router) Stop() {
	r.log.Stop()
}

// ProcessOnionPacket processes an incoming onion packet which has been forward
// to the target Sphinx router. If the encoded ephemeral key isn't on the
// target Elliptic Curve, then the packet is rejected. Similarly, if the
// derived shared secret has been seen before the packet is rejected.  Finally
// if the MAC doesn't check the packet is again rejected.
//
// In the case of a successful packet processing, and ProcessedPacket struct is
// returned which houses the newly parsed packet, along with instructions on
// what to do next.
func (r *Router) ProcessOnionPacket(onionPkt *OnionPacket,
	assocData []byte, incomingCltv uint32) (*ProcessedPacket, error) {

	// Compute the shared secret for this onion packet.
	sharedSecret, err := r.generateSharedSecret(onionPkt.EphemeralKey)
	if err != nil {
		return nil, err
	}

	// Additionally, compute the hash prefix of the shared secret, which
	// will serve as an identifier for detecting replayed packets.
	hashPrefix := hashSharedSecret(&sharedSecret)

	// Continue to optimistically process this packet, deferring replay
	// protection until the end to reduce the penalty of multiple IO
	// operations.
	packet, err := processOnionPacket(onionPkt, &sharedSecret, assocData, r)
	if err != nil {
		return nil, err
	}

	// Atomically compare this hash prefix with the contents of the on-disk
	// log, persisting it only if this entry was not detected as a replay.
	if err := r.log.Put(hashPrefix, incomingCltv); err != nil {
		return nil, err
	}

	return packet, nil
}

// ReconstructOnionPacket rederives the subsequent onion packet.
//
// NOTE: This method does not do any sort of replay protection, and should only
// be used to reconstruct packets that were successfully processed previously.
func (r *Router) ReconstructOnionPacket(onionPkt *OnionPacket,
	assocData []byte) (*ProcessedPacket, error) {

	// Compute the shared secret for this onion packet.
	sharedSecret, err := r.generateSharedSecret(onionPkt.EphemeralKey)
	if err != nil {
		return nil, err
	}

	return processOnionPacket(onionPkt, &sharedSecret, assocData, r)
}

// Tx is a transaction consisting of a number of sphinx packets to be atomically
// written to the replay log. This structure helps to coordinate construction of
// the underlying Batch object, and to ensure that the result of the processing
// is idempotent.
type Tx struct {
	// batch is the set of packets to be incrementally processed and
	// ultimately committed in this transaction
	batch *Batch

	// router is a reference to the sphinx router that created this
	// transaction. Committing this transaction will utilize this router's
	// replay log.
	router *Router

	// packets contains a potentially sparse list of optimistically processed
	// packets for this batch. The contents of a particular index should
	// only be accessed if the index is *not* included in the replay set, or
	// otherwise failed any other stage of the processing.
	packets []ProcessedPacket
}

// BeginTxn creates a new transaction that can later be committed back to the
// sphinx router's replay log.
//
// NOTE: The nels parameter should represent the maximum number of that could
// be added to the batch, using sequence numbers that match or exceed this
// value could result in an out-of-bounds panic.
func (r *Router) BeginTxn(id []byte, nels int) *Tx {
	return &Tx{
		batch:   NewBatch(id),
		router:  r,
		packets: make([]ProcessedPacket, nels),
	}
}

// ProcessOnionPacket processes an incoming onion packet which has been forward
// to the target Sphinx router. If the encoded ephemeral key isn't on the
// target Elliptic Curve, then the packet is rejected. Similarly, if the
// derived shared secret has been seen before the packet is rejected.  Finally
// if the MAC doesn't check the packet is again rejected.
//
// In the case of a successful packet processing, and ProcessedPacket struct is
// returned which houses the newly parsed packet, along with instructions on
// what to do next.
func (t *Tx) ProcessOnionPacket(seqNum uint16, onionPkt *OnionPacket,
	assocData []byte, incomingCltv uint32) error {

	// Compute the shared secret for this onion packet.
	sharedSecret, err := t.router.generateSharedSecret(
		onionPkt.EphemeralKey,
	)
	if err != nil {
		return err
	}

	// Additionally, compute the hash prefix of the shared secret, which
	// will serve as an identifier for detecting replayed packets.
	hashPrefix := hashSharedSecret(&sharedSecret)

	// Continue to optimistically process this packet, deferring replay
	// protection until the end to reduce the penalty of multiple IO
	// operations.
	packet, err := processOnionPacket(
		onionPkt, &sharedSecret, assocData, t.router,
	)
	if err != nil {
		return err
	}

	// Add the hash prefix to pending batch of shared secrets that will be
	// written later via Commit().
	err = t.batch.Put(seqNum, hashPrefix, incomingCltv)
	if err != nil {
		return err
	}

	// If we successfully added this packet to the batch, cache the
	// processed packet within the Tx which can be accessed after
	// committing if this sequence number does not appear in the replay
	// set.
	t.packets[seqNum] = *packet

	return nil
}

// Commit writes this transaction's batch of sphinx packets to the replay log,
// performing a final check against the log for replays.
func (t *Tx) Commit() ([]ProcessedPacket, *ReplaySet, error) {
	if t.batch.IsCommitted {
		return t.packets, t.batch.ReplaySet, nil
	}

	rs, err := t.router.log.PutBatch(t.batch)

	return t.packets, rs, err
}
