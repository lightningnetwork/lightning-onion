package sphinx

import (
	"bytes"
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

// processOnionPacket performs the primary key derivation and handling of onion
// packets. The processed packets returned from this method should only be used
// if the packet was not flagged as a replayed packet.
func processOnionPacket(onionPkt *OnionPacket, sharedSecret *Hash256,
	assocData []byte,
	sharedSecretGen sharedSecretGenerator) (*ProcessedPacket, error) {

	// First, we'll unwrap an initial layer of the onion packet. Typically,
	// we'll only have a single layer to unwrap, However, if the sender has
	// additional data for us within the Extra Onion Blobs (EOBs), then we
	// may have to unwrap additional layers.  By default, the inner most
	// mix header is the one that we'll want to pass onto the next hop so
	// they can properly check the HMAC and unwrap a layer for their
	// handoff hop.
	innerPkt, outerHopData, err := unwrapPacket(
		onionPkt, sharedSecret, assocData,
	)
	if err != nil {
		return nil, err
	}

	var (
		// innerHopData is the hop data of any inner onion packets we
		// may or may not need to unwrap. We only pass the outer hop
		// data to the next hop, so this will only be used for
		// unpacking EOBs.
		innerHopData *HopData = outerHopData

		// eob will house the data for any EOBs that we uncover while
		// we unwrap packets.
		eob ExtraHopData
	)

	// If this outer most hop data has a non-empty type, then that means we
	// at least need to read the pivot hop bytes and store the EOB type
	// within the EOB struct.
	if outerHopData.ExtraOnionBlobType() != EOBEmpty {
		if err := eob.UnpackPivotHop(outerHopData); err != nil {
			return nil, err
		}
	}

	// If this hop has any unrolled additional data within extra onion
	// blobs, then we'll need to continue unwrapping the packet in order to
	// fully unpack all the encoded EOBs.
	for hopsConsumed := 0; innerHopData.HasMoreEOBs(hopsConsumed == 0); hopsConsumed++ {
		// We'll now construct a special inner EOB onion packet. This
		// will have the same version as the outer packet, but use the
		// DH key, routing info of the unwrapped inner packet (which
		// usually goes straight to the next hop), and the HMAC within
		// our hop data (which usually has no more use as its only for
		// us to check the integrity of the next onion packet).
		eobPkt := &OnionPacket{
			Version:      onionPkt.Version,
			EphemeralKey: innerPkt.EphemeralKey,
			RoutingInfo:  innerPkt.RoutingInfo,
			HeaderMAC:    innerHopData.HMAC,
		}

		// With the onion packet constructed, we'll generate the shared
		// secret we're to use for the next hop, and then unwrap
		// another layer of the onion in order to obtain the inner
		// packet and the inner hop data we'll extract out EOB fragment
		// from.
		nextSharedSecret, err := sharedSecretGen.generateSharedSecret(
			eobPkt.EphemeralKey,
		)
		if err != nil {
			return nil, err
		}
		innerPkt, innerHopData, err = unwrapPacket(
			eobPkt, &nextSharedSecret, assocData,
		)
		if err != nil {
			return nil, err
		}

		// With another layer unwrapped, we'll now accumulate a full
		// EOB fragment.
		if err := eob.UnpackFullHop(innerHopData); err != nil {
			return nil, err
		}
	}

	// By default we'll assume that there are additional hops in the route.
	// However if the uncovered 'nextMac' is all zeroes, then this
	// indicates that we're the final hop in the route.
	var action ProcessCode = MoreHops
	if bytes.Compare(zeroHMAC[:], innerHopData.HMAC[:]) == 0 {
		action = ExitNode
	}

	// Finally, we'll return a fully processed packet with the outer most
	// hop data (where the primary forwarding instructions lie) and the
	// inner most onion packet that we unwrapped.
	return &ProcessedPacket{
		Action:                 action,
		ForwardingInstructions: *outerHopData,
		NextPacket:             innerPkt,
		ExtraData:              eob,
	}, nil
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
