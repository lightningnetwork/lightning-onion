package sphinx

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
)

const (
	// NumMaxHops is the maximum path length. This should be set to an
	// estimate of the upper limit of the diameter of the node graph.
	NumMaxHops = 20
)

// PaymentPath represents a series of hops within the Lightning Network
// starting at a sender and terminating at a receiver. Each hop contains a set
// of mandatory data which contains forwarding instructions for that hop.
// Additionally, we can also transmit additional data to each hop by utilizing
// the un-used hops (see TrueRouteLength()) to pack in additional data. In
// order to do this, we encrypt the several hops with the same node public key,
// and unroll the extra data into the space used for route forwarding
// information.
type PaymentPath [NumMaxHops]OnionHop

// OnionHop represents an abstract hop (a link between two nodes) within the
// Lightning Network. A hop is composed of the incoming node (able to decrypt
// the encrypted routing information), and the routing information itself.
// Optionally, the crafter of a route can indicate that additional data aside
// from the routing information is be delivered, which will manifest as
// additional hops to pack the data.
type OnionHop struct {
	// NodePub is the target node for this hop. The payload will enter this
	// hop, it'll decrypt the routing information, and hand off the
	// internal packet to the next hop.
	NodePub btcec.PublicKey

	// HopData are the plaintext routing instructions that should be
	// delivered to this hop.
	HopData HopData

	// ExtraData is an optional additional piece of data that's to be
	// delivered to this hop. If this is more than 10 bytes, then
	// additional hops will be consumed to fully pack the data.
	ExtraData ExtraHopData
}

// IsEmpty returns true if the hop isn't populated.
func (o OnionHop) IsEmpty() bool {
	return o.NodePub.X == nil || o.NodePub.Y == nil
}

// ValidatePayloadSanity validates that if any of the hops contains extra data,
// then the extra data can properly be unrolled into additional hops factoring
// in the max hop length, and also the total amount of extra data we can encode
// for a node, while respecting the source and destination requirements.
func (p *PaymentPath) ValidatePayloadSanity() error {
	// First, we'll tally up the cumulative size of all the raw extra data
	// bytes for each hop.
	numTotalBytes := p.TotalExtraDataSize()

	// Ensure that the total number of bytes isn't larger than the actual
	// number of bytes we can encode into a single Sphinx packet.
	if numTotalBytes > MaxExtraOnionBlob {
		return fmt.Errorf("unable to pack %v bytes in EOBs, max "+
			"number of bytes is %v", numTotalBytes,
			MaxExtraOnionBlob)
	}

	return nil
}

// TotalExtraDataSize is the sum of all EOB fragments to be encoded within the
// route. Note that this is the raw unrolled data size, and actual number of
// bytes consumed will grow due to signalling overhead.
func (p *PaymentPath) TotalExtraDataSize() uint32 {
	var numTotalBytes uint32
	for _, hop := range p {
		numTotalBytes += uint32(len(hop.ExtraData.ExtraOnionBlob))
	}

	return numTotalBytes
}

// NodeKeys returns a slice pointing to node keys that this route comprises of.
// The size of the returned slice will be TrueRouteLength().
func (p *PaymentPath) NodeKeys() []*btcec.PublicKey {

	var nodeKeys [NumMaxHops]*btcec.PublicKey

	routeLen := p.TrueRouteLength()
	for i := 0; i < routeLen; i++ {
		nodeKeys[i] = &p[i].NodePub
	}

	return nodeKeys[:routeLen]
}

// TrueRouteLength returns the "true" length of the PaymentPath. The max
// payment path is NumMaxHops size, but in practice routes are much smaller.
// This method will return the number of actual hops (nodes) involved in this
// route. For references, a direct path has a length of 1, path through an
// intermediate node has a length of 2 (3 nodes involved).
func (p *PaymentPath) TrueRouteLength() int {
	var routeLength int
	for _, hop := range p {
		// When we hit the first empty hop, we know we're now in the
		// zero'd out portion of the may array.
		if hop.IsEmpty() {
			return routeLength
		}

		routeLength++
	}

	return routeLength
}

// HasExtraData returns true if the hop has extra data or not. If the hop has
// extra data, then it should be unrolled before constructing the Sphinx packet
// to ensure the extra data is packed properly within the regular routing hop
// infos.
func (p *PaymentPath) HasExtraData() bool {
	for _, hop := range p {
		// If any of the hops has extra data, then we say that the
		// entire route does.
		if len(hop.ExtraData.ExtraOnionBlob) != 0 {
			return true
		}
	}

	return false
}

// UnrollExtraDataHops maps a regular PaymentPath with non-empty ExtraOnionBlob
// fields, into an "unrolled" PaymentPath which will encode the specified
// ExtraOnionBlob at each hop, into the regular HopData. As a result, if a path
// has EOBs, then unrolled path will be larger than the rolled path as it needs
// to consume additional hops to signal the EOBs and also pack each of the
// fragments.
//
// TODO(roasbeef): should actually be a diff type?
func (p *PaymentPath) UnrollExtraDataHops() (*PaymentPath, error) {
	var (
		// We'll keep track of both the number of bytes packed, and
		// also the total number of bytes we *should* pack so we can
		// carry out sanity checks below.
		totalBytesToPack = p.TotalExtraDataSize()

		numBytesPacked uint32

		unrolledPath PaymentPath
	)

	// We'll always perform NumMaxHops interactions in order to fully copy
	// over the original path to the unrolled path, At each hop we'll copy
	// over the original one, then maybe pack a series of EOB fragments.
	//
	// The unrolled hop pointer is our "slow" pointer, it always points to
	// the next unique hop (a different) node in the original path we move
	// it forward once each iteration. The hopIndex is our "fast" pointer,
	// we move it once at each iteration, but then it can also be
	// incremented multiple times in order to fill virtual hops to encode
	// any EOB data at that hop.
	var unrolledHopPointer, hopIndex uint32
	for ; hopIndex < NumMaxHops; hopIndex, unrolledHopPointer = hopIndex+1, unrolledHopPointer+1 {
		// Copy over the contents of this hop
		hop := p[unrolledHopPointer]
		unrolledPath[hopIndex] = hop

		// If this hop doesn't have any extra data, then we can copy if
		// over as is, as the hop won't expand at all.
		if len(hop.ExtraData.ExtraOnionBlob) == 0 {
			continue
		}

		// Otherwise, we'll need to expand this hop into the EOB of one
		// or more hops following this one. Minimally, we consume two
		// extra hops.
		eobPacker := hop.ExtraData.Packer()

		// We'll now use this hop to encode the minimal amount of bytes
		// we can, and also signal this as a "pivot" hop, along an
		// identifier to signal the type of this hop.
		bytesPacked, err := eobPacker.PackPivotHop(
			&unrolledPath[hopIndex].HopData,
		)
		if err != nil {
			return nil, err
		}

		// Next, Accumulate the total number of bytes packed above.
		numBytesPacked += uint32(bytesPacked)

		// If at this point, we've already fully packed this hop as it
		// only needs the bytes of the pivot hop, then we can continue
		// to unroll the next hop.
		if eobPacker.FullyPacked() {
			continue
		}

		// Now that we know we need to pack more hops, we'll increment
		// out pointer to the next full hop to pack.
		hopIndex++

		hopPub := hop.NodePub

		// Now that we've packed the first hop, we'll walk forward
		// unrolling the rest of the EOB into the subsequent hops until
		// we've either packed all the data, or run out of hops to use.
		for hopIndex < NumMaxHops {
			// Copy over the same public key as the pivot hop so
			// this node will be able to decrypt this payload as
			// well.
			unrolledPath[hopIndex].NodePub = hopPub

			// Now that we're past the pivot hop, we'll encode a
			// full hop allowing us use most of the regular hop
			// data fields, leaving room to signal the more byte.
			bytesPacked, err := eobPacker.PackFullHop(
				&unrolledPath[hopIndex].HopData,
			)
			if err != nil {
				return nil, err
			}

			// Accumulate the number of bytes we've packed in this
			// hop, and move our pointer to the next hop for either
			// packing or normal encoding.
			numBytesPacked += uint32(bytesPacked)

			// At this point we've finished packing all our
			// fragments, so we'll signal the fragment we're
			// currently pointing to as the last fragment.
			if eobPacker.FullyPacked() {
				break
			}

			// Otherwise, we still have more hops to pack, so we'll
			// move over to the next one.
			hopIndex++
		}
	}

	// As a sanity check, we'll ensure that we were able to fully pack all
	// the EOBs in their entirety.
	if numBytesPacked != totalBytesToPack {
		// TODO(roasbeef): make into actual error
		return nil, fmt.Errorf("unable to unroll hops have %v "+
			"bytes unable to pack", totalBytesToPack-numBytesPacked)
	}

	return &unrolledPath, nil
}
