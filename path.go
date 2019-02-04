package sphinx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/btcsuite/btcd/btcec"
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

// HopPayload is a slice of bytes and associated payload-type that are
// destined for a specific hop in the PaymentPath. The payload itself
// is treated as an opaque datafield by the onion router, while the
// Realm is modified to indicate how many hops are to be read by the
// processing node. The 4 MSB in the realm indicate how many
// additional hops are to be processed to collect the entire payload.
type HopPayload struct {
	Realm   [1]byte
	Payload []byte
	HMAC    [hmacSize]byte
}

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

	HopPayload HopPayload
}

// Helper function to transition from the two separate arrays to the
// single struct that describes the entire path.
func NewPaymentPath(nodeIds []*btcec.PublicKey, hopsData []HopData) (*PaymentPath, error) {
	var paymentPath PaymentPath

	if len(nodeIds) != len(hopsData) {
		return nil, fmt.Errorf("node ID count does not match hop data count: %d != %d", len(nodeIds), len(hopsData))
	}

	for i := range nodeIds {
		var buf bytes.Buffer
		paymentPath[i].NodePub = *nodeIds[i]
		paymentPath[i].HopData = hopsData[i]
		hopsData[i].Encode(&buf)
		paymentPath[i].HopPayload = HopPayload{
			Realm:   [1]byte{hopsData[i].Realm},
			Payload: buf.Bytes(),
		}
	}
	return &paymentPath, nil
}

// IsEmpty returns true if the hop isn't populated.
func (o OnionHop) IsEmpty() bool {
	return o.NodePub.X == nil || o.NodePub.Y == nil
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

func (p *PaymentPath) CountFrames() int {
	frameCount := 0
	for _, hop := range p {
		if hop.IsEmpty() {
			break
		}
		frameCount = frameCount + hop.HopPayload.CountFrames()
	}
	return frameCount
}

// CountFrames returns the number of frames required to encode a given payload
func (hp *HopPayload) CountFrames() int {
	// If it all fits in the legacy payload size, don't use any
	// additional frames.
	if len(hp.Payload) <= 32 {
		return 1
	}

	// Otherwise we'll need at least one additional frame: subtract
	// the 64 bytes we can stuff into payload and hmac of the
	// first, and the 33 bytes we can pack into the payload of the
	// second, then divide the remainder by 65.
	remainder := len(hp.Payload) - 64 - 33
	return 2 + int(math.Ceil(float64(remainder)/65))
}

func (hp *HopPayload) CalculateRealm() {
	hp.Realm[0] = (hp.Realm[0] & 0x0F) | (byte(hp.CountFrames()-1) << 4)
}

func (hp *HopPayload) Encode(w io.Writer) error {
	// We'll need to add enough padding bytes to position the HMAC
	// at the end of the payload
	padding := hp.CountFrames()*65 - len(hp.Payload) - 1 - 32
	if padding < 0 {
		panic("Can't have negative padding")
	}
	hp.CalculateRealm()

	if _, err := w.Write(hp.Realm[:]); err != nil {
		return err
	}

	if _, err := w.Write(hp.Payload); err != nil {
		return err
	}

	if padding > 0 {
		w.Write(bytes.Repeat([]byte{0x00}, padding))
	}

	if _, err := w.Write(hp.HMAC[:]); err != nil {
		return err
	}

	return nil
}

func (hp *HopPayload) Decode(r io.Reader) error {
	if _, err := io.ReadFull(r, hp.Realm[:]); err != nil {
		return err
	}

	numFrames := int(hp.Realm[0]>>4) + 1
	numBytes := (numFrames * hopDataSize) - 32 - 1

	hp.Payload = make([]byte, numBytes)

	if _, err := io.ReadFull(r, hp.Payload[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, hp.HMAC[:]); err != nil {
		return err
	}

	return nil
}

func (hp *HopPayload) HopData() (*HopData, error) {
	if hp.Realm[0] != 0x00 {
		// This is not a legacy HopData, so we can't interpret
		// it as such
		return nil, fmt.Errorf("payload is not a HopData payload, realm=%d", hp.Realm[0])
	}

	hd := HopData{
		Realm: hp.Realm[0],
		HMAC:  hp.HMAC,
	}

	// Parse the actual payload
	r := bytes.NewBuffer(hp.Payload)
	if _, err := io.ReadFull(r, hd.NextAddress[:]); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.BigEndian, &hd.ForwardAmount); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.BigEndian, &hd.OutgoingCltv); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(r, hd.ExtraBytes[:]); err != nil {
		return nil, err
	}
	return &hd, nil
}
