package sphinx

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	// NumMaxHops is the maximum path length. There is a maximum of 1300
	// bytes in the routing info block. Legacy hop payloads are always 65
	// bytes, while tlv payloads are at least 47 bytes (tlvlen 1, amt 2,
	// timelock 2, nextchan 10, hmac 32) for the intermediate hops and 37
	// bytes (tlvlen 1, amt 2, timelock 2, hmac 32) for the exit hop. The
	// maximum path length can therefore only be reached by using tlv
	// payloads only. With that, the maximum number of intermediate hops
	// is: Floor((1300 - 37) / 47) = 26. Including the exit hop, the
	// maximum path length is 27 hops.
	NumMaxHops = 27

	routeBlindingHMACKey = "blinded_node_id"
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

	// HopPayload is the opaque payload provided to this node. If the
	// HopData above is specified, then it'll be packed into this payload.
	HopPayload HopPayload
}

// IsEmpty returns true if the hop isn't populated.
func (o OnionHop) IsEmpty() bool {
	return o.NodePub.X().BitLen() == 0 || o.NodePub.Y().BitLen() == 0
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
		// zero'd out portion of the array.
		if hop.IsEmpty() {
			return routeLength
		}

		routeLength++
	}

	return routeLength
}

// TotalPayloadSize returns the sum of the size of each payload in the "true"
// route.
func (p *PaymentPath) TotalPayloadSize() int {
	var totalSize int
	for _, hop := range p {
		if hop.IsEmpty() {
			continue
		}

		totalSize += hop.HopPayload.NumBytes()
	}

	return totalSize
}

// BlindedPath represents all the data that the creator of a blinded path must
// transmit to the builder of route that will send to this path.
type BlindedPath struct {
	// IntroductionPoint is the real node ID of the first hop in the blinded
	// path. The sender should be able to find this node in the network
	// graph and route to it.
	IntroductionPoint *btcec.PublicKey

	// BlindingPoint is the first ephemeral blinding point. This is the
	// point that the introduction node will use in order to create a shared
	// secret with the builder of the blinded route. This point will need
	// to be communicated to the introduction node by the sender in some
	// way.
	BlindingPoint *btcec.PublicKey

	// BlindedHops is a list of ordered BlindedHopInfo. Each entry
	// represents a hop in the blinded path along with the encrypted data to
	// be sent to that node. Note that the first entry in the list
	// represents the introduction point of the path and so the node ID of
	// this point does not strictly need to be transmitted to the sender
	// since they will be able to derive the point using the BlindingPoint.
	BlindedHops []*BlindedHopInfo
}

// BlindedHopInfo represents a blinded node pub key along with the encrypted
// data for a node in a blinded route.
type BlindedHopInfo struct {
	// BlindedNodePub is the blinded public key of the node in the blinded
	// route.
	BlindedNodePub *btcec.PublicKey

	// CipherText is the encrypted payload to be transported to the hop in
	// the blinded route.
	CipherText []byte
}

// HopInfo represents a real node pub key along with the plaintext data for a
// node in a blinded route.
type HopInfo struct {
	// NodePub is the real public key of the node in the blinded route.
	NodePub *btcec.PublicKey

	// PlainText is the un-encrypted payload to be transported to the hop
	// the blinded route.
	PlainText []byte
}

// Encrypt uses the given sharedSecret to blind the public key of the node and
// encrypt the payload and returns the resulting BlindedHopInfo.
func (i *HopInfo) Encrypt(sharedSecret Hash256) (*BlindedHopInfo, error) {
	blindedData, err := encryptBlindedHopData(sharedSecret, i.PlainText)
	if err != nil {
		return nil, err
	}

	return &BlindedHopInfo{
		BlindedNodePub: blindNodeID(sharedSecret, i.NodePub),
		CipherText:     blindedData,
	}, nil
}

// BuildBlindedPath creates a new BlindedPath from a session key along with a
// list of HopInfo representing the nodes in the blinded path. The first hop in
// paymentPath is expected to be the introduction node.
func BuildBlindedPath(sessionKey *btcec.PrivateKey,
	paymentPath []*HopInfo) (*BlindedPath, error) {

	if len(paymentPath) < 1 {
		return nil, errors.New("at least 1 hop is required to create " +
			"a blinded path")
	}

	bp := &BlindedPath{
		IntroductionPoint: paymentPath[0].NodePub,
		BlindingPoint:     sessionKey.PubKey(),
		BlindedHops:       make([]*BlindedHopInfo, len(paymentPath)),
	}

	keys := make([]*btcec.PublicKey, len(paymentPath))
	for i, p := range paymentPath {
		keys[i] = p.NodePub
	}

	hopSharedSecrets, err := generateSharedSecrets(keys, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("error generating shared secret: %v",
			err)
	}

	for i, hop := range paymentPath {
		blindedInfo, err := hop.Encrypt(hopSharedSecrets[i])
		if err != nil {
			return nil, err
		}

		bp.BlindedHops[i] = blindedInfo
	}

	return bp, nil
}

// blindNodeID blinds the given public key using the provided shared secret.
func blindNodeID(sharedSecret Hash256,
	pubKey *btcec.PublicKey) *btcec.PublicKey {

	blindingFactorBytes := generateKey(routeBlindingHMACKey, &sharedSecret)

	var blindingFactor btcec.ModNScalar
	blindingFactor.SetBytes(&blindingFactorBytes)

	return blindGroupElement(pubKey, blindingFactor)
}

// encryptBlindedHopData blinds/encrypts the given plain text data using the
// provided shared secret.
func encryptBlindedHopData(sharedSecret Hash256, plainTxt []byte) ([]byte,
	error) {

	rhoKey := generateKey("rho", &sharedSecret)

	return chacha20polyEncrypt(rhoKey[:], plainTxt)
}

// decryptBlindedHopData decrypts the data encrypted by the creator of the
// blinded route.
func decryptBlindedHopData(privKey SingleKeyECDH, ephemPub *btcec.PublicKey,
	encryptedData []byte) ([]byte, error) {

	ss, err := privKey.ECDH(ephemPub)
	if err != nil {
		return nil, err
	}

	ssHash := Hash256(ss)
	rho := generateKey("rho", &ssHash)

	return chacha20polyDecrypt(rho[:], encryptedData)
}

// NextEphemeral computes the next ephemeral key given the current ephemeral
// key and this node's private key.
func NextEphemeral(privKey SingleKeyECDH,
	ephemPub *btcec.PublicKey) (*btcec.PublicKey, error) {

	ss, err := privKey.ECDH(ephemPub)
	if err != nil {
		return nil, err
	}

	blindingFactor := computeBlindingFactor(ephemPub, ss[:])
	nextEphem := blindGroupElement(ephemPub, blindingFactor)

	return nextEphem, nil
}
