package sphinx

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

const (
	// addressSize is the length of the serialized address used to uniquely
	// identify the next hop to forward the onion to. BOLT 04 defines this
	// as 8 byte channel_id.
	AddressSize = 8

	// RealmByteSize is the number of bytes that the realm byte occupies.
	RealmByteSize = 1

	// AmtForwardSize is the number of bytes that the amount to forward
	// occupies.
	AmtForwardSize = 8

	// OutgoingCLTVSize is the number of bytes that the outgoing CLTV value
	// occupies.
	OutgoingCLTVSize = 4

	// HopDataSize is the fixed size of hop_data. BOLT 04 currently
	// specifies this to be 1 byte realm, 8 byte channel_id, 8 byte amount
	// to forward, 4 byte outgoing CLTV value, 12 bytes padding and 32
	// bytes HMAC for a total of 65 bytes per hop.
	HopDataSize = (RealmByteSize + AddressSize + AmtForwardSize +
		OutgoingCLTVSize + NumPaddingBytes + HMACSize)

	// sharedSecretSize is the size in bytes of the shared secrets.
	sharedSecretSize = 32

	// routingInfoSize is the fixed size of the the routing info. This
	// consists of a addressSize byte address and a HMACSize byte HMAC for
	// each hop of the route, the first pair in cleartext and the following
	// pairs increasingly obfuscated. In case fewer than numMaxHops are
	// used, then the remainder is padded with null-bytes, also obfuscated.
	routingInfoSize = NumMaxHops * HopDataSize

	// numStreamBytes is the number of bytes produced by our CSPRG for the
	// key stream implementing our stream cipher to encrypt/decrypt the mix
	// header. The last hopDataSize bytes are only used in order to
	// generate/check the MAC over the header.
	numStreamBytes = routingInfoSize + HopDataSize

	// keyLen is the length of the keys used to generate cipher streams and
	// encrypt payloads. Since we use SHA256 to generate the keys, the
	// maximum length currently is 32 bytes.
	keyLen = 32

	// baseVersion represent the current supported version of onion packet.
	baseVersion = 0
)

// OnionPacket is the onion wrapped hop-to-hop routing information necessary to
// propagate a message through the mix-net without intermediate nodes having
// knowledge of their position within the route, the source, the destination,
// and finally the identities of the past/future nodes in the route. At each
// hop the ephemeral key is used by the node to perform ECDH between itself and
// the source node. This derived secret key is used to check the MAC of the
// entire mix header, decrypt the next set of routing information, and
// re-randomize the ephemeral key for the next node in the path. This per-hop
// re-randomization allows us to only propagate a single group element through
// the onion route.
type OnionPacket struct {
	// Version denotes the version of this onion packet. The version
	// indicates how a receiver of the packet should interpret the bytes
	// following this version byte. Currently, a version of 0x00 is the
	// only defined version type.
	Version byte

	// EphemeralKey is the public key that each hop will used in
	// combination with the private key in an ECDH to derive the shared
	// secret used to check the HMAC on the packet and also decrypted the
	// routing information.
	EphemeralKey *btcec.PublicKey

	// RoutingInfo is the full routing information for this onion packet.
	// This encodes all the forwarding instructions for this current hop
	// and all the hops in the route.
	RoutingInfo [routingInfoSize]byte

	// HeaderMAC is an HMAC computed with the shared secret of the routing
	// data and the associated data for this route. Including the
	// associated data lets each hop authenticate higher-level data that is
	// critical for the forwarding of this HTLC.
	HeaderMAC [HMACSize]byte
}

// HopData is the information destined for individual hops. It is a fixed size
// 64 bytes, prefixed with a 1 byte realm that indicates how to interpret it.
// For now we simply assume it's the bitcoin realm (0x00) and hence the format
// is fixed. The last 32 bytes are always the HMAC to be passed to the next
// hop, or zero if this is the packet is not to be forwarded, since this is the
// last hop.
type HopData struct {
	// Realm denotes the "real" of target chain of the next hop. For
	// bitcoin, this value will be 0x00.
	Realm [1]byte

	// NextAddress is the address of the next hop that this packet should
	// be forward to.
	NextAddress [AddressSize]byte

	// ForwardAmount is the HTLC amount that the next hop should forward.
	// This value should take into account the fee require by this
	// particular hop, and the cumulative fee for the entire route.
	ForwardAmount uint64

	// OutgoingCltv is the value of the outgoing absolute time-lock that
	// should be included in the HTLC forwarded.
	OutgoingCltv uint32

	// ExtraBytes is the set of unused bytes within the onion payload. This
	// extra set of bytes can be utilized by higher level applications to
	// package additional data within the per-hop payload, or signal that a
	// portion of the remaining set of hops are to be consumed as Extra
	// Onion Blobs.
	//
	// TODO(roasbeef): rename to padding bytes?
	ExtraBytes [NumPaddingBytes]byte

	// HMAC is an HMAC computed over the entire per-hop payload that also
	// includes the higher-level (optional) associated data bytes.
	HMAC [HMACSize]byte
}

// Encode writes the serialized version of the target HopData into the passed
// io.Writer.
func (hd *HopData) Encode(w io.Writer) error {
	if _, err := w.Write(hd.Realm[:]); err != nil {
		return err
	}

	if _, err := w.Write(hd.NextAddress[:]); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, hd.ForwardAmount); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, hd.OutgoingCltv); err != nil {
		return err
	}

	if _, err := w.Write(hd.ExtraBytes[:]); err != nil {
		return err
	}

	if _, err := w.Write(hd.HMAC[:]); err != nil {
		return err
	}

	return nil
}

// Decode deserializes the encoded HopData contained int he passed io.Reader
// instance to the target empty HopData instance.
func (hd *HopData) Decode(r io.Reader) error {
	if _, err := io.ReadFull(r, hd.Realm[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, hd.NextAddress[:]); err != nil {
		return err
	}

	if err := binary.Read(r, binary.BigEndian, &hd.ForwardAmount); err != nil {
		return err
	}

	if err := binary.Read(r, binary.BigEndian, &hd.OutgoingCltv); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, hd.ExtraBytes[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, hd.HMAC[:]); err != nil {
		return err
	}

	return nil
}

// generateSharedSecrets by the given nodes pubkeys, generates the shared
// secrets.
func generateSharedSecrets(paymentPath []*btcec.PublicKey,
	sessionKey *btcec.PrivateKey) []Hash256 {

	// Each hop performs ECDH with our ephemeral key pair to arrive at a
	// shared secret. Additionally, each hop randomizes the group element
	// for the next hop by multiplying it by the blinding factor. This way
	// we only need to transmit a single group element, and hops can't link
	// a session back to us if they have several nodes in the path.
	numHops := len(paymentPath)
	hopSharedSecrets := make([]Hash256, numHops)

	// Compute the triplet for the first hop outside of the main loop.
	// Within the loop each new triplet will be computed recursively based
	// off of the blinding factor of the last hop.
	lastEphemeralPubKey := sessionKey.PubKey()
	hopSharedSecrets[0] = generateSharedSecret(paymentPath[0], sessionKey)
	lastBlindingFactor := computeBlindingFactor(lastEphemeralPubKey, hopSharedSecrets[0][:])

	// The cached blinding factor will contain the running product of the
	// session private key x and blinding factors b_i, computed as
	//   c_0 = x
	//   c_i = c_{i-1} * b_{i-1} 		 (mod |F(G)|).
	//       = x * b_0 * b_1 * ... * b_{i-1} (mod |F(G)|).
	//
	// We begin with just the session private key x, so that base case
	// c_0 = x. At the beginning of each iteration, the previous blinding
	// factor is aggregated into the modular product, and used as the scalar
	// value in deriving the hop ephemeral keys and shared secrets.
	var cachedBlindingFactor big.Int
	cachedBlindingFactor.SetBytes(sessionKey.D.Bytes())

	// Now recursively compute the cached blinding factor, ephemeral ECDH
	// pub keys, and shared secret for each hop.
	var nextBlindingFactor big.Int
	for i := 1; i <= numHops-1; i++ {
		// Update the cached blinding factor with b_{i-1}.
		nextBlindingFactor.SetBytes(lastBlindingFactor[:])
		cachedBlindingFactor.Mul(&cachedBlindingFactor, &nextBlindingFactor)
		cachedBlindingFactor.Mod(&cachedBlindingFactor, btcec.S256().Params().N)

		// a_i = g ^ c_i
		//     = g^( x * b_0 * ... * b_{i-1} )
		//     = X^( b_0 * ... * b_{i-1} )
		// X_our_session_pub_key x all prev blinding factors
		lastEphemeralPubKey = blindBaseElement(cachedBlindingFactor.Bytes())

		// e_i = Y_i ^ c_i
		//     = ( Y_i ^ x )^( b_0 * ... * b_{i-1} )
		// (Y_their_pub_key x x_our_priv) x all prev blinding factors
		hopBlindedPubKey := blindGroupElement(
			paymentPath[i], cachedBlindingFactor.Bytes(),
		)

		// s_i = sha256( e_i )
		//     = sha256( Y_i ^ (x * b_0 * ... * b_{i-1} )
		hopSharedSecrets[i] = sha256.Sum256(hopBlindedPubKey.SerializeCompressed())

		// Only need to evaluate up to the penultimate blinding factor.
		if i >= numHops-1 {
			break
		}

		// b_i = sha256( a_i || s_i )
		lastBlindingFactor = computeBlindingFactor(
			lastEphemeralPubKey, hopSharedSecrets[i][:],
		)
	}

	return hopSharedSecrets
}

// NewOnionPacket creates a new onion packet which is capable of obliviously
// routing a message through the mix-net path outline by 'paymentPath'.
func NewOnionPacket(paymentPath *PaymentPath, sessionKey *btcec.PrivateKey,
	assocData []byte) (*OnionPacket, error) {

	// Next, taking into account the number of hops it would take to encode
	// all the extra data, we'll ensure that we can properly pack in a
	// regular 20 hop packet.
	err := paymentPath.ValidatePayloadSanity()
	if err != nil {
		return nil, err
	}

	// Now that we know we are exceeding any of the hop (length and
	// unrolled including data) limits, we'll check to see if we need to
	// unroll the path at all.
	if paymentPath.HasExtraData() {
		// In this case, the caller has inserted some extra data for
		// one or more hops, as a result, we'll unroll those hops that
		// pack additional data into an extended route we can run our
		// regular packet construction algorithm on.
		paymentPath, err = paymentPath.UnrollExtraDataHops()
		if err != nil {
			return nil, err
		}
	}

	// The number of total hops is the number of hops *afer* we (maybe)
	// unroll our path into a longer one to encode any EOB data within
	// virtual hop extra data fields.
	numHops := paymentPath.TrueRouteLength()

	hopSharedSecrets := generateSharedSecrets(
		paymentPath.NodeKeys(), sessionKey,
	)

	// Generate the padding, called "filler strings" in the paper.
	filler := generateHeaderPadding(
		"rho", numHops, HopDataSize, hopSharedSecrets,
	)

	// Allocate zero'd out byte slices to store the final mix header packet
	// and the hmac for each hop.
	var (
		mixHeader  [routingInfoSize]byte
		nextHmac   [HMACSize]byte
		hopDataBuf bytes.Buffer
	)

	// Now we compute the routing information for each hop, along with a
	// MAC of the routing info using the shared key for that hop. We use
	// the true size of the possibly expanded path to ensure we properly
	// encode each hop.
	for i := numHops - 1; i >= 0; i-- {
		// We'll derive the two keys we need for each hop in order to:
		// generate our stream cipher bytes for the mixHeader, and
		// calculate the MAC over the entire constructed packet.
		rhoKey := generateKey("rho", &hopSharedSecrets[i])
		muKey := generateKey("mu", &hopSharedSecrets[i])

		// The HMAC for the final hop is simply zeroes. This allows the
		// last hop to recognize that it is the destination for a
		// particular payment.
		paymentPath[i].HopData.HMAC = nextHmac

		// Next, using the key dedicated for our stream cipher, we'll
		// generate enough bytes to obfuscate this layer of the onion
		// packet.
		streamBytes := generateCipherStream(rhoKey, numStreamBytes)

		// Before we assemble the packet, we'll shift the current
		// mix-header to the write in order to make room for this next
		// per-hop data.
		rightShift(mixHeader[:], HopDataSize)

		// With the mix header right-shifted, we'll encode the current
		// hop data into a buffer we'll re-use during the packet
		// construction.
		err := paymentPath[i].HopData.Encode(&hopDataBuf)
		if err != nil {
			return nil, err
		}
		copy(mixHeader[:], hopDataBuf.Bytes())

		// Once the packet for this hop has been assembled, we'll
		// re-encrypt the packet by XOR'ing with a stream of bytes
		// generated using our shared secret.
		xor(mixHeader[:], mixHeader[:], streamBytes[:routingInfoSize])

		// If this is the "last" hop, then we'll override the tail of
		// the hop data.
		if i == numHops-1 {
			copy(mixHeader[len(mixHeader)-len(filler):], filler)
		}

		// The packet for this hop consists of: mixHeader. When
		// calculating the MAC, we'll also include the optional
		// associated data which can allow higher level applications to
		// prevent replay attacks.
		packet := append(mixHeader[:], assocData...)
		nextHmac = calcMac(muKey, packet)

		hopDataBuf.Reset()
	}

	return &OnionPacket{
		Version:      baseVersion,
		EphemeralKey: sessionKey.PubKey(),
		RoutingInfo:  mixHeader,
		HeaderMAC:    nextHmac,
	}, nil
}

// rightShift shifts the byte-slice by the given number of bytes to the right
// and 0-fill the resulting gap.
func rightShift(slice []byte, num int) {
	for i := len(slice) - num - 1; i >= 0; i-- {
		slice[num+i] = slice[i]
	}

	for i := 0; i < num; i++ {
		slice[i] = 0
	}
}

// generateHeaderPadding derives the bytes for padding the mix header to ensure
// it remains fixed sized throughout route transit. At each step, we add
// 'hopSize' padding of zeroes, concatenate it to the previous filler, then
// decrypt it (XOR) with the secret key of the current hop. When encrypting the
// mix header we essentially do the reverse of this operation: we "encrypt" the
// padding, and drop 'hopSize' number of zeroes. As nodes process the mix
// header they add the padding ('hopSize') in order to check the MAC and
// decrypt the next routing information eventually leaving only the original
// "filler" bytes produced by this function at the last hop. Using this
// methodology, the size of the field stays constant at each hop.
func generateHeaderPadding(key string, numHops int, hopSize int,
	sharedSecrets []Hash256) []byte {

	filler := make([]byte, (numHops-1)*hopSize)
	for i := 1; i < numHops; i++ {
		totalFillerSize := ((NumMaxHops - i) + 1) * hopSize

		streamKey := generateKey(key, &sharedSecrets[i-1])
		streamBytes := generateCipherStream(streamKey, numStreamBytes)

		xor(filler, filler, streamBytes[totalFillerSize:totalFillerSize+i*hopSize])
	}
	return filler
}

// Encode serializes the raw bytes of the onion packet into the passed
// io.Writer. The form encoded within the passed io.Writer is suitable for
// either storing on disk, or sending over the network.
func (f *OnionPacket) Encode(w io.Writer) error {
	ephemeral := f.EphemeralKey.SerializeCompressed()

	if _, err := w.Write([]byte{f.Version}); err != nil {
		return err
	}

	if _, err := w.Write(ephemeral); err != nil {
		return err
	}

	if _, err := w.Write(f.RoutingInfo[:]); err != nil {
		return err
	}

	if _, err := w.Write(f.HeaderMAC[:]); err != nil {
		return err
	}

	return nil
}

// Decode fully populates the target ForwardingMessage from the raw bytes
// encoded within the io.Reader. In the case of any decoding errors, an error
// will be returned. If the method success, then the new OnionPacket is ready
// to be processed by an instance of SphinxNode.
func (f *OnionPacket) Decode(r io.Reader) error {
	var err error

	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	f.Version = buf[0]

	// If version of the onion packet protocol unknown for us than in might
	// lead to improperly decoded data.
	if f.Version != baseVersion {
		return ErrInvalidOnionVersion
	}

	var ephemeral [33]byte
	if _, err := io.ReadFull(r, ephemeral[:]); err != nil {
		return err
	}
	f.EphemeralKey, err = btcec.ParsePubKey(ephemeral[:], btcec.S256())
	if err != nil {
		return ErrInvalidOnionKey
	}

	if _, err := io.ReadFull(r, f.RoutingInfo[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, f.HeaderMAC[:]); err != nil {
		return err
	}

	return nil
}

// unwrapPacket wraps a layer of the passed onion packet using the specified
// shared secret and associated data. The associated data will be used to check
// the HMAC at each hop to ensure the same data is passed along with the onion
// packet. This function returns the next inner onion packet layer, along with
// the hop data extracted from the outer onion packet.
func unwrapPacket(onionPkt *OnionPacket, sharedSecret *Hash256,
	assocData []byte) (*OnionPacket, *HopData, error) {

	dhKey := onionPkt.EphemeralKey
	routeInfo := onionPkt.RoutingInfo
	headerMac := onionPkt.HeaderMAC

	// Using the derived shared secret, ensure the integrity of the routing
	// information by checking the attached MAC without leaking timing
	// information.
	message := append(routeInfo[:], assocData...)
	calculatedMac := calcMac(generateKey("mu", sharedSecret), message)
	if !hmac.Equal(headerMac[:], calculatedMac[:]) {
		return nil, nil, ErrInvalidOnionHMAC
	}

	// Attach the padding zeroes in order to properly strip an encryption
	// layer off the routing info revealing the routing information for the
	// next hop.
	streamBytes := generateCipherStream(
		generateKey("rho", sharedSecret),
		numStreamBytes,
	)
	zeroBytes := bytes.Repeat([]byte{0}, HopDataSize)
	headerWithPadding := append(routeInfo[:], zeroBytes...)

	var hopInfo [numStreamBytes]byte
	xor(hopInfo[:], headerWithPadding, streamBytes)

	// Randomize the DH group element for the next hop using the
	// deterministic blinding factor.
	blindingFactor := computeBlindingFactor(dhKey, sharedSecret[:])
	nextDHKey := blindGroupElement(dhKey, blindingFactor[:])

	// With the MAC checked, and the payload decrypted, we can now parse
	// out the per-hop data so we can derive the specified forwarding
	// instructions.
	var hopData HopData
	if err := hopData.Decode(bytes.NewReader(hopInfo[:])); err != nil {
		return nil, nil, err
	}

	// With the necessary items extracted, we'll copy of the onion packet
	// for the next node, snipping off our per-hop data.
	var nextMixHeader [routingInfoSize]byte
	copy(nextMixHeader[:], hopInfo[HopDataSize:])
	innerPkt := &OnionPacket{
		Version:      onionPkt.Version,
		EphemeralKey: nextDHKey,
		RoutingInfo:  nextMixHeader,
		HeaderMAC:    hopData.HMAC,
	}

	return innerPkt, &hopData, nil
}
