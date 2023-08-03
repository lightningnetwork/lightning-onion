package sphinx

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/btcsuite/btcd/wire"
)

// PayloadType denotes the type of the payload included in the onion packet.
// Serialization of a raw HopPayload will depend on the payload type, as some
// include a varint length prefix, while others just encode the raw payload.
type PayloadType uint8

const (
	// PayloadLegacy is the legacy payload type. It includes a fixed 32
	// bytes, 12 of which are padding, and uses a "zero length" (the old
	// realm) prefix.
	PayloadLegacy PayloadType = iota

	// PayloadTLV is the new modern TLV based format. This payload includes
	// a set of opaque bytes with a varint length prefix. The varint used
	// is the same CompactInt as used in the Bitcoin protocol.
	PayloadTLV
)

// HopPayload is a slice of bytes and associated payload-type that are destined
// for a specific hop in the PaymentPath. The payload itself is treated as an
// opaque data field by the onion router. The included Type field informs the
// serialization/deserialziation of the raw payload.
type HopPayload struct {
	// Type is the type of the payload.
	Type PayloadType

	// Payload is the raw bytes of the per-hop payload for this hop.
	// Depending on the realm, this pay be the regular legacy hop data, or
	// a set of opaque blobs to be parsed by higher layers.
	Payload []byte

	// HMAC is an HMAC computed over the entire per-hop payload that also
	// includes the higher-level (optional) associated data bytes.
	HMAC [HMACSize]byte
}

// NewTLVHopPayload creates a new TLV encoded HopPayload. The payload will be
// a TLV encoded stream that will contain forwarding instructions for a hop.
func NewTLVHopPayload(payload []byte) (HopPayload, error) {
	var (
		h HopPayload
		b bytes.Buffer
	)

	// Write out the raw payload which contains a set of opaque bytes that
	// the recipient can decode to make a forwarding decision.
	if _, err := b.Write(payload); err != nil {
		return h, nil
	}

	h.Type = PayloadTLV
	h.Payload = b.Bytes()

	return h, nil
}

// NumBytes returns the number of bytes it will take to serialize the full
// payload. Depending on the payload type, this may include some additional
// signalling bytes.
func (hp *HopPayload) NumBytes() int {
	if hp.Type == PayloadLegacy {
		return legacyNumBytes()
	}

	return tlvNumBytes(len(hp.Payload))
}

// Encode encodes the hop payload into the passed writer.
func (hp *HopPayload) Encode(w io.Writer) error {
	if hp.Type == PayloadLegacy {
		return encodeLegacyHopPayload(hp, w)
	}

	return encodeTLVHopPayload(hp, w)
}

// Decode unpacks an encoded HopPayload from the passed reader into the target
// HopPayload.
func (hp *HopPayload) Decode(r io.Reader) error {
	bufReader := bufio.NewReader(r)

	// In order to properly parse the payload, we'll need to check the
	// first byte. We'll use a bufio reader to peek at it without consuming
	// it from the buffer.
	peekByte, err := bufReader.Peek(1)
	if err != nil {
		return err
	}

	var (
		legacyPayload = isLegacyPayloadByte(peekByte[0])
		payloadSize   uint16
	)

	if legacyPayload {
		payloadSize = legacyPayloadSize()
		hp.Type = PayloadLegacy
	} else {
		payloadSize, err = tlvPayloadSize(bufReader)
		if err != nil {
			return err
		}

		hp.Type = PayloadTLV
	}

	// Now that we know the payload size, we'll create a  new buffer to
	// read it out in full.
	//
	// TODO(roasbeef): can avoid all these copies
	hp.Payload = make([]byte, payloadSize)
	if _, err := io.ReadFull(bufReader, hp.Payload[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(bufReader, hp.HMAC[:]); err != nil {
		return err
	}

	return nil
}

// HopData attempts to extract a set of forwarding instructions from the target
// HopPayload. If the realm isn't what we expect, then an error is returned.
// This method also returns the left over EOB that remain after the hop data
// has been parsed. Callers may want to map this blob into something more
// concrete.
func (hp *HopPayload) HopData() (*HopData, error) {
	// The HopData can only be extracted at this layer for payloads using
	// the legacy encoding.
	if hp.Type == PayloadLegacy {
		return decodeLegacyHopData(hp.Payload)
	}

	return nil, nil
}

// tlvPayloadSize uses the passed reader to extract the payload length encoded
// as a var-int.
func tlvPayloadSize(r io.Reader) (uint16, error) {
	var b [8]byte
	varInt, err := ReadVarInt(r, &b)
	if err != nil {
		return 0, err
	}

	if varInt > math.MaxUint16 {
		return 0, fmt.Errorf("payload size of %d is larger than the "+
			"maximum allowed size of %d", varInt, math.MaxUint16)
	}

	return uint16(varInt), nil
}

// tlvNumBytes takes the length of the payload and returns the number of bytes
// that it would take to serialise such a payload. For the TLV type encoding,
// the payload length itself would be encoded as a var-int, this is then
// followed by the payload itself and finally an HMAC would be appended.
func tlvNumBytes(payloadLen int) int {
	return wire.VarIntSerializeSize(uint64(payloadLen)) + payloadLen +
		HMACSize
}

// encodeTLVHopPayload takes a HopPayload and writes it to the given writer
// using the TLV encoding which requires the payload and HMAC to be pre-fixed
// with a var-int encoded length.
func encodeTLVHopPayload(hp *HopPayload, w io.Writer) error {
	// First, the length of the payload is encoded as a var-int.
	var b [8]byte
	err := WriteVarInt(w, uint64(len(hp.Payload)), &b)
	if err != nil {
		return err
	}

	// Then, the raw payload and he HMAC are written in series.
	if _, err := w.Write(hp.Payload); err != nil {
		return err
	}

	_, err = w.Write(hp.HMAC[:])

	return err
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
	Realm [RealmByteSize]byte

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

	err := binary.Write(w, binary.BigEndian, hd.ForwardAmount)
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, hd.OutgoingCltv)
	if err != nil {
		return err
	}

	if _, err := w.Write(hd.ExtraBytes[:]); err != nil {
		return err
	}

	return nil
}

// Decode Decodes populates the target HopData with the contents of a serialized
// HopData packed into the passed io.Reader.
func (hd *HopData) Decode(r io.Reader) error {
	if _, err := io.ReadFull(r, hd.Realm[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, hd.NextAddress[:]); err != nil {
		return err
	}

	err := binary.Read(r, binary.BigEndian, &hd.ForwardAmount)
	if err != nil {
		return err
	}

	err = binary.Read(r, binary.BigEndian, &hd.OutgoingCltv)
	if err != nil {
		return err
	}

	_, err = io.ReadFull(r, hd.ExtraBytes[:])
	return err
}

// NewLegacyHopPayload creates a new hop payload given a set of forwarding
// instructions specified as HopData for a hop. This is the legacy encoding
// for a HopPayload.
func NewLegacyHopPayload(hopData *HopData) (HopPayload, error) {
	var (
		h HopPayload
		b bytes.Buffer
	)

	if err := hopData.Encode(&b); err != nil {
		return h, nil
	}

	// We'll also mark that this particular hop will be using the legacy
	// format as the modern format packs the existing hop data information
	// into the EOB space as a TLV stream.
	h.Type = PayloadLegacy
	h.Payload = b.Bytes()

	return h, nil
}

// legacyPayloadSize returns the size of payloads encoded using the legacy
// fixed-size encoding.
func legacyPayloadSize() uint16 {
	return LegacyHopDataSize - HMACSize
}

// legacyNumBytes returns the number of bytes it will take to serialize the full
// payload. For the legacy encoding type, this is always a fixed number.
func legacyNumBytes() int {
	return LegacyHopDataSize
}

// isLegacyPayload returns true if the given byte is equal to the 0x00 byte
// which indicates that the payload should be decoded as a legacy payload.
func isLegacyPayloadByte(b byte) bool {
	return b == 0x00
}

// encodeLegacyHopPayload takes a HopPayload and writes it to the given writer
// using the legacy encoding.
func encodeLegacyHopPayload(hp *HopPayload, w io.Writer) error {
	// The raw payload and he HMAC are written in series.
	if _, err := w.Write(hp.Payload); err != nil {
		return err
	}

	_, err := w.Write(hp.HMAC[:])

	return err
}

// decodeLegacyHopData takes a payload and decodes it into a HopData struct.
func decodeLegacyHopData(payload []byte) (*HopData, error) {
	var (
		payloadReader = bytes.NewBuffer(payload)
		hd            HopData
	)
	if err := hd.Decode(payloadReader); err != nil {
		return nil, err
	}

	return &hd, nil
}
