package sphinx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// MoreHopsLength is the amount of bytes it takes us to signal that
	// there are additional hops that contain unrolled EOB fragments.
	MoreHopsLength = 1

	// BlobTypeLength is the number of bytes we use to signal how the
	// underlying EOB fragments should be interpreted by the higher layer.
	BlobTypeLength = 1

	// NumPaddingBytes is the number of padding bytes in the hopData. These
	// bytes are currently unused within the protocol, and are reserved for
	// future use. However, if a hop contains extra data, then we'll
	// utilize this space to pack in the unrolled bytes.
	NumPaddingBytes = 12

	// PivotHopDataSize is the number of bytes of the EOB fragment at the
	// pivot hop. For this hop, we need to use 2 bytes (more hops and type)
	// for signalling purposes, while the remainder can be used to packet
	// EOB fragments.
	//
	// (10 bytes)
	PivotHopDataSize = NumPaddingBytes - MoreHopsLength - BlobTypeLength

	// UnrolledHopDataSize is the size of an unrolled EOB fragment. We use
	// all the existing fields (which are usually used for forwarding used
	// to check the integrity of the unwrapped onion packet.
	//
	// (32 bytes)
	//
	// TODO(roasbeef): if when processing, skip HMAC check...then can be 65
	//  * can also remove the blob type to add another byte
	UnrolledHopDataSize = HopDataSize - HMACSize - MoreHopsLength

	// MaxExtraOnionBlob is the max number of bytes that a sender can fit
	// into all the EOB fragments in a route. Note that in order to pack
	// this many bytes, there can only be a single hop in the route (or a
	// direct hop), as we need a hop to go from sender to pivot hop, with
	// the remaining 19 hops used to pack fragments.
	//
	// NOTE: When using more than 1 hop to deliver data, the max amount of
	// bytes packed will be much lower, as we lose 10 bytes from our
	// theoretical max to signal each pivot hop.
	//
	// TODO(roasbeef): can get 33 more bytes if move to 8 byte exit hop
	// signal in short chan ID
	//
	// (618 bytes)
	MaxExtraOnionBlob = PivotHopDataSize + (UnrolledHopDataSize * (NumMaxHops - 2))
)

var (
	// MoreHopsFlag is a flag that will be used to signal if there are
	// additional EOB hops left. For a pivot hop (the first hop that only
	// has up to 12 bytes available), we'll use the high bit of the second
	// byte. For the full hop (where we can pack up to 32 bytes) we'll set
	// the high bit of the first byte.
	MoreHopsFlag byte = (1 << 7)

	// NumBytesMask is a mask we'll use to pull out the encoding for the
	// number of bytes used to store EOB data in either a pivot or full
	// hop. We use the lower 7 bits of the second padding byte in pivot
	// hop, and the lower 7 bits in the first padding byte of a full hop.
	NumBytesMask byte = (1 << 7) - 1
)

// ErrInvalidNumBytesInPivotHop is a error factory that will be used to inform
// the caller that the encoding of the number of bytes used in a hop are
// incorrect.
func ErrInvalidNumBytesInPivotHop(numBytes uint8) error {
	return fmt.Errorf("max number of bytes in pivot hop is %v, %v was "+
		"signalled", PivotHopDataSize, numBytes)
}

// EOBType is an enum-like type that denotes how to interpret the bytes in EOB
// hops. Higher level applications can use this information to compose
// additional protocols on top of the LN.
type EOBType uint8

const (
	// EOBEmpty denotes that this hop does not contain any additional data.
	EOBEmpty EOBType = 0

	// SphinxSend dentoes that this hop contains data that consumes 2 total
	// hops. This data is the pre-image to the HTLC extended with the onion
	// payload.
	EOBSphinxSend EOBType = 1

	// EOBInnerTLV denotes that the raw bytes in this EOB are encoded using
	// a TLV (type-length-value) format. This is a very flexible EOB type
	// as the sender can communicate strutted data to the receiver.
	EOBInnerTLV EOBType = 2
)

// ExtraHopData is the fully unpacked form of the EOB which can be encoded
// within additional hops of an LN route.
type ExtraHopData struct {
	// Type denotes the type, which tells how the ExtraOnionBlob bytes are
	// to be interpreted.
	Type EOBType

	// ExtraOnionBlob is the raw EOB bytes. Depending on the type of the
	// EOB, this may be structured data or simply be a blob.
	//
	// TODO(roasbeef): may be a map in the future?
	ExtraOnionBlob []byte
}

// UnpackPivotHop attempts to unpack the data within a pivot hop. A pivot hop
// can store 10 bytes total as the break down of a full hop is:
//
//   realm (1 bytes) || chan_id (8 bytes) || amt (8 bytes) || cltv (4 bytes) ||
//   12 bytes (padding) || hmac (32 bytes)
//
// Within the pivot hop, we can only use the 12 padding bytes. Of those 12
// bytes we use the first byte to signal the type of the EOB data, and the
// second byte to encode if there are more hops, and also the number of bytes
// used within this hop.
func (e *ExtraHopData) UnpackPivotHop(h *HopData) error {
	e.Type = EOBType(h.ExtraBytes[0])

	numBytes := h.ExtraBytes[1] & NumBytesMask

	// It's only possible to pack 10 bytes into this hop. Any larger number
	// is an error.
	if numBytes > PivotHopDataSize {
		return ErrInvalidNumBytesInPivotHop(numBytes)
	}

	e.ExtraOnionBlob = append(
		e.ExtraOnionBlob[:], h.ExtraBytes[2:numBytes+2]...,
	)

	return nil
}

// UnpckFullHop attempts to unpack a hop full of EOB data. A full hop can store
// a total of UnrolledHopDataSize or 32 bytes. We're able to use the entire hop
// data other than the HMAC, and we save 1 byte in order to signal
// if there are additional unrolled hops, also packing in the total number of
// bytes used within this hop as well.
func (e *ExtraHopData) UnpackFullHop(h *HopData) error {
	var bytesRead uint8

	bytesPacked := h.ExtraBytes[0] & NumBytesMask

	// maybeUnpack is a helper function that allows us to communicate to
	// each unpacking layer exactly how many bytes they need to read from
	// their field. We use this to ensure that we only communicate the
	// *exact* number of bytes packed, without any padding from unused
	// space.
	maybeUnpack := func(unpackFunc func(uint8) (uint8, error)) error {
		// We'll only call the unpacking function if we still have
		// additional bytes to read.
		if bytesRead < bytesPacked {
			bytesToRead := uint8(bytesPacked - bytesRead)
			bytesUnpacked, err := unpackFunc(bytesToRead)

			bytesRead += bytesUnpacked

			if err != nil {
				return err
			}
		}

		return nil
	}

	var b bytes.Buffer

	// From the realm bytes, we can obtain up to 1 bytes.
	if err := maybeUnpack(func(bytesToRead uint8) (uint8, error) {
		if _, err := b.Write(h.Realm[:]); err != nil {
			return 0, err
		}

		return 1, nil
	}); err != nil {
		return err
	}

	// From the next address field, we can obtain up to 8 bytes.
	if err := maybeUnpack(func(bytesToRead uint8) (uint8, error) {
		if bytesToRead > AddressSize {
			bytesToRead = AddressSize
		}

		_, err := b.Write(h.NextAddress[:bytesToRead])
		if err != nil {
			return 0, err
		}

		return uint8(bytesToRead), nil
	}); err != nil {
		return err
	}

	// From the amount to forward field, we can obtain up to 8 bytes.
	if err := maybeUnpack(func(bytesToRead uint8) (uint8, error) {
		if bytesToRead > AmtForwardSize {
			bytesToRead = AmtForwardSize
		}

		var a [AmtForwardSize]byte
		binary.BigEndian.PutUint64(a[:], h.ForwardAmount)

		if _, err := b.Write(a[:bytesToRead]); err != nil {
			return 0, err
		}

		return uint8(bytesToRead), nil
	}); err != nil {
		return err
	}

	// From the CLTV field, we can obtain up to 4 bytes.
	if err := maybeUnpack(func(bytesToRead uint8) (uint8, error) {
		if bytesToRead > OutgoingCLTVSize {
			bytesToRead = OutgoingCLTVSize
		}

		var o [OutgoingCLTVSize]byte
		binary.BigEndian.PutUint32(o[:], h.OutgoingCltv)

		if _, err := b.Write(o[:bytesToRead]); err != nil {
			return 0, err
		}

		return uint8(bytesToRead), nil
	}); err != nil {
		return err
	}

	// From the padding bytes, we can obtain up to 11 bytes.
	if err := maybeUnpack(func(bytesToRead uint8) (uint8, error) {
		if bytesToRead > NumPaddingBytes {
			bytesToRead = NumPaddingBytes
		}

		_, err := b.Write(h.ExtraBytes[1 : bytesToRead+1])
		if err != nil {
			return 0, err
		}

		return bytesToRead, nil

	}); err != nil {
		return err
	}

	e.ExtraOnionBlob = append(e.ExtraOnionBlob, b.Bytes()...)

	return nil
}

// Packer returns an EOBPacker instance which can be used for unrolling the
// contents of this EOB into additional hops following it.
func (e *ExtraHopData) Packer() EOBPacker {
	return NewEOBPacker(e.ExtraOnionBlob, e.Type)
}

// EOBPacker implements the EOB codec, which allows the caller to unroll the
// EOB data destined for a particular node. Each EOB fragment consumes a single
// actual hop, and comes in two flavors: pivot and full.
type EOBPacker struct {
	// numTotalBytes is the total number of bytes to pack.
	numTotalBytes uint32

	// bytesPacked is the number of bytes that we've packed so far.
	bytesPacked uint32

	// eobReader is a Reader that contains the bytes we've yet to pack into
	// hops.
	eobReader io.Reader

	// eobType is the type of the EOB data. We hold onto this so we can
	// encode it into the pivot hop.
	eobType EOBType
}

// NewEOBPacker returns a new instance of the EOBPacker which can be used to
// unroll EOB data into multiple hops.
func NewEOBPacker(eobData []byte, eobType EOBType) EOBPacker {
	return EOBPacker{
		numTotalBytes: uint32(len(eobData)),
		eobReader:     bytes.NewReader(eobData),
		eobType:       eobType,
	}
}

// PackPivotHop packs up to PivotHopDataSize bytes from the underlying EOB
// reader into the passed HopData. Along the way we set the EOB type, and also
// signal that there are additional EOB fragments following this hop. The
// number of actual bytes packed is returned.
//
// Pivot hop extra padding bytes encoding (10 bytes of data, 2 bytes signal):
//
// 1 byte (type) || 1 bit (more) || 7 bits (length) || 10 bytes data
//
// Where length is the total number of actual bytes packed into this hop.
//
// TODO(roasbeef): use less bytes for length?
func (e *EOBPacker) PackPivotHop(hop *HopData) (uint8, error) {
	// First, we set the type of this hop so the receiver knows how to
	// decode it.
	hop.ExtraBytes[0] = byte(e.eobType)

	// If there are no bytes to pack, then we're down here and we can
	// return early.
	if e.numTotalBytes == 0 {
		return 0, nil
	}

	// With our type encoded, then we'll copy over the first 10 bytes of
	// the EOB as that's what's remaining for this pivot hop.
	n, err := io.ReadFull(e.eobReader, hop.ExtraBytes[2:])
	if err != nil && err != io.ErrUnexpectedEOF {
		// An ErrUnexpectedEOF is expected if we weren't able to fully
		// read all PivotHopDataSize bytes.
		return 0, err
	}

	e.bytesPacked += uint32(n)

	// At this point, if we don't have any more bytes to pack, then we'll
	// mark the "more" bit as false, otherwise we'll toggle it to true.
	if e.FullyPacked() {
		hop.ExtraBytes[1] = 0
	} else {
		hop.ExtraBytes[1] |= byte(MoreHopsFlag)
	}

	// Finally, we'll encode in the remaining 7 bits of the second padding
	// byte the number of bytes packed in this instance.
	hop.ExtraBytes[1] |= byte(n)

	return uint8(n), nil
}

// PackFullHop packs up to UnrolledHopDataSize bytes into the passed HopData.
// The number of actual bytes packed is returned.
// Full hop extra padding bytes encoding:
//
// 1 bit (more) || 7 bits (length) || 11 bytes data
//
// Where length is the total number of actual bytes packed into this hop.
// Additionally, we can also use 32 bytes from the rest of the hop data fields.
// The value we encode in length allows the unpacker to determine which fields
// to read.
func (e *EOBPacker) PackFullHop(hop *HopData) (uint8, error) {
	// First, we'll determine the number of bytes we need to pack for this
	// full hop. If the remaining amount would take multiple hops, then
	// we'll only pack as much as can fit into this one.
	bytesToPack := uint8(e.numTotalBytes - e.bytesPacked)
	if bytesToPack > UnrolledHopDataSize {
		bytesToPack = UnrolledHopDataSize
	}

	var hopBytesPacked uint8
	maybePack := func(packFunc func() (uint8, error)) error {
		if hopBytesPacked != bytesToPack {
			bytesPacked, err := packFunc()

			hopBytesPacked += bytesPacked
			e.bytesPacked += uint32(bytesPacked)

			if err != nil {
				return err
			}
		}

		return nil
	}

	// Using the realm we can pack up to a single byte.
	if err := maybePack(func() (uint8, error) {
		n, err := io.ReadFull(e.eobReader, hop.Realm[:])
		if err != nil && err != io.ErrUnexpectedEOF {
			// An ErrUnexpectedEOF is expected if we weren't able
			// to fully read all PivotHopDataSize bytes.
			return 0, err
		}

		return uint8(n), nil
	}); err != nil {
		return 0, err
	}

	// From the next address, we can pack up to 8 bytes.
	if err := maybePack(func() (uint8, error) {
		n, pErr := io.ReadFull(e.eobReader, hop.NextAddress[:])
		if pErr != nil && pErr != io.ErrUnexpectedEOF {
			// An ErrUnexpectedEOF is expected if we weren't able
			// to fully read all PivotHopDataSize bytes.
			return 0, pErr
		}

		return uint8(n), nil
	}); err != nil {
		return 0, err
	}

	// The forwarding amount also allows us to pack up to 8 bytes.
	if err := maybePack(func() (uint8, error) {
		var a [AmtForwardSize]byte
		n, _ := io.ReadFull(e.eobReader, a[:])

		hop.ForwardAmount = binary.BigEndian.Uint64(a[:])

		return uint8(n), nil
	}); err != nil {
		return 0, err
	}

	// With the outgoing CLTV amount, we can pack up to 4 bytes.
	if err := maybePack(func() (uint8, error) {
		var o [OutgoingCLTVSize]byte
		n, _ := io.ReadFull(e.eobReader, o[:])

		hop.OutgoingCltv = binary.BigEndian.Uint32(o[:])

		return uint8(n), nil
	}); err != nil {
		return 0, err
	}

	// Finally, with the we can pack up to 11 bytes in the padding bytes of
	// the hop data.
	if err := maybePack(func() (uint8, error) {
		n, pErr := io.ReadFull(e.eobReader, hop.ExtraBytes[1:])
		if pErr != nil && pErr != io.ErrUnexpectedEOF {
			// An ErrUnexpectedEOF is expected if we weren't able
			// to fully read all PivotHopDataSize bytes.
			return 0, pErr
		}

		return uint8(n), nil
	}); err != nil {
		return 0, err
	}

	// At this point, if we don't have any more bytes to pack, then we'll
	// mark the "more" byte as false, otherwise we'll toggle it to true.
	if e.FullyPacked() {
		hop.ExtraBytes[0] = 0
	} else {
		hop.ExtraBytes[0] |= byte(MoreHopsFlag)
	}

	// Now that we know how many bytes we've need to packed, we'll encode
	// it into the lower 7 bits of the extra padding bytes.
	hop.ExtraBytes[0] |= hopBytesPacked

	return hopBytesPacked, nil
}

// FullyPacked returns true if all bytes within the underlying EOB reader have
// been fully packed into hop data fragments.
func (e *EOBPacker) FullyPacked() bool {
	return e.numTotalBytes == e.bytesPacked
}

// HasMoreEOBs returns true if this hop additional unrolled hops that are
// encrypted to the same DH public key.
func (h *HopData) HasMoreEOBs(isPivot bool) bool {
	if isPivot {
		return byte(h.ExtraBytes[1])&MoreHopsFlag == MoreHopsFlag
	} else {
		return byte(h.ExtraBytes[0])&MoreHopsFlag == MoreHopsFlag
	}
}

// ExtraOnionBlobType extracts the EOB type (if any) from the padding bytes
// within the hop data.
func (hd *HopData) ExtraOnionBlobType() EOBType {
	return EOBType(hd.ExtraBytes[0])
}

// TODO(roasbeef): move into diff files after set of tests are written, etc
