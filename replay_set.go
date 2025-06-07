package sphinx

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/lightningnetwork/lnd/tlv"
)

// ReplaySet is a data structure used to efficiently record the occurrence of
// replays, identified by sequence number, when processing a Batch. Its primary
// functionality includes set construction, membership queries, and merging of
// replay sets.
type ReplaySet struct {
	maxCLTV   tlv.RecordT[tlv.TlvType0, uint32]
	replaySet tlv.RecordT[tlv.TlvType1, replayMap]
}

// NewReplaySet initializes an empty replay set.
func NewReplaySet() *ReplaySet {
	return &ReplaySet{
		maxCLTV: tlv.NewPrimitiveRecord[tlv.TlvType0, uint32](0),
		replaySet: tlv.NewRecordT[tlv.TlvType1](
			make(replayMap),
		),
	}
}

// MaxCLTV returns the maximum CLTV value in the replay set.
func (rs *ReplaySet) MaxCLTV() uint32 {
	return rs.maxCLTV.Val
}

// SetMaxCLTV sets the maximum CLTV value in the replay set if the provided
// CLTV is greater than the current maximum.
func (rs *ReplaySet) SetMaxCLTV(cltv uint32) {
	if cltv > rs.maxCLTV.Val {
		rs.maxCLTV.Val = cltv
	}
}

// Size returns the number of elements in the replay set.
func (rs *ReplaySet) Size() int {
	return len(rs.replaySet.Val)
}

// Add inserts the provided index into the replay set.
func (rs *ReplaySet) Add(idx uint16, cltv uint32) {
	rs.replaySet.Val[idx] = struct{}{}

	// Update the maximum CLTV if the provided CLTV is greater.
	if cltv > rs.maxCLTV.Val {
		rs.maxCLTV.Val = cltv
	}
}

// Contains queries the contents of the replay set for membership of a
// particular index.
func (rs *ReplaySet) Contains(idx uint16) bool {
	_, ok := rs.replaySet.Val[idx]
	return ok
}

// Merge adds the contents of the provided replay set to the receiver's set.
func (rs *ReplaySet) Merge(rs2 *ReplaySet) {
	// First merge all sequence numbers
	for seqNum := range rs2.replaySet.Val {
		rs.replaySet.Val[seqNum] = struct{}{}
	}

	// Then update maxCLTV once if needed
	if rs2.maxCLTV.Val > rs.maxCLTV.Val {
		rs.maxCLTV.Val = rs2.maxCLTV.Val
	}
}

// Encode serializes the replay set into an io.Writer suitable for storage. The
// replay set can be recovered using Decode.
func (rs *ReplaySet) Encode(w io.Writer) error {
	records := []tlv.Record{
		rs.maxCLTV.Record(),
		rs.replaySet.Record(),
	}

	tlv.SortRecords(records)

	tlvStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode reconstructs a replay set given a io.Reader. The byte
// slice is assumed to be even in length, otherwise resulting in failure.
func (rs *ReplaySet) Decode(r io.Reader) error {
	tlvStream, err := tlv.NewStream(rs.maxCLTV.Record(),
		rs.replaySet.Record())
	if err != nil {
		return err
	}

	return tlvStream.Decode(r)
}

type replayMap map[uint16]struct{}

// encodeReplayMap encodes a replay map.
func encodeReplayMap(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(replayMap); ok {
		length := len(v)
		err := binary.Write(w, binary.BigEndian, uint32(length))
		if err != nil {
			return err
		}

		for seqNum := range v {
			err := binary.Write(w, binary.BigEndian, seqNum)
			if err != nil {
				return err
			}
		}

		return nil
	}

	return tlv.NewTypeForEncodingErr(val, "replayMap")
}

// decodeReplayMap decodes a replay map.
func decodeReplayMap(r io.Reader, val interface{}, buf *[8]byte,
	l uint64) error {

	if v, ok := val.(replayMap); ok {
		// First read the length of the map.
		var length uint32
		err := binary.Read(r, binary.BigEndian, &length)
		if err != nil {
			return err
		}

		// Then read all sequence numbers.
		for i := uint32(0); i < length; i++ {
			var seqNum uint16
			err := binary.Read(r, binary.BigEndian, &seqNum)
			if err != nil {
				return err
			}

			v[seqNum] = struct{}{}
		}

		return nil
	}

	return tlv.NewTypeForDecodingErr(val, "replayMap", l, l)
}

// Record returns a TLV record that can be used to encode/decode a
// replayMap to/from a TLV stream.
//
// NOTE: Needs to be defined as a value receiver, otherwise the encoder and
// decoder will fail the type check.
func (rm replayMap) Record() tlv.Record {
	recordSize := func() uint64 {
		var (
			b   bytes.Buffer
			buf [8]byte
		)
		if err := encodeReplayMap(&b, rm, &buf); err != nil {
			panic(err)
		}

		return uint64(len(b.Bytes()))
	}

	return tlv.MakeDynamicRecord(
		0, rm, recordSize, encodeReplayMap, decodeReplayMap,
	)
}
