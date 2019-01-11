package sphinx

import (
	"bytes"
	"math/rand"
	"testing"
	"time"
)

// TestEOBPackUnpackPivotHop tests that we're able to properly pack+unpack a
// pivot hop.  Packing maps a EOB blob into a hop data, and unpacking goes the
// other direction.
func TestEOBPackUnpackPivotHop(t *testing.T) {
	t.Parallel()

	var testCases = []struct {
		dataSize    uint32
		fullyPacked bool
		eobType     EOBType
	}{
		// Exact size, should fit in a pivot hop, and should be fully packed.
		{
			dataSize:    PivotHopDataSize,
			fullyPacked: true,
			eobType:     EOBSphinxSend,
		},

		// Smaller than the max size, should still fit and be fully packed.
		{
			dataSize:    PivotHopDataSize / 2,
			fullyPacked: true,
			eobType:     EOBSphinxSend,
		},

		// Greater than the max size, should pack, but data should be left
		// over.
		{
			dataSize:    PivotHopDataSize * 2,
			fullyPacked: false,
			eobType:     EOBInnerTLV,
		},

		// Empty data, should still pack, and show fully packed as there're
		// no bytes to pack at all.
		{
			dataSize:    0,
			fullyPacked: true,
			eobType:     EOBInnerTLV,
		},
	}

	for i, testCase := range testCases {
		// First, we'll make our sample data by reading the specified
		// number of random bytes.
		pivotData := make([]byte, testCase.dataSize)
		if _, err := rand.Read(pivotData[:]); err != nil {
			t.Fatalf("#%v: unable to read pivot hop types: %v",
				i, err)
		}

		// With our bytes read, we'll create a packer, and pack in only
		// a pivot hop's worth of data.
		eobPacker := (&ExtraHopData{
			ExtraOnionBlob: pivotData,
			Type:           testCase.eobType,
		}).Packer()

		var hopData HopData
		if _, err := eobPacker.PackPivotHop(&hopData); err != nil {
			t.Fatalf("#%v: unable to pack pivot hop: %v", i, err)
		}

		switch {
		// After packing, if we should be fully be packed, but aren't
		// then we've failed.
		case !eobPacker.FullyPacked() && testCase.fullyPacked:
			t.Fatalf("#%v: hop should be fully packed but isn't", i)

		// On the other hand if we're fully packed but shouldn't be,
		// then this is also a failure.
		case eobPacker.FullyPacked() && !testCase.fullyPacked:
			t.Fatalf("#%v: hop should is fully packed but "+
				"shouldn't be", i)

		// If we're fully packed, then from the perspective of the hop
		// data, there shouldn't be any more to unpack.
		case eobPacker.FullyPacked() && hopData.HasMoreEOBs(true):
			t.Fatalf("#%v: hop data shows more EOBs but shouldn't",
				i)
		}

		// Next, we'll attempt to unpack the data back into an EOB data
		// struct.
		var eobData ExtraHopData
		if err := eobData.UnpackPivotHop(&hopData); err != nil {
			t.Fatalf("#%v: unable to unpack data: %v", i, err)
		}

		switch {
		// If this isn't beyond an amount that can fit into a pivot
		// hop, then we'll ensure to only compare the dataSize length
		// bytes in the hop data and not the entire thing.
		case testCase.dataSize <= PivotHopDataSize:
			if !bytes.Equal(pivotData, eobData.ExtraOnionBlob) {
				t.Fatalf("#%v: unable to unpack data: "+
					"expected %x got %x", i, pivotData,
					eobData.ExtraOnionBlob)
			}

			if testCase.dataSize != eobPacker.bytesPacked {
				t.Fatalf("#%v: expected %v bytes packed, "+
					"got %v", i, testCase.dataSize,
					eobPacker.bytesPacked)
			}

		// Alternatively, if this is more that a fully pivot hop, then
		// we'll only compare the amount that we _should_ be able to
		// pack.
		case testCase.dataSize > PivotHopDataSize:
			if !bytes.Equal(pivotData[:PivotHopDataSize],
				eobData.ExtraOnionBlob) {

				t.Fatalf("#%v: unable to unpack data: "+
					"expected %x got %x", i,
					pivotData[:PivotHopDataSize],
					eobData.ExtraOnionBlob)
			}

		}

		// Finally, ensure that the pivot hop type was mapped properly.
		if eobData.Type != testCase.eobType {
			t.Fatalf("#%v: wrong eob type: expected %v got %v", i,
				testCase.eobType, eobData.Type)
		}
		if hopData.ExtraOnionBlobType() != testCase.eobType {
			t.Fatalf("#%v: wrong hop data eob type: expected %v "+
				"got %v", i, testCase.eobType,
				hopData.ExtraOnionBlobType())
		}
	}
}

// TestEOBPackUnpackFullHop tests that we're able to properly pack+unpack a
// pivot hop.  Packing maps a EOB blob into a hop data, and unpacking goes the
// other direction.
func TestEOBPackUnpackFullHop(t *testing.T) {
	t.Parallel()

	type testCase struct {
		dataSize    uint32
		fullyPacked bool
		multiPack   bool
	}

	var testCases = []testCase{
		// Greater than the max size, should pack but into multiple
		// hops, but data should be left over.
		{
			dataSize:    UnrolledHopDataSize * 2,
			fullyPacked: false,
			multiPack:   true,
		},

		// Greater than the max size, non full last hop. Should pack
		// but into multiple hops, but data should be left over.
		{
			dataSize:    UnrolledHopDataSize*2 + 10,
			fullyPacked: false,
			multiPack:   true,
		},
	}

	// We'll ensure that we can properly encode data sizes from 0 to
	// UnrolledHopDataSize.
	for i := 0; i < UnrolledHopDataSize+1; i++ {
		// All of these should be fully packed, and fit into a single hop.
		testCases = append(testCases, testCase{
			dataSize:    uint32(i),
			fullyPacked: true,
		})
	}

	for i, testCase := range testCases {
		// First, we'll make our sample data by reading the specified
		// number of random bytes.
		fullData := make([]byte, testCase.dataSize)
		if _, err := rand.Read(fullData[:]); err != nil {
			t.Fatalf("#%v: unable to read full hop types: %v",
				i, err)
		}

		// With our bytes read, we'll create a packer, and pack in only
		// a pivot hop's worth of data.
		eobPacker := NewEOBPacker(fullData, 0)

		var hopDatas []HopData
		hopDatas = append(hopDatas, HopData{})
		if _, err := eobPacker.PackFullHop(&hopDatas[0]); err != nil {
			t.Fatalf("#%v: unable to pack full hop: %v", i, err)
		}

		switch {
		// If this should be a multi-pack, and we're not yet fully
		// packed, then we'll continue to pack until we are.
		case testCase.multiPack && !eobPacker.FullyPacked():
			for !eobPacker.FullyPacked() {
				hopDatas = append(hopDatas, HopData{})
				_, err := eobPacker.PackFullHop(
					&hopDatas[len(hopDatas)-1],
				)
				if err != nil {
					t.Fatalf("#%v: unable to pack full "+
						"hop: %v", i, err)
				}

				// If we're still not fully packed, then the
				// hopData should reflect that.
				hop := hopDatas[len(hopDatas)-1]
				if !eobPacker.FullyPacked() !=
					hop.HasMoreEOBs(false) {

					t.Fatalf("#%v: mismatch between "+
						"packer (full=%v) and hopData "+
						"(full=%v)", i, eobPacker.FullyPacked(),
						!hop.HasMoreEOBs(false))
				}
			}

		// If this should be a multi-pack, and we're already fully
		// packed, then we've failed.
		case testCase.multiPack && eobPacker.FullyPacked():
			t.Fatalf("multi pack already fully packed")

		// After packing, if we should be fully be packed, but aren't
		// then we've failed.
		case !eobPacker.FullyPacked() && testCase.fullyPacked:
			t.Fatalf("#%v: hop should be fully packed but isn't", i)

		// On the other hand if we're fully packed but shouldn't be,
		// then this is also a failure.
		case eobPacker.FullyPacked() && !testCase.fullyPacked:
			t.Fatalf("#%v: hop should is fully packed but "+
				"shouldn't be", i)
		}

		// Next, we'll attempt to unpack the data back into an EOB data
		// struct.
		var eobData ExtraHopData
		for _, hopData := range hopDatas {
			if err := eobData.UnpackFullHop(&hopData); err != nil {
				t.Fatalf("#%v: unable to unpack data: %v", i,
					err)
			}
		}

		// Ensure we were able to fully recover all the bytes.
		if !bytes.Equal(fullData, eobData.ExtraOnionBlob) {
			t.Fatalf("#%v: unable to unpack data: expected %x "+
				"got %x", i, fullData, eobData.ExtraOnionBlob)
		}

		if testCase.dataSize != eobPacker.bytesPacked {
			t.Fatalf("#%v: expected %v bytes packed, got %v", i,
				testCase.dataSize, eobPacker.bytesPacked)
		}
	}
}

// TestUnpackPivotHopInvalidNumBytes ensures that the UnpackPivotHop method
// will reject an malformed length field for all the bytes.
func TestUnpackPivotHopInvalidNumBytes(t *testing.T) {
	t.Parallel()

	var hopData HopData
	hopData.ExtraBytes[1] = (1 << 8) - 1

	var eobData ExtraHopData
	err := eobData.UnpackPivotHop(&hopData)
	if err == nil {
		t.Fatalf("should have failed to unpack hop")
	}
}

// TestUnpackFullHopInvalidFullHopNumBytes tests that if a full hop as an
// invalid num bytes encoding,t hen we parse all the bytes we can and not fail.
func TestUnpackFullHopInvalidFullHopNumBytes(t *testing.T) {
	t.Parallel()

	var hopData HopData
	hopData.ExtraBytes[1] = (1 << 8) - 1

	var eobData ExtraHopData
	err := eobData.UnpackFullHop(&hopData)
	if err != nil {
		t.Fatalf("should have unpacked available bytes: %v", err)
	}
}

func init() {
	rand.Seed(int64(time.Now().Unix()))
}
