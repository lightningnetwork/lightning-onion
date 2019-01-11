package sphinx

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
)

func randPubKey(t *testing.T, r io.Reader) btcec.PublicKey {
	t.Helper()

	var randPriv [32]byte
	if _, err := io.ReadFull(r, randPriv[:]); err != nil {
		t.Fatalf("unable to create rand pubkey: %v", err)
	}

	_, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), randPriv[:])
	pubKey.Curve = nil

	return *pubKey
}

func makePath(t *testing.T, r io.Reader, blobs [][]byte) PaymentPath {
	var path PaymentPath

	for i, blob := range blobs {
		path[i].NodePub = randPubKey(t, r)
		path[i].ExtraData = ExtraHopData{
			ExtraOnionBlob: blob,
		}
	}

	return path
}

// TestValidatePayloadSanity tests that we'll properly reject paths that aren't
// well formed.
func TestValidatePayloadSanity(t *testing.T) {
	t.Parallel()

	rReader := rand.New(rand.NewSource(int64(time.Now().Unix())))

	var testCases = []struct {
		path  PaymentPath
		valid bool
	}{
		// An empty path is fine.
		{
			valid: true,
		},

		// A path with a single hop that has data below the max number
		// of bytes we can encode is sane.
		{
			path:  makePath(t, rReader, [][]byte{bytes.Repeat([]byte("a"), 100)}),
			valid: true,
		},

		// A path with many hops (some empty), that sum up to right
		// below the max number of bytes we can encode is sane.
		{
			path: makePath(
				t, rReader, [][]byte{
					bytes.Repeat([]byte("b"), 100),
					[]byte{}, bytes.Repeat([]byte("b"), 100),
				},
			),
			valid: true,
		},

		// A path with many hops that collectively exceed the max
		// number of hops is not valid.
		{
			path: makePath(
				t, rReader,
				[][]byte{
					bytes.Repeat([]byte("b"), MaxExtraOnionBlob-1),
					[]byte{}, bytes.Repeat([]byte("b"), 100),
				},
			),
			valid: false,
		},
	}

	for i, testCase := range testCases {
		err := testCase.path.ValidatePayloadSanity()
		switch {
		case err != nil && testCase.valid:
			t.Fatalf("#%v: valid path mistaken as invalid", i)

		case err == nil && !testCase.valid:
			t.Fatalf("#%v: invalid path mistaken as valid", i)
		}
	}
}

// TestTotalExtraDataSize tests that we properly compute the total extra data
// size for a given path.
func TestTotalExtraDataSize(t *testing.T) {
	t.Parallel()

	rReader := rand.New(rand.NewSource(int64(time.Now().Unix())))

	var testCases = []struct {
		path PaymentPath
		size uint32
	}{
		// No hops so the size should be zero.
		{
			size: 0,
		},

		// Single hop with EOB bytes.
		{
			size: 200,
			path: makePath(
				t, rReader, [][]byte{bytes.Repeat([]byte("a"), 200)},
			),
		},

		// Multiple hops, each having some EOB bytes.
		{
			path: makePath(
				t, rReader, [][]byte{bytes.Repeat([]byte("a"), 25),
					bytes.Repeat([]byte("a"), 25)},
			),
			size: 50,
		},
	}

	for i, testCase := range testCases {
		totalBytes := testCase.path.TotalExtraDataSize()
		if totalBytes != testCase.size {
			t.Fatalf("#%v incorrect size: expected %v, got %v",
				i, totalBytes, testCase.size)
		}
	}
}

// TestHasExtraData tests that we properly detect if a path has any EOBs.
func TestHasExtraData(t *testing.T) {
	t.Parallel()

	rReader := rand.New(rand.NewSource(int64(time.Now().Unix())))

	var testCases = []struct {
		path   PaymentPath
		hasEOB bool
	}{
		// A path with two hops, both of which don't have EOB data
		// shouldn't be picked up.
		{
			hasEOB: false,
			path:   makePath(t, rReader, [][]byte{[]byte{}, []byte{}}),
		},

		// A path with a single hop, having EOB data should be picked
		// up.
		{
			hasEOB: true,
			path:   makePath(t, rReader, [][]byte{[]byte("data")}),
		},
	}

	for i, testCase := range testCases {
		hasData := testCase.path.HasExtraData()
		if hasData != testCase.hasEOB {
			t.Fatalf("#%v: eob mismatch: expected %v, got %v", i,
				testCase.hasEOB, hasData)
		}
	}
}

// TestUnrollExtraDataHops tests that we're able to fully unroll a path that
// has hops which need EOB data into a longer path with the EOB data encoded in
// the hop data fields of certain hops.
func TestUnrollExtraDataHops(t *testing.T) {
	t.Parallel()

	rReader := rand.New(rand.NewSource(int64(time.Now().Unix())))

	var testCases = []struct {
		rolledPath         PaymentPath
		unrolledPathLength uint32
		fail               bool
	}{
		// A path that has more data that we can possibly pack into 20
		// bytes shop fail.
		{
			rolledPath: makePath(
				t, rReader, [][]byte{
					bytes.Repeat([]byte("a"), MaxExtraOnionBlob/2),
					bytes.Repeat([]byte("a"), MaxExtraOnionBlob),
					bytes.Repeat([]byte("a"), MaxExtraOnionBlob),
				},
			),
			fail: true,
		},

		// A path with no EOB data shouldn't be expanded at all.
		{
			rolledPath: makePath(t, rReader, [][]byte{
				[]byte{}, []byte{},
			}),
			unrolledPathLength: 2,
		},

		// A path with EOB data that can fit into the pivot hop
		// shouldn't be expanded at all.
		{
			rolledPath: makePath(
				t, rReader, [][]byte{
					bytes.Repeat([]byte{0x9}, PivotHopDataSize),
					[]byte{}, []byte{},
				},
			),
			unrolledPathLength: 3,
		},

		// A path with EOB data that needs to _one_ additional hop
		// should be expanded accordingly.
		{
			rolledPath: makePath(
				t, rReader, [][]byte{
					bytes.Repeat([]byte{0x9}, PivotHopDataSize+1),
					[]byte{}, []byte{},
				},
			),
			unrolledPathLength: 4,
		},

		// A case of hop expansion that takes place at the final hop.
		{
			rolledPath: makePath(
				t, rReader,
				[][]byte{
					bytes.Repeat([]byte{0x9}, UnrolledHopDataSize*3),
				},
			),
			// We expand to 4 hops total as we can fit 10 bytes into
			// the first hop, and then need 3 hop (32 bytes each) to
			// encode the remaining 86 bytes.
			unrolledPathLength: 4,
		},

		// A case of hop expansion that takes place at each hop.
		{
			rolledPath: makePath(
				t, rReader,
				[][]byte{
					bytes.Repeat([]byte{0x9}, UnrolledHopDataSize),
					bytes.Repeat([]byte{0x9}, UnrolledHopDataSize),
					bytes.Repeat([]byte{0x9}, UnrolledHopDataSize),
				},
			),
			// Each hop needs an additional hop, and there are 3 of
			// them, so we should unroll into 6 hops.
			unrolledPathLength: 6,
		},
	}

	for i, testCase := range testCases {
		unrolledPath, err := testCase.rolledPath.UnrollExtraDataHops()
		switch {
		case err == nil && testCase.fail:
			t.Fatalf("#%v: should have failed to unroll but "+
				"didn't", i)

		case err != nil && !testCase.fail:
			t.Fatalf("#%v: unable to unroll path: %v", i, err)
		}

		if err != nil {
			continue
		}

		// Ensure that the path was expanded accordingly.
		if uint32(unrolledPath.TrueRouteLength()) !=
			testCase.unrolledPathLength {

			t.Fatalf("#%v: incorrect path expansion: expected len "+
				"%v got %v", i, testCase.unrolledPathLength,
				unrolledPath.TrueRouteLength())
		}
	}
}
