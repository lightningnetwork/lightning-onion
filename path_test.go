package sphinx

import (
	"bytes"
	"testing"
)

func TestHopPayloadSizes(t *testing.T) {
	var tests = []struct {
		size     int
		expected int
		realm    byte
	}{
		{30, 1, 0x01},
		{32, 1, 0x01},
		{33, 2, 0x11},
		{97, 2, 0x11}, // The largest possible 2-hop payload
		{98, 3, 0x21},
		{162, 3, 0x21},
		{163, 4, 0x31},
	}

	for _, tt := range tests {
		hp := HopPayload{
			Realm:   [1]byte{1},
			Payload: bytes.Repeat([]byte{0x00}, tt.size),
		}

		actual := hp.CountFrames()
		if actual != tt.expected {
			t.Errorf("Wrong number of hops returned: expected %d, actual %d", tt.expected, actual)
		}

		hp.CalculateRealm()
		if hp.Realm[0] != tt.realm {
			t.Errorf("Updated realm did not match our expectation: expected %q, actual %q", tt.realm, hp.Realm)
		}
	}
}
