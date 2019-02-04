package sphinx

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec"
)

var (
	s *OnionPacket
	p *ProcessedPacket
)

func BenchmarkPathPacketConstruction(b *testing.B) {
	b.StopTimer()
	route := make([]*btcec.PublicKey, NumMaxHops)
	for i := 0; i < NumMaxHops; i++ {
		privKey, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			b.Fatalf("unable to generate key: %v", privKey)
		}

		route[i] = privKey.PubKey()
	}

	var (
		err          error
		sphinxPacket *OnionPacket
	)

	var hopsData []HopData
	for i := 0; i < len(route); i++ {
		hopsData = append(hopsData, HopData{
			Realm:         0x00,
			ForwardAmount: uint64(i),
			OutgoingCltv:  uint32(i),
		})
		copy(hopsData[i].NextAddress[:], bytes.Repeat([]byte{byte(i)}, 8))
	}

	d, _ := btcec.PrivKeyFromBytes(btcec.S256(), bytes.Repeat([]byte{'A'}, 32))
	b.ReportAllocs()
	b.StartTimer()

	path, err := NewPaymentPath(route, hopsData)
	if err != nil {
		b.Fatalf("unable to create payment path: %v", err)
	}

	for i := 0; i < b.N; i++ {
		sphinxPacket, err = NewOnionPacket(path, d, nil)
		if err != nil {
			b.Fatalf("unable to create packet: %v", err)
		}
	}

	s = sphinxPacket
}

func BenchmarkProcessPacket(b *testing.B) {
	b.StopTimer()
	_, nodes, sphinxPacket, err := newTestRoute(1)
	if err != nil {
		b.Fatalf("unable to create test route: %v", err)
	}
	b.ReportAllocs()
	nodes[0].log.Start()
	defer nodes[0].log.Stop()
	b.StartTimer()

	var (
		pkt *ProcessedPacket
	)
	for i := 0; i < b.N; i++ {
		pkt, err = nodes[0].ProcessOnionPacket(sphinxPacket, nil, uint32(i))
		if err != nil {
			b.Fatalf("unable to process packet %d: %v", i, err)
		}

		b.StopTimer()
		router := nodes[0]
		router.log.Stop()
		nodes[0] = &Router{
			nodeID:   router.nodeID,
			nodeAddr: router.nodeAddr,
			onionKey: router.onionKey,
			log:      NewMemoryReplayLog(),
		}
		nodes[0].log.Start()
		b.StartTimer()
	}

	p = pkt
}
