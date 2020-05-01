package sphinx

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/davecgh/go-spew/spew"
)

// BOLT 4 Test Vectors
var (
	// bolt4PubKeys are the public keys of the hops used in the route.
	bolt4PubKeys = []string{
		"02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
		"0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
		"027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007",
		"032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
		"02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145",
	}

	// bolt4SessionKey is the session private key.
	bolt4SessionKey = bytes.Repeat([]byte{'A'}, 32)

	// bolt4AssocData is the associated data added to the packet.
	bolt4AssocData = bytes.Repeat([]byte{'B'}, 32)

	// bolt4FinalPacketHex encodes the expected sphinx packet as a result of
	// creating a new packet with the above parameters.
	bolt4FinalPacketHex = "0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a71e87f9aab8f6378c6ff744c1f34b393ad28d065b535c1a8668d85d3b34a1b3befd10f7d61ab590531cf08000178a333a347f8b4072e216400406bdf3bf038659793a1f9e7abc789266cc861cabd95818c0fc8efbdfdc14e3f7c2bc7eb8d6a79ef75ce721caad69320c3a469a202f3e468c67eaf7a7cda226d0fd32f7b48084dca885d014698cf05d742557763d9cb743faeae65dcc79dddaecf27fe5942be5380d15e9a1ec866abe044a9ad635778ba61fc0776dc832b39451bd5d35072d2269cf9b040a2a2fba158a0d8085926dc2e44f0c88bf487da56e13ef2d5e676a8589881b4869ed4c7f0218ff8c6c7dd7221d189c65b3b9aaa71a01484b122846c7c7b57e02e679ea8469b70e14fe4f70fee4d87b910cf144be6fe48eef24da475c0b0bcc6565a9f99728426ce2380a9580e2a9442481ceae7679906c30b1a0e21a10f26150e0645ab6edfdab1ce8f8bea7b1dee511c5fd38ac0e702c1c15bb86b52bca1b71e15b96982d262a442024c33ceb7dd8f949063c2e5e613e873250e2f8708bd4e1924abd45f65c2fa5617bfb10ee9e4a42d6b5811acc8029c16274f937dac9e8817c7e579fdb767ffe277f26d413ced06b620ede8362081da21cf67c2ca9d6f15fe5bc05f82f5bb93f8916bad3d63338ca824f3bbc11b57ce94a5fa1bc239533679903d6fec92a8c792fd86e2960188c14f21e399cfd72a50c620e10aefc6249360b463df9a89bf6836f4f26359207b765578e5ed76ae9f31b1cc48324be576e3d8e44d217445dba466f9b6293fdf05448584eb64f61e02903f834518622b7d4732471c6e0e22e22d1f45e31f0509eab39cdea5980a492a1da2aaac55a98a01216cd4bfe7abaa682af0fbff2dfed030ba28f1285df750e4d3477190dd193f8643b61d8ac1c427d590badb1f61a05d480908fbdc7c6f0502dd0c4abb51d725e92f95da2a8facb79881a844e2026911adcc659d1fb20a2fce63787c8bb0d9f6789c4b231c76da81c3f0718eb7156565a081d2be6b4170c0e0bcebddd459f53db2590c974bca0d705c055dee8c629bf854a5d58edc85228499ec6dde80cce4c8910b81b1e9e8b0f43bd39c8d69c3a80672729b7dc952dd9448688b6bd06afc2d2819cda80b66c57b52ccf7ac1a86601410d18d0c732f69de792e0894a9541684ef174de766fd4ce55efea8f53812867be6a391ac865802dbc26d93959df327ec2667c7256aa5a1d3c45a69a6158f285d6c97c3b8eedb09527848500517995a9eae4cd911df531544c77f5a9a2f22313e3eb72ca7a07dba243476bc926992e0d1e58b4a2fc8c7b01e0cad726237933ea319bad7537d39f3ed635d1e6c1d29e97b3d2160a09e30ee2b65ac5bce00996a73c008bcf351cecb97b6833b6d121dcf4644260b2946ea204732ac9954b228f0beaa15071930fd9583dfc466d12b5f0eeeba6dcf23d5ce8ae62ee5796359d97a4a15955c778d868d0ef9991d9f2833b5bb66119c5f8b396fd108baed7906cbb3cc376d13551caed97fece6f42a4c908ee279f1127fda1dd3ee77d8de0a6f3c135fa3f1cffe38591b6738dc97b55f0acc52be9753ce53e64d7e497bb00ca6123758df3b68fad99e35c04389f7514a8e36039f541598a417275e77869989782325a15b5342ac5011ff07af698584b476b35d941a4981eac590a07a092bb50342da5d3341f901aa07964a8d02b623c7b106dd0ae50bfa007a22d46c8772fa55558176602946cb1d11ea5460db7586fb89c6d3bcd3ab6dd20df4a4db63d2e7d52380800ad812b8640887e027e946df96488b47fbc4a4fadaa8beda4abe446fafea5403fae2ef"

	testLegacyRouteNumHops = 20
)

func newTestRoute(numHops int) ([]*Router, *PaymentPath, *[]HopData, *OnionPacket, error) {
	nodes := make([]*Router, numHops)

	// Create numHops random sphinx nodes.
	for i := 0; i < len(nodes); i++ {
		privKey, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("Unable to "+
				"generate random key for sphinx node: %v", err)
		}

		nodes[i] = NewRouter(
			&PrivKeyECDH{PrivKey: privKey}, &chaincfg.MainNetParams,
			NewMemoryReplayLog(),
		)
	}

	// Gather all the pub keys in the path.
	var (
		route PaymentPath
	)
	for i := 0; i < len(nodes); i++ {
		hopData := HopData{
			ForwardAmount: uint64(i),
			OutgoingCltv:  uint32(i),
		}
		copy(hopData.NextAddress[:], bytes.Repeat([]byte{byte(i)}, 8))

		hopPayload, err := NewHopPayload(&hopData, nil)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("unable to "+
				"create new hop payload: %v", err)
		}

		route[i] = OnionHop{
			NodePub:    *nodes[i].onionKey.PubKey(),
			HopPayload: hopPayload,
		}
	}

	// Generate a forwarding message to route to the final node via the
	// generated intermediate nodes above.  Destination should be Hash160,
	// adding padding so parsing still works.
	sessionKey, _ := btcec.PrivKeyFromBytes(
		btcec.S256(), bytes.Repeat([]byte{'A'}, 32),
	)
	fwdMsg, err := NewOnionPacket(
		&route, sessionKey, nil, DeterministicPacketFiller,
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("unable to create "+
			"forwarding message: %#v", err)
	}

	var hopsData []HopData
	for i := 0; i < len(nodes); i++ {
		hopData, err := route[i].HopPayload.HopData()
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("unable to "+
				"gen hop data: %v", err)
		}

		hopsData = append(hopsData, *hopData)
	}

	return nodes, &route, &hopsData, fwdMsg, nil
}

func TestBolt4Packet(t *testing.T) {
	var (
		route    PaymentPath
		hopsData []HopData
	)
	for i, pubKeyHex := range bolt4PubKeys {
		pubKeyBytes, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			t.Fatalf("unable to decode BOLT 4 hex pubkey #%d: %v", i, err)
		}

		pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
		if err != nil {
			t.Fatalf("unable to parse BOLT 4 pubkey #%d: %v", i, err)
		}

		hopData := HopData{
			ForwardAmount: uint64(i),
			OutgoingCltv:  uint32(i),
		}
		copy(hopData.NextAddress[:], bytes.Repeat([]byte{byte(i)}, 8))
		hopsData = append(hopsData, hopData)

		hopPayload, err := NewHopPayload(&hopData, nil)
		if err != nil {
			t.Fatalf("unable to make hop payload: %v", err)
		}

		pubKey.Curve = nil

		route[i] = OnionHop{
			NodePub:    *pubKey,
			HopPayload: hopPayload,
		}
	}

	finalPacket, err := hex.DecodeString(bolt4FinalPacketHex)
	if err != nil {
		t.Fatalf("unable to decode BOLT 4 final onion packet from hex: "+
			"%v", err)
	}

	sessionKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), bolt4SessionKey)
	pkt, err := NewOnionPacket(
		&route, sessionKey, bolt4AssocData, DeterministicPacketFiller,
	)
	if err != nil {
		t.Fatalf("unable to construct onion packet: %v", err)
	}

	var b bytes.Buffer
	if err := pkt.Encode(&b); err != nil {
		t.Fatalf("unable to decode onion packet: %v", err)
	}

	if bytes.Compare(b.Bytes(), finalPacket) != 0 {
		t.Fatalf("final packet does not match expected BOLT 4 packet, "+
			"want: %s, got %s", hex.EncodeToString(finalPacket),
			hex.EncodeToString(b.Bytes()))
	}
}

func TestSphinxCorrectness(t *testing.T) {
	nodes, _, hopDatas, fwdMsg, err := newTestRoute(testLegacyRouteNumHops)
	if err != nil {
		t.Fatalf("unable to create random onion packet: %v", err)
	}

	// Now simulate the message propagating through the mix net eventually
	// reaching the final destination.
	for i := 0; i < len(nodes); i++ {
		// Start each node's ReplayLog and defer shutdown
		nodes[i].log.Start()
		defer nodes[i].log.Stop()

		hop := nodes[i]

		t.Logf("Processing at hop: %v \n", i)
		onionPacket, err := hop.ProcessOnionPacket(fwdMsg, nil, uint32(i)+1)
		if err != nil {
			t.Fatalf("Node %v was unable to process the "+
				"forwarding message: %v", i, err)
		}

		// The hop data for this hop should *exactly* match what was
		// initially used to construct the packet.
		expectedHopData := (*hopDatas)[i]
		if !reflect.DeepEqual(*onionPacket.ForwardingInstructions, expectedHopData) {
			t.Fatalf("hop data doesn't match: expected %v, got %v",
				spew.Sdump(expectedHopData),
				spew.Sdump(onionPacket.ForwardingInstructions))
		}

		// If this is the last hop on the path, the node should
		// recognize that it's the exit node.
		if i == len(nodes)-1 {
			if onionPacket.Action != ExitNode {
				t.Fatalf("Processing error, node %v is the last hop in "+
					"the path, yet it doesn't recognize so", i)
			}

		} else {
			// If this isn't the last node in the path, then the
			// returned action should indicate that there are more
			// hops to go.
			if onionPacket.Action != MoreHops {
				t.Fatalf("Processing error, node %v is not the final"+
					" hop, yet thinks it is.", i)
			}

			// The next hop should have been parsed as node[i+1].
			parsedNextHop := onionPacket.ForwardingInstructions.NextAddress[:]
			expected := bytes.Repeat([]byte{byte(i)}, AddressSize)
			if !bytes.Equal(parsedNextHop, expected) {
				t.Fatalf("Processing error, next hop parsed incorrectly."+
					" next hop should be %v, was instead parsed as %v",
					hex.EncodeToString(nodes[i+1].nodeID[:]),
					hex.EncodeToString(parsedNextHop))
			}

			fwdMsg = onionPacket.NextPacket
		}
	}
}

func TestSphinxSingleHop(t *testing.T) {
	// We'd like to test the proper behavior of the correctness of onion
	// packet processing for "single-hop" payments which bare a full onion
	// packet.
	nodes, _, _, fwdMsg, err := newTestRoute(1)
	if err != nil {
		t.Fatalf("unable to create test route: %v", err)
	}

	// Start the ReplayLog and defer shutdown
	nodes[0].log.Start()
	defer nodes[0].log.Stop()

	// Simulating a direct single-hop payment, send the sphinx packet to
	// the destination node, making it process the packet fully.
	processedPacket, err := nodes[0].ProcessOnionPacket(fwdMsg, nil, 1)
	if err != nil {
		t.Fatalf("unable to process sphinx packet: %v", err)
	}

	// The destination node should detect that the packet is destined for
	// itself.
	if processedPacket.Action != ExitNode {
		t.Fatalf("processed action is correct, is %v should be %v",
			processedPacket.Action, ExitNode)
	}
}

func TestSphinxNodeRelpay(t *testing.T) {
	// We'd like to ensure that the sphinx node itself rejects all replayed
	// packets which share the same shared secret.
	nodes, _, _, fwdMsg, err := newTestRoute(testLegacyRouteNumHops)
	if err != nil {
		t.Fatalf("unable to create test route: %v", err)
	}

	// Start the ReplayLog and defer shutdown
	nodes[0].log.Start()
	defer nodes[0].log.Stop()

	// Allow the node to process the initial packet, this should proceed
	// without any failures.
	if _, err := nodes[0].ProcessOnionPacket(fwdMsg, nil, 1); err != nil {
		t.Fatalf("unable to process sphinx packet: %v", err)
	}

	// Now, force the node to process the packet a second time, this should
	// fail with a detected replay error.
	if _, err := nodes[0].ProcessOnionPacket(fwdMsg, nil, 1); err != ErrReplayedPacket {
		t.Fatalf("sphinx packet replay should be rejected, instead error is %v", err)
	}
}

func TestSphinxNodeRelpaySameBatch(t *testing.T) {
	// We'd like to ensure that the sphinx node itself rejects all replayed
	// packets which share the same shared secret.
	nodes, _, _, fwdMsg, err := newTestRoute(testLegacyRouteNumHops)
	if err != nil {
		t.Fatalf("unable to create test route: %v", err)
	}

	// Start the ReplayLog and defer shutdown
	nodes[0].log.Start()
	defer nodes[0].log.Stop()

	tx := nodes[0].BeginTxn([]byte("0"), 2)

	// Allow the node to process the initial packet, this should proceed
	// without any failures.
	if err := tx.ProcessOnionPacket(0, fwdMsg, nil, 1); err != nil {
		t.Fatalf("unable to process sphinx packet: %v", err)
	}

	// Now, force the node to process the packet a second time, this call
	// should not fail, even though the batch has internally recorded this
	// as a duplicate.
	err = tx.ProcessOnionPacket(1, fwdMsg, nil, 1)
	if err != nil {
		t.Fatalf("adding duplicate sphinx packet to batch should not "+
			"result in an error, instead got: %v", err)
	}

	// Commit the batch to disk, then we will inspect the replay set to
	// ensure the duplicate entry was properly included.
	_, replaySet, err := tx.Commit()
	if err != nil {
		t.Fatalf("unable to commit batch of sphinx packets: %v", err)
	}

	if replaySet.Contains(0) {
		t.Fatalf("index 0 was not expected to be in replay set")
	}

	if !replaySet.Contains(1) {
		t.Fatalf("expected replay set to contain duplicate packet " +
			"at index 1")
	}
}

func TestSphinxNodeRelpayLaterBatch(t *testing.T) {
	// We'd like to ensure that the sphinx node itself rejects all replayed
	// packets which share the same shared secret.
	nodes, _, _, fwdMsg, err := newTestRoute(testLegacyRouteNumHops)
	if err != nil {
		t.Fatalf("unable to create test route: %v", err)
	}

	// Start the ReplayLog and defer shutdown
	nodes[0].log.Start()
	defer nodes[0].log.Stop()

	tx := nodes[0].BeginTxn([]byte("0"), 1)

	// Allow the node to process the initial packet, this should proceed
	// without any failures.
	if err := tx.ProcessOnionPacket(uint16(0), fwdMsg, nil, 1); err != nil {
		t.Fatalf("unable to process sphinx packet: %v", err)
	}

	_, _, err = tx.Commit()
	if err != nil {
		t.Fatalf("unable to commit sphinx batch: %v", err)
	}

	tx2 := nodes[0].BeginTxn([]byte("1"), 1)

	// Now, force the node to process the packet a second time, this should
	// fail with a detected replay error.
	err = tx2.ProcessOnionPacket(uint16(0), fwdMsg, nil, 1)
	if err != nil {
		t.Fatalf("sphinx packet replay should not have been rejected, "+
			"instead error is %v", err)
	}

	_, replays, err := tx2.Commit()
	if err != nil {
		t.Fatalf("unable to commit second sphinx batch: %v", err)
	}

	if !replays.Contains(0) {
		t.Fatalf("expected replay set to contain index: %v", 0)
	}
}

func TestSphinxNodeReplayBatchIdempotency(t *testing.T) {
	// We'd like to ensure that the sphinx node itself rejects all replayed
	// packets which share the same shared secret.
	nodes, _, _, fwdMsg, err := newTestRoute(testLegacyRouteNumHops)
	if err != nil {
		t.Fatalf("unable to create test route: %v", err)
	}

	// Start the ReplayLog and defer shutdown
	nodes[0].log.Start()
	defer nodes[0].log.Stop()

	tx := nodes[0].BeginTxn([]byte("0"), 1)

	// Allow the node to process the initial packet, this should proceed
	// without any failures.
	if err := tx.ProcessOnionPacket(uint16(0), fwdMsg, nil, 1); err != nil {
		t.Fatalf("unable to process sphinx packet: %v", err)
	}

	packets, replays, err := tx.Commit()
	if err != nil {
		t.Fatalf("unable to commit sphinx batch: %v", err)
	}

	tx2 := nodes[0].BeginTxn([]byte("0"), 1)

	// Now, force the node to process the packet a second time, this should
	// not fail with a detected replay error.
	err = tx2.ProcessOnionPacket(uint16(0), fwdMsg, nil, 1)
	if err != nil {
		t.Fatalf("sphinx packet replay should not have been rejected, "+
			"instead error is %v", err)
	}

	packets2, replays2, err := tx2.Commit()
	if err != nil {
		t.Fatalf("unable to commit second sphinx batch: %v", err)
	}

	if replays.Size() != replays2.Size() {
		t.Fatalf("expected replay set to be %v, instead got %v",
			replays, replays2)
	}

	if !reflect.DeepEqual(packets, packets2) {
		t.Fatalf("expected packets to be %v, instead go %v",
			packets, packets2)
	}
}

func TestSphinxAssocData(t *testing.T) {
	// We want to make sure that the associated data is considered in the
	// HMAC creation
	nodes, _, _, fwdMsg, err := newTestRoute(5)
	if err != nil {
		t.Fatalf("unable to create random onion packet: %v", err)
	}

	// Start the ReplayLog and defer shutdown
	nodes[0].log.Start()
	defer nodes[0].log.Stop()

	_, err = nodes[0].ProcessOnionPacket(fwdMsg, []byte("somethingelse"), 1)
	if err == nil {
		t.Fatalf("we should fail when associated data changes")
	}

}

func TestSphinxEncodeDecode(t *testing.T) {
	// Create some test data with a randomly populated, yet valid onion
	// forwarding message.
	_, _, _, fwdMsg, err := newTestRoute(5)
	if err != nil {
		t.Fatalf("unable to create random onion packet: %v", err)
	}

	// Encode the created onion packet into an empty buffer. This should
	// succeeed without any errors.
	var b bytes.Buffer
	if err := fwdMsg.Encode(&b); err != nil {
		t.Fatalf("unable to encode message: %v", err)
	}

	// Now decode the bytes encoded above. Again, this should succeeed
	// without any errors.
	newFwdMsg := &OnionPacket{}
	if err := newFwdMsg.Decode(&b); err != nil {
		t.Fatalf("unable to decode message: %v", err)
	}

	// The two forwarding messages should now be identical.
	if !reflect.DeepEqual(fwdMsg, newFwdMsg) {
		t.Fatalf("forwarding messages don't match, %v vs %v",
			spew.Sdump(fwdMsg), spew.Sdump(newFwdMsg))
	}
}

func newEOBRoute(numHops uint32,
	eobMapping map[int]HopPayload) (*OnionPacket, []*Router, error) {

	nodes := make([]*Router, numHops)

	if uint32(len(eobMapping)) != numHops {
		return nil, nil, fmt.Errorf("must provide payload " +
			"mapping for all hops")
	}

	// First, we'll assemble a set of routers that will consume all the
	// hops we create in this path.
	for i := 0; i < len(nodes); i++ {
		privKey, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to generate "+
				"random key for sphinx node: %v", err)
		}

		nodes[i] = NewRouter(
			&PrivKeyECDH{PrivKey: privKey}, &chaincfg.MainNetParams,
			NewMemoryReplayLog(),
		)
	}

	// Next we'll gather all the pubkeys in the path, checking our eob
	// mapping to see which hops need an extra payload.
	var (
		route PaymentPath
	)
	for i := 0; i < len(nodes); i++ {
		route[i] = OnionHop{
			NodePub:    *nodes[i].onionKey.PubKey(),
			HopPayload: eobMapping[i],
		}
	}

	// Generate a forwarding message to route to the final node via the
	// generated intermediate nodes above.  Destination should be Hash160,
	// adding padding so parsing still works.
	sessionKey, _ := btcec.PrivKeyFromBytes(
		btcec.S256(), bytes.Repeat([]byte{'A'}, 32),
	)
	fwdMsg, err := NewOnionPacket(
		&route, sessionKey, nil, DeterministicPacketFiller,
	)
	if err != nil {
		return nil, nil, err
	}

	return fwdMsg, nodes, nil
}

func mustNewHopPayload(hopData *HopData, eob []byte) HopPayload {
	payload, err := NewHopPayload(hopData, eob)
	if err != nil {
		panic(err)
	}

	return payload
}

// TestSphinxHopVariableSizedPayloads tests that we're able to fully decode an
// EOB payload that was targeted at the final hop in a route, and also when
// intermediate nodes have EOB data encoded as well. Additionally, we test that
// we're able to mix the legacy and current format within the same route.
func TestSphinxHopVariableSizedPayloads(t *testing.T) {
	t.Parallel()

	var testCases = []struct {
		numNodes      uint32
		eobMapping    map[int]HopPayload
		expectedError error
	}{
		// A single hop route with a payload going to the last hop in
		// the route. The payload is enough to fit into what would be
		// the normal frame type, but it's a TLV hop.
		{
			numNodes: 1,
			eobMapping: map[int]HopPayload{
				0: HopPayload{
					Type:    PayloadTLV,
					Payload: bytes.Repeat([]byte("a"), LegacyHopDataSize-HMACSize),
				},
			},
		},

		// A single hop route where the payload to the final node needs
		// to shift more than a single frame.
		{
			numNodes: 1,
			eobMapping: map[int]HopPayload{
				0: HopPayload{
					Type:    PayloadTLV,
					Payload: bytes.Repeat([]byte("a"), LegacyHopDataSize*3),
				},
			},
		},

		// A two hop route, so one going over 3 nodes, with the sender
		// encrypting a payload to the final node. The payload of the
		// final node will require more shifts than normal to parse the
		// data The first hop is a legacy hop containing the usual
		// amount of data.
		{
			numNodes: 2,
			eobMapping: map[int]HopPayload{
				0: mustNewHopPayload(&HopData{
					Realm:         [1]byte{0x00},
					ForwardAmount: 2,
					OutgoingCltv:  3,
					NextAddress:   [8]byte{1, 1, 1, 1, 1, 1, 1, 1},
				}, nil),
				1: HopPayload{
					Type:    PayloadTLV,
					Payload: bytes.Repeat([]byte("a"), LegacyHopDataSize*2),
				},
			},
		},

		// A 3 hop route (4 nodes) with all but the middle node
		// receiving a TLV payload. Each of the TLV hops will use a
		// distinct amount of data in each hop.
		{
			numNodes: 3,
			eobMapping: map[int]HopPayload{
				0: HopPayload{
					Type:    PayloadTLV,
					Payload: bytes.Repeat([]byte("a"), 100),
				},
				1: mustNewHopPayload(&HopData{
					Realm:         [1]byte{0x00},
					ForwardAmount: 22,
					OutgoingCltv:  9,
					NextAddress:   [8]byte{1, 1, 1, 1, 1, 1, 1, 1},
				}, nil),
				2: HopPayload{
					Type:    PayloadTLV,
					Payload: bytes.Repeat([]byte("a"), 256),
				},
			},
		},

		// A 3 hop route (4 nodes), each hop is a TLV hop and will use
		// a distinct amount of data for each of their hops.
		{
			numNodes: 3,
			eobMapping: map[int]HopPayload{
				0: HopPayload{
					Type:    PayloadTLV,
					Payload: bytes.Repeat([]byte("a"), 200),
				},
				1: HopPayload{
					Type:    PayloadTLV,
					Payload: bytes.Repeat([]byte("a"), 256),
				},
				2: HopPayload{
					Type:    PayloadTLV,
					Payload: bytes.Repeat([]byte("a"), 150),
				},
			},
		},

		// A 3 hop route (4 nodes) that carries more data then what fits
		// in the routing info.
		{
			numNodes: 3,
			eobMapping: map[int]HopPayload{
				0: HopPayload{
					Type:    PayloadTLV,
					Payload: bytes.Repeat([]byte("a"), 500),
				},
				1: HopPayload{
					Type:    PayloadTLV,
					Payload: bytes.Repeat([]byte("a"), 500),
				},
				2: HopPayload{
					Type:    PayloadTLV,
					Payload: bytes.Repeat([]byte("a"), 500),
				},
			},
			expectedError: ErrMaxRoutingInfoSizeExceeded,
		},
	}

	for testCaseNum, testCase := range testCases {
		nextPkt, routers, err := newEOBRoute(
			testCase.numNodes, testCase.eobMapping,
		)
		if testCase.expectedError != err {
			t.Fatalf("#%v: unable to create eob "+
				"route: %v", testCase, err)
		}
		if err != nil {
			continue
		}

		// We'll now walk thru manually each actual hop within the
		// route. We use the size of the routers rather than the number
		// of hops here as virtual EOB hops may have been inserted into
		// the route.
		for i := 0; i < len(routers); i++ {
			// Start each node's ReplayLog and defer shutdown
			routers[i].log.Start()
			defer routers[i].log.Stop()

			currentHop := routers[i]

			// Ensure that this hop is able to properly process
			// this onion packet. If additional EOB hops were
			// added, then it should be able to properly decrypt
			// all the layers and pass them on to the next node
			// properly.
			processedPacket, err := currentHop.ProcessOnionPacket(
				nextPkt, nil, uint32(i),
			)
			if err != nil {
				t.Fatalf("#%v: unable to process packet at "+
					"hop #%v: %v", testCaseNum, i, err)
			}

			// If this hop is expected to have EOB data, then we'll
			// check now to ensure the bytes were properly
			// recovered on the other end.
			eobData := testCase.eobMapping[i]
			if !reflect.DeepEqual(eobData.Payload,
				processedPacket.Payload.Payload) {
				t.Fatalf("#%v (hop %v): eob mismatch: expected "+
					"%v, got %v", testCaseNum, i,
					spew.Sdump(eobData.Payload),
					spew.Sdump(processedPacket.Payload.Payload))
			}

			if eobData.Type != processedPacket.Payload.Type {
				t.Fatalf("mismatched types: expected %v "+
					"got %v", eobData.Type,
					processedPacket.Payload.Type)
			}

			// If this is the last node (but not necessarily hop
			// due to EOB expansion), then it should recognize that
			// it's the exit node.
			if i == len(routers)-1 {
				if processedPacket.Action != ExitNode {
					t.Fatalf("#%v: Processing error, "+
						"node %v is the last hop in "+
						"the path, yet it doesn't "+
						"recognize so", testCaseNum, i)
				}
				continue
			}

			// If this isn't the last node in the path, then the
			// returned action should indicate that there are more
			// hops to go.
			if processedPacket.Action != MoreHops {
				t.Fatalf("#%v: Processing error, node %v is "+
					"not the final hop, yet thinks it is.",
					testCaseNum, i)
			}

			// The next hop should have been parsed as node[i+1],
			// but only if this was a legacy hop.
			if processedPacket.ForwardingInstructions != nil {
				parsedNextHop := processedPacket.ForwardingInstructions.NextAddress[:]

				expected := bytes.Repeat([]byte{byte(1)}, AddressSize)
				if !bytes.Equal(parsedNextHop, expected) {
					t.Fatalf("#%v: Processing error, next hop parsed "+
						"incorrectly. next hop should be %v, "+
						"was instead parsed as %v", testCaseNum,
						hex.EncodeToString(expected),
						hex.EncodeToString(parsedNextHop))
				}
			}

			nextPkt = processedPacket.NextPacket
		}
	}
}

// testFileName is the name of the multi-frame onion test file.
const testFileName = "testdata/onion-test-multi-frame.json"

type jsonHop struct {
	Type string `json:"type"`

	Pubkey string `json:"pubkey"`

	Payload string `json:"payload"`
}

type payloadTestCase struct {
	SessionKey string `json:"session_key"`

	AssociatedData string `json:"associated_data"`

	Hops []jsonHop `json:"hops"`
}

type jsonTestCase struct {
	Comment string `json:"comment"`

	Generate payloadTestCase `json:"generate"`

	Onion string `json:"onion"`

	Decode []string `json:"decode"`
}

// jsonTypeToPayloadType maps the JSON payload type to our concrete PayloadType
// type.
func jsonTypeToPayloadType(jsonType string) PayloadType {
	switch jsonType {
	case "raw":
		fallthrough
	case "tlv":
		return PayloadTLV

	case "legacy":
		return PayloadLegacy

	default:
		panic(fmt.Sprintf("unknown payload type: %v", jsonType))
	}
}

// TestVariablePayloadOnion tests that if we construct a packet that contains a
// mix of the old and new payload format, that we match the version that's
// included in the spec.
func TestVariablePayloadOnion(t *testing.T) {
	t.Parallel()

	// First, we'll read out the raw JSOn file at the target location.
	jsonBytes, err := ioutil.ReadFile(testFileName)
	if err != nil {
		t.Fatalf("unable to read json file: %v", err)
	}

	// Once we have the raw file, we'll unpack it into our jsonTestCase
	// struct defined above.
	testCase := &jsonTestCase{}
	if err := json.Unmarshal(jsonBytes, testCase); err != nil {
		t.Fatalf("unable to parse spec json file: %v", err)
	}

	// Next, we'll populate a new OnionHop using the information included
	// in this test case.
	var route PaymentPath
	for i, hop := range testCase.Generate.Hops {
		pubKeyBytes, err := hex.DecodeString(hop.Pubkey)
		if err != nil {
			t.Fatalf("unable to decode pubkey: %v", err)
		}
		pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
		if err != nil {
			t.Fatalf("unable to parse BOLT 4 pubkey #%d: %v", i, err)
		}

		payload, err := hex.DecodeString(hop.Payload)
		if err != nil {
			t.Fatalf("unable to decode payload: %v", err)
		}

		payloadType := jsonTypeToPayloadType(hop.Type)
		route[i] = OnionHop{
			NodePub: *pubKey,
			HopPayload: HopPayload{
				Type:    payloadType,
				Payload: payload,
			},
		}

		if payloadType == PayloadLegacy {
			route[i].HopPayload.Payload = append(
				[]byte{0x00}, route[i].HopPayload.Payload...,
			)

			route[i].HopPayload.Payload = append(
				route[i].HopPayload.Payload,
				bytes.Repeat([]byte{0x00}, NumPaddingBytes)...,
			)
		}
	}

	finalPacket, err := hex.DecodeString(testCase.Onion)
	if err != nil {
		t.Fatalf("unable to decode packet: %v", err)
	}

	sessionKeyBytes, err := hex.DecodeString(testCase.Generate.SessionKey)
	if err != nil {
		t.Fatalf("unable to generate session key: %v", err)
	}

	associatedData, err := hex.DecodeString(testCase.Generate.AssociatedData)
	if err != nil {
		t.Fatalf("unable to decode AD: %v", err)
	}

	// With all the required data assembled, we'll craft a new packet.
	sessionKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), sessionKeyBytes)
	pkt, err := NewOnionPacket(
		&route, sessionKey, associatedData, DeterministicPacketFiller,
	)
	if err != nil {
		t.Fatalf("unable to construct onion packet: %v", err)
	}

	var b bytes.Buffer
	if err := pkt.Encode(&b); err != nil {
		t.Fatalf("unable to decode onion packet: %v", err)
	}

	// Finally, we expect that our packet matches the packet included in
	// the spec's test vectors.
	if bytes.Compare(b.Bytes(), finalPacket) != 0 {
		t.Fatalf("final packet does not match expected BOLT 4 packet, "+
			"want: %s, got %s", hex.EncodeToString(finalPacket),
			hex.EncodeToString(b.Bytes()))
	}
}
