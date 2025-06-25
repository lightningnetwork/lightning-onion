package sphinx

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

const (
	routeBlindingTestFileName            = "testdata/route-blinding-test.json"
	onionRouteBlindingTestFileName       = "testdata/onion-route-blinding-test.json"
	blindedOnionMessageOnionTestFileName = "testdata/blinded-onion-message-onion-test.json"
)

var (
	// bolt4PubKeys contains the public keys used in the Bolt 4 spec test
	// vectors. We convert them variables named after the commonly used
	// names in cryptography.
	alicePubKey = bolt4PubKeys[0]
	bobPubKey   = bolt4PubKeys[1]
)

// TestBuildBlindedRoute tests BuildBlindedRoute and decryptBlindedHopData against
// the spec test vectors.
func TestBuildBlindedRoute(t *testing.T) {
	t.Parallel()

	// First, we'll read out the raw Json file at the target location.
	jsonBytes, err := os.ReadFile(routeBlindingTestFileName)
	require.NoError(t, err)

	// Once we have the raw file, we'll unpack it into our
	// blindingJsonTestCase struct defined below.
	testCase := &blindingJsonTestCase{}
	require.NoError(t, json.Unmarshal(jsonBytes, testCase))
	require.Len(t, testCase.Generate.Hops, 4)

	// buildPaymentPath is a helper closure used to convert hopData objects
	// into BlindedPathHop objects.
	buildPaymentPath := func(h []hopData) []*HopInfo {
		path := make([]*HopInfo, len(h))
		for i, hop := range h {
			nodeIDStr, _ := hex.DecodeString(hop.NodeID)
			nodeID, _ := btcec.ParsePubKey(nodeIDStr)
			payload, _ := hex.DecodeString(hop.EncodedTLVs)

			path[i] = &HopInfo{
				NodePub:   nodeID,
				PlainText: payload,
			}
		}
		return path
	}

	// First, Eve will build a blinded path from Dave to herself.
	eveSessKey := privKeyFromString(testCase.Generate.Hops[2].SessionKey)
	eveDavePath := buildPaymentPath(testCase.Generate.Hops[2:])
	pathED, err := BuildBlindedPath(eveSessKey, eveDavePath)
	require.NoError(t, err)

	// At this point, Eve will give her blinded path to Bob who will then
	// build his own blinded route from himself to Carol. He will then
	// concatenate the two paths. Note that in his TLV for Carol, Bob will
	// add the `next_blinding_override` field which he will set to the
	// first blinding point in Eve's blinded route. This will indicate to
	// Carol that she should use this point for the next blinding key
	// instead of the next blinding key that she derives.
	bobCarolPath := buildPaymentPath(testCase.Generate.Hops[:2])
	bobSessKey := privKeyFromString(testCase.Generate.Hops[0].SessionKey)
	pathBC, err := BuildBlindedPath(bobSessKey, bobCarolPath)
	require.NoError(t, err)

	// Construct the concatenated path.
	path := &BlindedPath{
		IntroductionPoint: pathBC.Path.IntroductionPoint,
		BlindingPoint:     pathBC.Path.BlindingPoint,
		BlindedHops: append(pathBC.Path.BlindedHops,
			pathED.Path.BlindedHops...),
	}

	// Check that the constructed path is equal to the test vector path.
	require.True(t, equalPubKeys(
		testCase.Route.IntroductionNodeID, path.IntroductionPoint,
	))
	require.True(t, equalPubKeys(
		testCase.Route.Blinding, path.BlindingPoint,
	))

	for i, hop := range testCase.Route.Hops {
		require.True(t, equalPubKeys(
			hop.BlindedNodeID, path.BlindedHops[i].BlindedNodePub,
		))

		data, _ := hex.DecodeString(hop.EncryptedData)
		require.True(
			t, bytes.Equal(data, path.BlindedHops[i].CipherText),
		)
	}

	// Assert that each hop is able to decode the encrypted data meant for
	// it.
	for i, hop := range testCase.Unblind.Hops {
		priv := privKeyFromString(hop.NodePrivKey)
		ephem := pubKeyFromString(hop.EphemeralPubKey)

		data, err := decryptBlindedHopData(
			&PrivKeyECDH{PrivKey: priv}, ephem,
			path.BlindedHops[i].CipherText,
		)
		require.NoError(t, err)

		decoded, _ := hex.DecodeString(hop.DecryptedData)
		require.True(t, bytes.Equal(data, decoded))

		nextEphem, err := NextEphemeral(&PrivKeyECDH{priv}, ephem)
		require.NoError(t, err)

		require.True(t, equalPubKeys(
			hop.NextEphemeralPubKey, nextEphem,
		))
	}
}

// TestBuildOnionMessageBlindedRoute tests the construction of a blinded route
// for an onion message, specifically the concatenation of two blinded paths,
// against the spec test vectors in `blinded-onion-message-onion-test.json`. It
// verifies the correctness of BuildBlindedPath, decryptBlindedHopData, and
// NextEphemeral.
//
// The test setup involves several parties and two distinct blinded paths that
// are combined to form the full route:
//
//  1. Path from Dave: Dave (the receiver) first constructs a blinded path for a
//     message to be sent from Bob to himself (Dave).
//     The path is: Bob -> Carol -> Dave
//
//  2. Path from Sender: Dave gives his blinded path to a Sender. The Sender
//     then creates their own blinded path from themselves to Bob, passing
//     through Alice. The path is: Sender -> Alice -> Bob
//
//  3. Path Concatenation: The Sender prepends their path to Dave's path,
//     creating a final, concatenated route:
//     Sender -> Alice -> Bob -> Carol ->  Dave
//     To link the two paths, the Sender includes a `next_path_key_override`
//     in the payload for Alice. This override is set to the first path key
//     (blinding point) of Dave's path, instructing Alice to use it for the next
//     hop (Bob) instead of the key that she could derive herself.
//
// The test then asserts that the generated concatenated path matches the test
// vector's expected route. Finally, it simulates the decryption process at each
// hop, verifying that each node can correctly decrypt its payload and derive
// the correct next ephemeral key.
func TestBuildOnionMessageBlindedRoute(t *testing.T) {
	t.Parallel()

	// First, we'll read out the raw Json file at the target location.
	jsonBytes, err := os.ReadFile(blindedOnionMessageOnionTestFileName)
	require.NoError(t, err)

	// Once we have the raw file, we'll unpack it into our
	// onionMessageJsonTestCase struct defined below.
	testCase := &onionMessageJsonTestCase{}
	require.NoError(t, json.Unmarshal(jsonBytes, testCase))
	require.Len(t, testCase.Generate.Hops, 4)

	// buildMessagePath is a helper closure used to convert
	// hopOnionMessageData objects into HopInfo objects.
	buildMessagePath := func(h []hopOnionMessageData,
		initialHopID string) []*HopInfo {

		path := make([]*HopInfo, len(h))
		// The json test vector doesn't properly specify the current
		// node id, so we need the initial Node ID as a starting point.
		currentHop := initialHopID
		for i, hop := range h {
			nodeIDStr, err := hex.DecodeString(currentHop)
			require.NoError(t, err)
			nodeID, err := btcec.ParsePubKey(nodeIDStr)
			require.NoError(t, err)
			payload, err := hex.DecodeString(hop.EncryptedDataTlv)
			require.NoError(t, err)

			path[i] = &HopInfo{
				NodePub:   nodeID,
				PlainText: payload,
			}

			// The json test vector doesn't properly specify the
			// current node id. It does specify the next node id. So
			// to get the current node id for the next iteration, we
			// get the next node id here.
			currentHop = hop.EncodedOnionMessageTLVs.NextNodeID
		}
		return path
	}

	// First, Dave will build a blinded path from Bob to itself.
	daveSessKey := privKeyFromString(
		testCase.Generate.Hops[1].PathKeySecret,
	)
	daveBobPath := buildMessagePath(
		testCase.Generate.Hops[1:], bobPubKey,
	)
	daveBobBlindedPath, err := BuildBlindedPath(daveSessKey, daveBobPath)
	require.NoError(t, err)

	// At this point, Dave will give his blinded path to the Sender who will
	// then build its own blinded route from itself to Bob via Alice. The
	// sender will then concatenate the two paths. Note that in the payload
	// for Alice, the `next_path_key_override` field is added which is set
	// to the first path key in Dave's blinded route. This will indicate to
	// Alice that she should use this point for the next path key instead of
	// the next path key that she derives.
	// Path created by Dave: Bob -> Carol -> Dave
	// Path that the Sender will build: Sender -> Alice -> Bob
	aliceBobPath := buildMessagePath(
		testCase.Generate.Hops[:1], alicePubKey,
	)
	senderSessKey := privKeyFromString(
		testCase.Generate.Hops[0].PathKeySecret,
	)
	aliceBobBlindedPath, err := BuildBlindedPath(
		senderSessKey, aliceBobPath,
	)
	require.NoError(t, err)

	// Construct the concatenated path.
	path := &BlindedPath{
		IntroductionPoint: aliceBobBlindedPath.Path.IntroductionPoint,
		BlindingPoint:     aliceBobBlindedPath.Path.BlindingPoint,
		BlindedHops: append(
			aliceBobBlindedPath.Path.BlindedHops,
			daveBobBlindedPath.Path.BlindedHops...,
		),
	}

	// Check that the constructed path is equal to the test vector path.
	require.True(t, equalPubKeys(
		testCase.Route.FirstNodeId, path.IntroductionPoint,
	))
	require.True(t, equalPubKeys(
		testCase.Route.FirstPathKey, path.BlindingPoint,
	))

	for i, hop := range testCase.Route.Hops {
		require.True(t, equalPubKeys(
			hop.BlindedNodeID, path.BlindedHops[i].BlindedNodePub,
		))

		data, _ := hex.DecodeString(hop.EncryptedRecipientData)
		require.Equal(t, data, path.BlindedHops[i].CipherText)
	}

	// Assert that each hop is able to decode the encrypted data meant for
	// it.
	for i, hop := range testCase.Decrypt.Hops {
		genData := testCase.Generate.Hops[i]
		priv := privKeyFromString(hop.PrivKey)
		ephem := pubKeyFromString(genData.EphemeralPubKey)

		// Now we'll decrypt the blinded hop data using the private key
		// and the ephemeral public key.
		data, err := decryptBlindedHopData(
			&PrivKeyECDH{PrivKey: priv}, ephem,
			path.BlindedHops[i].CipherText,
		)
		require.NoError(t, err)

		// Check if the decrypted data is what we expect it to be.
		dataExpected, _ := hex.DecodeString(genData.EncryptedDataTlv)
		require.Equal(t, data, dataExpected)

		nextEphem, err := NextEphemeral(&PrivKeyECDH{priv}, ephem)
		require.NoError(t, err)

		nextE := privKeyFromString(genData.NextEphemeralPrivKey)

		require.Equal(t, nextE.PubKey(), nextEphem)
	}
}

// TestOnionRouteBlinding tests that an onion packet can correctly be processed
// by a node in a blinded route.
func TestOnionRouteBlinding(t *testing.T) {
	t.Parallel()

	// First, we'll read out the raw Json file at the target location.
	jsonBytes, err := os.ReadFile(onionRouteBlindingTestFileName)
	require.NoError(t, err)

	// Once we have the raw file, we'll unpack it into our
	// blindingJsonTestCase struct defined above.
	testCase := &onionBlindingJsonTestCase{}
	require.NoError(t, json.Unmarshal(jsonBytes, testCase))

	assoc, err := hex.DecodeString(testCase.Generate.AssocData)
	require.NoError(t, err)

	// Extract the original onion packet to be processed.
	onion, err := hex.DecodeString(testCase.Generate.Onion)
	require.NoError(t, err)

	onionBytes := bytes.NewReader(onion)
	onionPacket := &OnionPacket{}
	require.NoError(t, onionPacket.Decode(onionBytes))

	// peelOnion is a helper closure that can be used to set up a Router
	// and use it to process the given onion packet.
	peelOnion := func(key *btcec.PrivateKey,
		blindingPoint *btcec.PublicKey) *ProcessedPacket {

		r := NewRouter(
			&PrivKeyECDH{PrivKey: key}, NewMemoryReplayLog(),
		)

		require.NoError(t, r.Start())
		defer r.Stop()

		res, err := r.ProcessOnionPacket(
			onionPacket, assoc, 10,
			WithBlindingPoint(blindingPoint),
		)
		require.NoError(t, err)

		return res
	}

	hops := testCase.Decrypt.Hops
	require.Len(t, hops, 5)

	// There are some things that the processor of the onion packet will
	// only be able to determine from the actual contents of the encrypted
	// data it receives. These things include the next_blinding_point for
	// the introduction point and the next_blinding_override. The decryption
	// of this data is dependent on the encoding chosen by higher layers.
	// The test uses TLVs. Since the extraction of this data is dependent
	// on layers outside the scope of this library, we provide handle these
	// cases manually for the sake of the test.
	var (
		introPointIndex = 2
		firstBlinding   = pubKeyFromString(hops[1].NextBlinding)

		concatIndex      = 3
		blindingOverride = pubKeyFromString(hops[2].NextBlinding)
	)

	var blindingPoint *btcec.PublicKey
	for i, hop := range testCase.Decrypt.Hops {
		buff := bytes.NewBuffer(nil)
		require.NoError(t, onionPacket.Encode(buff))
		require.Equal(t, hop.Onion, hex.EncodeToString(buff.Bytes()))

		priv := privKeyFromString(hop.NodePrivKey)

		if i == introPointIndex {
			blindingPoint = firstBlinding
		} else if i == concatIndex {
			blindingPoint = blindingOverride
		}

		processedPkt := peelOnion(priv, blindingPoint)

		if blindingPoint != nil {
			blindingPoint, err = NextEphemeral(
				&PrivKeyECDH{priv}, blindingPoint,
			)
			require.NoError(t, err)
		}
		onionPacket = processedPkt.NextPacket
	}
}

// TestOnionMessageRouteBlinding tests that an onion message packet can
// correctly be processed by a node in a blinded route.
func TestOnionMessageRouteBlinding(t *testing.T) {
	t.Parallel()

	// First, we'll read out the raw Json file at the target location.
	jsonBytes, err := os.ReadFile(blindedOnionMessageOnionTestFileName)
	require.NoError(t, err)

	// Once we have the raw file, we'll unpack it into our
	// onionMessageJsonTestCase struct defined above.
	testCase := &onionMessageJsonTestCase{}
	require.NoError(t, json.Unmarshal(jsonBytes, testCase))

	// Extract the original onion message packet to be processed.
	onion, err := hex.DecodeString(testCase.OnionMessage.OnionMessagePacket)
	require.NoError(t, err)

	onionBytes := bytes.NewReader(onion)
	onionPacket := &OnionPacket{}
	require.NoError(t, onionPacket.Decode(onionBytes))

	// peelOnion is a helper closure that can be used to set up a Router
	// and use it to process the given onion packet.
	peelOnion := func(key *btcec.PrivateKey,
		blindingPoint *btcec.PublicKey,
		onionPacket *OnionPacket) *ProcessedPacket {

		r := NewRouter(&PrivKeyECDH{PrivKey: key}, NewMemoryReplayLog())

		require.NoError(t, r.Start())
		defer r.Stop()

		res, err := r.ProcessOnionPacket(
			onionPacket, nil, 10,
			WithBlindingPoint(blindingPoint),
		)
		require.NoError(t, err)

		return res
	}

	hops := testCase.Generate.Hops

	// There are some things that the processor of the onion packet will
	// only be able to determine from the actual contents of the encrypted
	// data it receives. These things include the next_blinding_point for
	// the introduction point and the next_blinding_override. The decryption
	// of this data is dependent on the encoding chosen by higher layers.
	// The test uses TLVs. Since the extraction of this data is dependent
	// on layers outside the scope of this library, we provide handle these
	// cases manually for the sake of the test.
	var (
		firstBlinding    = pubKeyFromString(testCase.Route.FirstPathKey)
		concatIndex      = 1
		blindingOverride = pubKeyFromString(
			hops[0].EncodedOnionMessageTLVs.NextPathKeyOverride,
		)
	)

	// Onion message routes are always entirely blinded, so
	// the first hop will always use the first blinding
	// point.
	blindingPoint := firstBlinding
	currentOnionPacket := onionPacket
	for i, hop := range testCase.Decrypt.Hops {
		// We encode the onion message packet to a buffer at each hop to
		// compare it to the onion message packet in the test vector.
		buff := bytes.NewBuffer(nil)
		require.NoError(t, currentOnionPacket.Encode(buff))

		// hop.OnionMessage contains the onion_message hex string. This
		// contains the type 513 (two bytes), the path_key (33 bytes)
		// and the length of the onion_message_packet (two bytes). We
		// are only interested in the onion_message_packet so we only
		// check that part. 2 + 33 + 2 = 37 bytes, so we skip the first
		// 37 bytes, which equals 74 hex characters.
		const onionMessageHexHeaderLen = 74

		require.Equal(
			t, hop.OnionMessage[onionMessageHexHeaderLen:],
			hex.EncodeToString(buff.Bytes()),
		)

		priv := privKeyFromString(hop.PrivKey)

		if i == concatIndex {
			blindingPoint = blindingOverride
		}

		// With peelOnion we call into ProcessOnionPacket (with the
		// functional option WithBlindingPoint) and we expect that the
		// onion message packet for this hop is processed without error,
		// otherwise peelOnion fails the test.
		processedPkt := peelOnion(
			priv, blindingPoint, currentOnionPacket,
		)

		// We derive the next blinding point from the current blinding
		// point and the private key of the current hop. The new
		// blindingPoint will be used to peel the next hop's onion
		// unless it is overridden by a blinding override.
		blindingPoint, err = NextEphemeral(
			&PrivKeyECDH{priv}, blindingPoint,
		)
		require.NoError(t, err)

		// We set the current onion packet to the next packet in the
		// processed packet. This is the packet that the next hop will
		// process. During the next iteration we will run all the above
		// checks on this packet.
		currentOnionPacket = processedPkt.NextPacket
	}
}

type onionBlindingJsonTestCase struct {
	Generate generateOnionData `json:"generate"`
	Decrypt  decryptData       `json:"decrypt"`
}

type generateOnionData struct {
	SessionKey string `json:"session_key"`
	AssocData  string `json:"associated_data"`
	Onion      string `json:"onion"`
}

type decryptData struct {
	Hops []decryptHops `json:"hops"`
}

type decryptOnionMessageData struct {
	Hops []decryptOnionMessageHops `json:"hops"`
}

type decryptHops struct {
	Onion        string `json:"onion"`
	NodePrivKey  string `json:"node_privkey"`
	NextBlinding string `json:"next_blinding"`
}

type decryptOnionMessageHops struct {
	OnionMessage string `json:"onion_message"`
	PrivKey      string `json:"privkey"`
	NextNodeID   string `json:"next_node_id"`
}

type blindingJsonTestCase struct {
	Generate generateData `json:"generate"`
	Route    routeData    `json:"route"`
	Unblind  unblindData  `json:"unblind"`
}

type onionMessageJsonTestCase struct {
	Generate     generateOnionMessageData `json:"generate"`
	Route        routeOnionMessageData    `json:"route"`
	OnionMessage onionMessageData         `json:"onionmessage"`
	Decrypt      decryptOnionMessageData  `json:"decrypt"`
}

type routeData struct {
	IntroductionNodeID string       `json:"introduction_node_id"`
	Blinding           string       `json:"blinding"`
	Hops               []blindedHop `json:"hops"`
}

type routeOnionMessageData struct {
	FirstNodeId  string                   `json:"first_node_id"`
	FirstPathKey string                   `json:"first_path_key"`
	Hops         []blindedOnionMessageHop `json:"hops"`
}

type onionMessageData struct {
	OnionMessagePacket string `json:"onion_message_packet"`
}

type unblindData struct {
	Hops []unblindedHop `json:"hops"`
}

type generateData struct {
	Hops []hopData `json:"hops"`
}

type generateOnionMessageData struct {
	SessionKey string                `json:"session_key"`
	Hops       []hopOnionMessageData `json:"hops"`
}

type unblindedHop struct {
	NodePrivKey         string `json:"node_privkey"`
	EphemeralPubKey     string `json:"ephemeral_pubkey"`
	DecryptedData       string `json:"decrypted_data"`
	NextEphemeralPubKey string `json:"next_ephemeral_pubkey"`
}

type hopData struct {
	SessionKey  string `json:"session_key"`
	NodeID      string `json:"node_id"`
	EncodedTLVs string `json:"encoded_tlvs"`
}

type hopOnionMessageData struct {
	PathKeySecret           string                  `json:"path_key_secret"`
	EncodedOnionMessageTLVs encodedOnionMessageTLVs `json:"tlvs"`
	EncryptedDataTlv        string                  `json:"encrypted_data_tlv"`
	EphemeralPubKey         string                  `json:"E"`
	NextEphemeralPrivKey    string                  `json:"next_e"`
}

type encodedOnionMessageTLVs struct {
	NextNodeID            string `json:"next_node_id"`
	NextPathKeyOverride   string `json:"next_path_key_override"`
	PathKeyOverrideSecret string `json:"path_key_override_secret"`
	PathID                string `json:"path_id"`
}

type blindedHop struct {
	BlindedNodeID string `json:"blinded_node_id"`
	EncryptedData string `json:"encrypted_data"`
}

type blindedOnionMessageHop struct {
	BlindedNodeID          string `json:"blinded_node_id"`
	EncryptedRecipientData string `json:"encrypted_recipient_data"`
}

func equalPubKeys(pkStr string, pk *btcec.PublicKey) bool {
	return hex.EncodeToString(pk.SerializeCompressed()) == pkStr
}

func privKeyFromString(pkStr string) *btcec.PrivateKey {
	bytes, _ := hex.DecodeString(pkStr)
	key, _ := btcec.PrivKeyFromBytes(bytes)
	return key
}

func pubKeyFromString(pkStr string) *btcec.PublicKey {
	bytes, _ := hex.DecodeString(pkStr)
	key, _ := btcec.ParsePubKey(bytes)
	return key
}
