package sphinx

import "errors"

var (
	// ErrReplayedPacket is an error returned when a packet is rejected
	// during processing due to being an attempted replay or probing
	// attempt.
	ErrReplayedPacket = errors.New("sphinx packet replay attempted")

	// ErrInvalidOnionVersion is returned during decoding of the onion
	// packet, when the received packet has an unknown version byte.
	ErrInvalidOnionVersion = errors.New("invalid onion packet version")

	// ErrInvalidOnionHMAC is returned during onion parsing process, when
	// received mac does not corresponds to the generated one.
	ErrInvalidOnionHMAC = errors.New("invalid mismatched mac")

	// ErrInvalidOnionKey is returned during onion parsing process, when
	// onion key is invalid.
	ErrInvalidOnionKey = errors.New("invalid onion key: pubkey isn't on " +
		"secp256k1 curve")

	// ErrLogEntryNotFound is an error returned when a packet lookup in a
	// replay log fails because it is missing.
	ErrLogEntryNotFound = errors.New("sphinx packet is not in log")

	// ErrPayloadSizeExceeded is returned when the payload size exceeds the
	// configured payload size of the onion packet.
	ErrPayloadSizeExceeded = errors.New("max payload size exceeded")

	// ErrSharedSecretDerivation is returned when we fail to derive the
	// shared secret for a hop.
	ErrSharedSecretDerivation = errors.New("error generating shared secret")

	// ErrMissingHMAC is returned when the onion packet is too small to
	// contain a valid HMAC.
	ErrMissingHMAC = errors.New("onion packet is too small, missing HMAC")

	// ErrNegativeRoutingInfoSize is returned when a negative routing info
	// size is specified in the Sphinx configuration.
	ErrNegativeRoutingInfoSize = errors.New("routing info size must be " +
		"non-negative")

	// ErrNegativePayloadSize is returned when a negative payload size is
	// specified in the Sphinx configuration.
	ErrNegativePayloadSize = errors.New("payload size must be " +
		"non-negative")

	// ErrZeroHops is returned when attempting to create a route with zero
	// hops.
	ErrZeroHops = errors.New("route of length zero passed in")

	// ErrIOReadFull is returned when an io read full operation fails.
	ErrIOReadFull = errors.New("io read full error")
)
