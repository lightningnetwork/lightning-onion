package sphinx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMemoryReplayLogStorageAndRetrieval tests that the non-batch methods on
// MemoryReplayLog work as expected.
func TestMemoryReplayLogStorageAndRetrieval(t *testing.T) {
	rl := NewMemoryReplayLog()
	rl.Start()
	defer rl.Stop()

	var hashPrefix HashPrefix
	hashPrefix[0] = 1

	var cltv1 uint32 = 1

	// Attempt to lookup unknown sphinx packet.
	_, err := rl.Get(&hashPrefix)
	if err == nil {
		t.Fatalf("Expected ErrLogEntryNotFound")
	}
	if err != ErrLogEntryNotFound {
		t.Fatalf("Get failed - received unexpected error upon Get: %v", err)
	}

	// Log incoming sphinx packet.
	err = rl.Put(&hashPrefix, cltv1)
	if err != nil {
		t.Fatalf("Put failed - received unexpected error upon Put: %v", err)
	}

	// Attempt to replay sphinx packet.
	err = rl.Put(&hashPrefix, cltv1)
	if err == nil {
		t.Fatalf("Expected ErrReplayedPacket")
	}
	if err != ErrReplayedPacket {
		t.Fatalf("Put failed - received unexpected error upon Put: %v", err)
	}

	// Lookup logged sphinx packet.
	cltv, err := rl.Get(&hashPrefix)
	if err != nil {
		t.Fatalf("Get failed - received unexpected error upon Get: %v", err)
	}
	if cltv != cltv1 {
		t.Fatalf("Get returned wrong value: expected %v, got %v", cltv1, cltv)
	}

	// Delete sphinx packet from log.
	err = rl.Delete(&hashPrefix)
	if err != nil {
		t.Fatalf("Delete failed - received unexpected error upon Delete: %v", err)
	}

	// Attempt to lookup deleted sphinx packet.
	_, err = rl.Get(&hashPrefix)
	if err == nil {
		t.Fatalf("Expected ErrLogEntryNotFound")
	}
	if err != ErrLogEntryNotFound {
		t.Fatalf("Get failed - received unexpected error upon Get: %v", err)
	}

	// Reinsert incoming sphinx packet into the log.
	var cltv2 uint32 = 2
	err = rl.Put(&hashPrefix, cltv2)
	if err != nil {
		t.Fatalf("Put failed - received unexpected error upon Put: %v", err)
	}

	// Lookup logged sphinx packet.
	cltv, err = rl.Get(&hashPrefix)
	if err != nil {
		t.Fatalf("Get failed - received unexpected error upon Get: %v", err)
	}
	if cltv != cltv2 {
		t.Fatalf("Get returned wrong value: expected %v, got %v", cltv2, cltv)
	}
}

// TestMemoryReplayLogPutBatch tests that the batch adding of packets to a log
// works as expected.
func TestMemoryReplayLogPutBatch(t *testing.T) {
	rl := NewMemoryReplayLog()
	rl.Start()
	defer rl.Stop()

	var hashPrefix1, hashPrefix2 HashPrefix
	hashPrefix1[0] = 1
	hashPrefix2[0] = 2

	// Create a batch with a duplicated packet.
	batch1 := NewBatch([]byte{1})
	err := batch1.Put(1, &hashPrefix1, 1)
	if err != nil {
		t.Fatalf("Unexpected error adding entry to batch: %v", err)
	}
	err = batch1.Put(1, &hashPrefix1, 1)
	if err != nil {
		t.Fatalf("Unexpected error adding entry to batch: %v", err)
	}

	replays, err := rl.PutBatch(batch1)
	if replays.Size() != 1 || !replays.Contains(1) {
		t.Fatalf("Unexpected replay set after adding batch 1 to log: %v", err)
	}

	// Create a batch with one replayed packet and one valid one.
	batch2 := NewBatch([]byte{2})
	err = batch2.Put(1, &hashPrefix1, 1)
	if err != nil {
		t.Fatalf("Unexpected error adding entry to batch: %v", err)
	}
	err = batch2.Put(2, &hashPrefix2, 2)
	if err != nil {
		t.Fatalf("Unexpected error adding entry to batch: %v", err)
	}

	replays, err = rl.PutBatch(batch2)
	if replays.Size() != 1 || !replays.Contains(1) {
		t.Fatalf("Unexpected replay set after adding batch 2 to log: %v", err)
	}

	// Reprocess batch 2, which should be idempotent.
	replays, err = rl.PutBatch(batch2)
	if replays.Size() != 1 || !replays.Contains(1) {
		t.Fatalf("Unexpected replay set after adding batch 2 to log: %v", err)
	}
}

// TestNoOpReplayLog tests that NoOpReplayLog performs no replay protection,
// allowing all packets through without storing any state.
func TestNoOpReplayLog(t *testing.T) {
	t.Parallel()

	rl := NewNoOpReplayLog()

	// Start and Stop should succeed without error.
	require.NoError(t, rl.Start())
	defer func() {
		require.NoError(t, rl.Stop())
	}()

	var hashPrefix HashPrefix

	hashPrefix[0] = 1

	// Get should always return ErrLogEntryNotFound since nothing is stored.
	_, err := rl.Get(&hashPrefix)
	require.ErrorIs(t, err, ErrLogEntryNotFound)

	// Put should always succeed.
	require.NoError(t, rl.Put(&hashPrefix, 1))

	// Put the same packet again - should still succeed (no replay
	// detection).
	require.NoError(t, rl.Put(&hashPrefix, 1))

	// Get should still return ErrLogEntryNotFound (nothing is stored).
	_, err = rl.Get(&hashPrefix)
	require.ErrorIs(t, err, ErrLogEntryNotFound)

	// Delete should succeed.
	require.NoError(t, rl.Delete(&hashPrefix))
}

// TestNoOpReplayLogPutBatch tests that NoOpReplayLog's PutBatch marks batches
// as committed and never reports replays.
func TestNoOpReplayLogPutBatch(t *testing.T) {
	t.Parallel()

	rl := NewNoOpReplayLog()

	var hashPrefix1, hashPrefix2 HashPrefix

	hashPrefix1[0] = 1
	hashPrefix2[0] = 2

	// Create a batch with duplicate packets.
	batch1 := NewBatch([]byte{1})
	require.NoError(t, batch1.Put(1, &hashPrefix1, 1))
	require.NoError(t, batch1.Put(2, &hashPrefix1, 1))

	replays, err := rl.PutBatch(batch1)
	require.NoError(t, err)
	require.True(t, batch1.IsCommitted, "Batch should be marked as "+
		"committed")

	// NoOpReplayLog doesn't detect intra-batch replays (that's done by
	// Batch itself), but it should return an empty set from its own
	// detection.
	require.NotNil(t, replays)

	// Create another batch with the same hash prefix - should not detect
	// replay since NoOpReplayLog doesn't store anything.
	batch2 := NewBatch([]byte{2})
	require.NoError(t, batch2.Put(1, &hashPrefix1, 1))
	require.NoError(t, batch2.Put(2, &hashPrefix2, 2))

	replays, err = rl.PutBatch(batch2)
	require.NoError(t, err)
	require.True(t, batch2.IsCommitted, "Batch should be marked as "+
		"committed")

	// Should report no replays since NoOpReplayLog doesn't track state.
	require.Equal(t, 0, replays.Size(), "Expected empty replay set")
}
