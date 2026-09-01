package store

import (
	"context"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// Memory is an in-memory Store for development/test (no DB). It is NOT durable —
// state is lost on restart — and exists so the service boots and the routes are
// testable without Postgres. Production uses the Postgres backend.
type Memory struct {
	mu      sync.Mutex
	jobs    map[string]*Job
	sigs    map[string]*Signature
	reports map[string]ReportInput
	locks   map[string]memLock
}

// memLock is one in-memory chain lock: the owning slot + its expiry.
type memLock struct {
	slot    string
	expires time.Time
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		jobs:    make(map[string]*Job),
		sigs:    make(map[string]*Signature),
		reports: make(map[string]ReportInput),
		locks:   make(map[string]memLock),
	}
}

// SaveJob stores the mapping, rejecting a duplicate job_id (mirrors the PK).
func (m *Memory) SaveJob(_ context.Context, in SaveJobInput) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.jobs[in.JobID]; ok {
		return ErrDuplicate
	}
	state := in.State
	if state == "" {
		state = "PREPARING"
	}
	now := time.Now().UTC()
	m.jobs[in.JobID] = &Job{
		JobID: in.JobID, EnvelopeID: in.EnvelopeID, SlotID: in.SlotID,
		Flow: in.Flow, SigFormat: in.SigFormat, State: state,
		CallerSub: in.CallerSub, LoginMethod: in.LoginMethod, LoA: in.LoA,
		CreatedAt: now, UpdatedAt: now,
	}

	return nil
}

// ReconcileJob updates a job's state, or ErrNotFound if absent.
func (m *Memory) ReconcileJob(_ context.Context, jobID, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	j, ok := m.jobs[jobID]
	if !ok {
		return ErrNotFound
	}
	j.State = state
	j.UpdatedAt = time.Now().UTC()

	return nil
}

// GetJob returns a copy of the job, or ErrNotFound.
func (m *Memory) GetJob(_ context.Context, jobID string) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	j, ok := m.jobs[jobID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *j

	return &cp, nil
}

// InsertSignature records a signature and returns a fresh ULID.
func (m *Memory) InsertSignature(_ context.Context, in SignatureInput) (string, error) {
	id := ulid.Make().String()
	presv := in.PreservationClass
	if presv == "" {
		presv = "none"
	}
	m.mu.Lock()
	m.sigs[id] = &Signature{
		ID: id, JobID: in.JobID, EnvelopeID: in.EnvelopeID, SlotID: in.SlotID,
		FlowUsed: in.FlowUsed, SigFormat: in.SigFormat, Level: in.Level,
		SignedDocumentRef: in.SignedDocumentRef, TimestampRef: in.TimestampRef,
		Validated: in.Validated, ValidationID: in.ValidationID, PreservationClass: presv,
		LoginMethod: in.LoginMethod, LoA: in.LoA,
	}
	m.mu.Unlock()

	return id, nil
}

// GetSignature returns a copy of the signature record, or ErrNotFound.
func (m *Memory) GetSignature(_ context.Context, id string) (*Signature, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sigs[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *s

	return &cp, nil
}

// RecordValidation links a validation result onto a signature, or ErrNotFound.
func (m *Memory) RecordValidation(_ context.Context, signatureID, validationID string, validated bool, level string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sigs[signatureID]
	if !ok {
		return ErrNotFound
	}
	s.ValidationID = validationID
	s.Validated = validated
	if level != "" {
		s.Level = level
	}

	return nil
}

// StoreReport records a normalized result and returns a fresh ULID.
func (m *Memory) StoreReport(_ context.Context, in ReportInput) (string, error) {
	id := ulid.Make().String()
	m.mu.Lock()
	m.reports[id] = in
	m.mu.Unlock()

	return id, nil
}

// AcquireChainLock claims the chain's active-signer slot; another slot holding an
// unexpired lock is refused (acquired=false). The caller's own slot re-acquires.
func (m *Memory) AcquireChainLock(_ context.Context, chainKey, holderSlot, _ string, ttlSeconds int) (bool, error) {
	if ttlSeconds <= 0 {
		ttlSeconds = 300
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	if cur, ok := m.locks[chainKey]; ok && cur.expires.After(now) && cur.slot != holderSlot {
		return false, nil
	}
	m.locks[chainKey] = memLock{slot: holderSlot, expires: now.Add(time.Duration(ttlSeconds) * time.Second)}

	return true, nil
}

// ReleaseChainLock drops the caller's own hold (no-op if another slot took it over).
func (m *Memory) ReleaseChainLock(_ context.Context, chainKey, holderSlot string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cur, ok := m.locks[chainKey]; ok && cur.slot == holderSlot {
		delete(m.locks, chainKey)
	}

	return nil
}

// ChainLockStatus reports whether a chain holds an unexpired lock.
func (m *Memory) ChainLockStatus(_ context.Context, chainKey string) (bool, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cur, ok := m.locks[chainKey]; ok && cur.expires.After(time.Now().UTC()) {
		return true, cur.slot, nil
	}

	return false, "", nil
}

// Ping always succeeds (in-memory).
func (m *Memory) Ping(_ context.Context) error { return nil }

// Close is a no-op.
func (m *Memory) Close() {}
