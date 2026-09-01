package store

import (
	"context"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestMemorySaveJobDefaultsStateAndRejectsDuplicate(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	err := m.SaveJob(ctx, SaveJobInput{JobID: "job-1", EnvelopeID: "env-1", SlotID: "slot-1", Flow: "eparakstsMobile", SigFormat: "XAdES", CallerSub: "user-1"})
	qt.Assert(t, qt.IsNil(err))

	job, err := m.GetJob(ctx, "job-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(job.State, "PREPARING"))
	qt.Assert(t, qt.Equals(job.EnvelopeID, "env-1"))
	qt.Assert(t, qt.IsFalse(job.CreatedAt.IsZero()))

	err = m.SaveJob(ctx, SaveJobInput{JobID: "job-1"})
	qt.Assert(t, qt.ErrorIs(err, ErrDuplicate))
}

func TestMemorySaveJobKeepsGivenState(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(m.SaveJob(ctx, SaveJobInput{JobID: "job-1", State: "AWAITING_AUTHORIZATION"})))

	job, err := m.GetJob(ctx, "job-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(job.State, "AWAITING_AUTHORIZATION"))
}

func TestMemoryGetJobNotFound(t *testing.T) {
	m := NewMemory()

	_, err := m.GetJob(context.Background(), "missing")
	qt.Assert(t, qt.ErrorIs(err, ErrNotFound))
}

func TestMemoryReconcileJobUpdatesState(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	qt.Assert(t, qt.IsNil(m.SaveJob(ctx, SaveJobInput{JobID: "job-1"})))
	qt.Assert(t, qt.IsNil(m.ReconcileJob(ctx, "job-1", "COMPLETED")))

	job, err := m.GetJob(ctx, "job-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(job.State, "COMPLETED"))
}

func TestMemoryReconcileJobNotFound(t *testing.T) {
	m := NewMemory()

	err := m.ReconcileJob(context.Background(), "missing", "COMPLETED")
	qt.Assert(t, qt.ErrorIs(err, ErrNotFound))
}

func TestMemoryGetJobReturnsACopy(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	qt.Assert(t, qt.IsNil(m.SaveJob(ctx, SaveJobInput{JobID: "job-1"})))

	job, err := m.GetJob(ctx, "job-1")
	qt.Assert(t, qt.IsNil(err))
	job.State = "MUTATED"

	job2, err := m.GetJob(ctx, "job-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(job2.State, "PREPARING"))
}

func TestMemoryInsertSignatureDefaultsPreservationClass(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	id, err := m.InsertSignature(ctx, SignatureInput{JobID: "job-1", FlowUsed: "eparakstsMobile", SigFormat: "XAdES"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Not(qt.Equals(id, "")))

	sig, err := m.GetSignature(ctx, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(sig.PreservationClass, "none"))
	qt.Assert(t, qt.Equals(sig.JobID, "job-1"))
}

func TestMemoryInsertSignatureKeepsGivenPreservationClass(t *testing.T) {
	m := NewMemory()

	id, err := m.InsertSignature(context.Background(), SignatureInput{PreservationClass: "long-term"})
	qt.Assert(t, qt.IsNil(err))

	sig, err := m.GetSignature(context.Background(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(sig.PreservationClass, "long-term"))
}

func TestMemoryGetSignatureNotFound(t *testing.T) {
	m := NewMemory()

	_, err := m.GetSignature(context.Background(), "missing")
	qt.Assert(t, qt.ErrorIs(err, ErrNotFound))
}

func TestMemoryGetSignatureReturnsACopy(t *testing.T) {
	m := NewMemory()
	id, err := m.InsertSignature(context.Background(), SignatureInput{})
	qt.Assert(t, qt.IsNil(err))

	sig, err := m.GetSignature(context.Background(), id)
	qt.Assert(t, qt.IsNil(err))
	sig.Level = "MUTATED"

	sig2, err := m.GetSignature(context.Background(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(sig2.Level, ""))
}

func TestMemoryRecordValidationUpdatesFields(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	id, err := m.InsertSignature(ctx, SignatureInput{})
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNil(m.RecordValidation(ctx, id, "val-1", true, "QES")))

	sig, err := m.GetSignature(ctx, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(sig.ValidationID, "val-1"))
	qt.Assert(t, qt.IsTrue(sig.Validated))
	qt.Assert(t, qt.Equals(sig.Level, "QES"))
}

func TestMemoryRecordValidationEmptyLevelKeepsExisting(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	id, err := m.InsertSignature(ctx, SignatureInput{Level: "AES"})
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNil(m.RecordValidation(ctx, id, "val-1", false, "")))

	sig, err := m.GetSignature(ctx, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(sig.Level, "AES"))
	qt.Assert(t, qt.IsFalse(sig.Validated))
}

func TestMemoryRecordValidationNotFound(t *testing.T) {
	m := NewMemory()

	err := m.RecordValidation(context.Background(), "missing", "val-1", true, "")
	qt.Assert(t, qt.ErrorIs(err, ErrNotFound))
}

func TestMemoryStoreReport(t *testing.T) {
	m := NewMemory()

	id, err := m.StoreReport(context.Background(), ReportInput{SignatureID: "sig-1", Verdict: "PASSED"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Not(qt.Equals(id, "")))
}

func TestMemoryPingAlwaysSucceeds(t *testing.T) {
	m := NewMemory()
	qt.Assert(t, qt.IsNil(m.Ping(context.Background())))
}

func TestMemoryCloseIsNoOp(t *testing.T) {
	m := NewMemory()
	m.Close() // must not panic
}
