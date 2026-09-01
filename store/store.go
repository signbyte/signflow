// Package store persists signflow's durable portal-side state — the `signing` and
// `validation` schemas — reached ONLY through their SECURITY DEFINER procedures
// under the EXECUTE-only `signing_public` role; an in-memory backend exists for
// tests/dev. No backend exposes raw table access — every
// operation is a procedure call. The provider's signing session and the document
// bytes live in their own services — never here.
package store

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors the procedure error codes map onto, so callers/routes can pick
// the right HTTP status (`signing:<reason>` — :not_found → 404, :duplicate → 409).
var (
	// ErrNotFound is returned when a job is absent.
	ErrNotFound = errors.New("signing: not found")
	// ErrDuplicate is returned when a job_id is already mapped.
	ErrDuplicate = errors.New("signing: job already exists")
)

// Job is one signing_job row: the slot↔eparaksts-signer jobId mapping persisted
// across the user-driven redirect.
type Job struct {
	JobID       string    `json:"job_id"`
	EnvelopeID  string    `json:"envelope_id"`
	SlotID      string    `json:"slot_id"`
	Flow        string    `json:"flow"`
	SigFormat   string    `json:"sig_format"`
	State       string    `json:"state"`
	CallerSub   string    `json:"caller_sub"`
	LoginMethod string    `json:"login_method,omitempty"`
	LoA         string    `json:"loa,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SaveJobInput is the slot↔job mapping persisted before the redirect. State
// defaults to "PREPARING" when empty. LoginMethod and LoA carry the session's
// authentication binding through the user's redirect.
type SaveJobInput struct {
	JobID       string
	EnvelopeID  string
	SlotID      string
	Flow        string
	SigFormat   string
	CallerSub   string
	State       string
	LoginMethod string
	LoA         string
}

// Signature is one signature_record row: the lifecycle record of an applied
// signature, carrying its at-signing validation result and a ref to the
// normalized validation report. LoginMethod, together with FlowUsed, is the
// precise binding evidence ("authenticated via X, signed via Y"); LoA is the
// level of assurance achieved at login.
type Signature struct {
	ID                string `json:"id"`
	JobID             string `json:"job_id"`
	EnvelopeID        string `json:"envelope_id"`
	SlotID            string `json:"slot_id"`
	FlowUsed          string `json:"flow_used"`
	SigFormat         string `json:"sig_format"`
	Level             string `json:"level,omitempty"`
	SignedDocumentRef string `json:"signed_document_ref,omitempty"`
	TimestampRef      string `json:"timestamp_ref,omitempty"`
	Validated         bool   `json:"validated"`
	ValidationID      string `json:"validation_id,omitempty"`
	PreservationClass string `json:"preservation_class,omitempty"`
	LoginMethod       string `json:"login_method,omitempty"`
	LoA               string `json:"loa,omitempty"`
}

// SignatureInput records one applied signature on the signature_record.
type SignatureInput struct {
	JobID      string
	EnvelopeID string
	SlotID     string
	FlowUsed   string
	SigFormat  string
	Level      string
	// SignedDocumentRef is the document-store id of the signed output (an ASiC container
	// for XAdES, a signed PDF for PAdES).
	SignedDocumentRef string
	TimestampRef      string
	ValidationID      string
	PreservationClass string
	Validated         bool
	// LoginMethod + LoA are the login⇒signing binding evidence, copied from the
	// signing job onto the durable record.
	LoginMethod string
	LoA         string
}

// ReportInput is the Orchestrator-normalized validation result — the full
// signature-details field set persisted as durable evidence. The signer
// serial/registration is the real value in the clear (masking is a UI concern, the
// reveal is not audited); the verbatim provider report is never stored.
type ReportInput struct {
	SignatureID     string
	Verdict         string // PASSED | INDETERMINATE | FAILED
	Format          string
	Level           string
	Signer          string
	SignerSerial    string
	Organization    string
	ContainerForm   string
	SigningTime     string // RFC 3339; empty when absent
	RevocationTime  string // RFC 3339; empty when absent
	MaxValidityTime string // RFC 3339; empty when absent
	SignedFiles     []string
	Warnings        []string
	Errors          []string
	ResultRef       string
}

// Store is signflow's persistence contract. It maps 1:1 onto the `signing` +
// `validation` schema procedures.
type Store interface {
	// SaveJob persists the slot↔jobId mapping before the redirect (signing.save_job).
	// Returns ErrDuplicate if the job_id is already mapped.
	SaveJob(ctx context.Context, in SaveJobInput) error
	// ReconcileJob idempotently updates a job's state on return/callback
	// (signing.reconcile_job). Returns ErrNotFound if the job is absent.
	ReconcileJob(ctx context.Context, jobID, state string) error
	// GetJob reads one job by id (signing.get_job). Returns ErrNotFound if absent.
	GetJob(ctx context.Context, jobID string) (*Job, error)
	// InsertSignature records a signature_record (signing.insert_signature) and
	// returns its assigned ULID id.
	InsertSignature(ctx context.Context, in SignatureInput) (id string, err error)
	// GetSignature reads one signature_record by id (signing.get_signature).
	// Returns ErrNotFound if absent.
	GetSignature(ctx context.Context, id string) (*Signature, error)
	// RecordValidation links a normalized validation result back onto a
	// signature_record (signing.record_validation): the validation pass/fail, the
	// report ref, and the legal-meaning level (level is skipped when empty). It is
	// idempotent — a re-validation overwrites the prior link. Returns ErrNotFound
	// if the signature is absent.
	RecordValidation(ctx context.Context, signatureID, validationID string, validated bool, level string) error
	// StoreReport persists the normalized validation result (validation.store_report)
	// and returns its assigned ULID id.
	StoreReport(ctx context.Context, in ReportInput) (id string, err error)
	// AcquireChainLock atomically claims the single active-signer slot for a chain
	// (the PAdES co-sign concurrency gate): acquired=true when the chain is free, its
	// lock has expired, or the caller's own slot already holds it; false when another
	// slot holds an unexpired lock. holderRef is observability only; ttlSeconds is the
	// abandonment backstop (<=0 → the procedure default).
	AcquireChainLock(ctx context.Context, chainKey, holderSlot, holderRef string, ttlSeconds int) (acquired bool, err error)
	// ReleaseChainLock releases the caller's own hold on a chain (a no-op if another
	// slot took it over after a TTL expiry).
	ReleaseChainLock(ctx context.Context, chainKey, holderSlot string) error
	// ChainLockStatus reports whether a chain currently holds an unexpired active-signer
	// lock (for a blocked signer's "wait until free" poll). holderSlot is "" when free.
	ChainLockStatus(ctx context.Context, chainKey string) (locked bool, holderSlot string, err error)
	// Ping verifies backend connectivity for readiness checks.
	Ping(ctx context.Context) error
	// Close releases backend resources.
	Close()
}
