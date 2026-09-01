package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is the platform store: the `signing` + `validation` schemas reached
// ONLY through SECURITY DEFINER procedures under the EXECUTE-only `signing_public`
// role. This package never issues raw table SQL — it only CALLs the procedures.
//
// Selected when SIGNING_STORE_DSN is set; the in-memory backend is the dev/test
// default.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres opens a connection pool to the platform PostgreSQL. The pool is
// lazy; connectivity is verified on first use (or via Ping).
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: postgres connect: %w", err)
	}

	return &Postgres{pool: pool}, nil
}

// Close releases the connection pool.
func (p *Postgres) Close() { p.pool.Close() }

// Ping verifies backend connectivity.
func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

// envelope is the structured result every procedure returns
// (util.result_success / util.result_error).
type envelope struct {
	Result  string          `json:"result"`
	Data    json.RawMessage `json:"data"`
	Code    string          `json:"code"`
	Message string          `json:"message"`
}

// mapCode turns a <domain>:<reason> error code into a sentinel error where one
// exists, so callers/routes can pick the right HTTP status.
func mapCode(proc, code, msg string) error {
	switch {
	case strings.HasSuffix(code, ":not_found"):
		return ErrNotFound
	case strings.HasSuffix(code, ":duplicate"):
		return ErrDuplicate
	default:
		return fmt.Errorf("store: %s: %s: %s", proc, code, msg)
	}
}

// call invokes a SECURITY DEFINER procedure with the uniform JSONB envelope and
// returns the decoded `data` payload, or a typed error from result_error.
func (p *Postgres) call(ctx context.Context, proc string, in any) (json.RawMessage, error) {
	inJSON, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("store: marshal input: %w", err)
	}

	// CALL with an INOUT parameter returns a single-column row carrying po_data;
	// NULL seeds the INOUT slot.
	q := fmt.Sprintf("CALL %s($1::jsonb, NULL::jsonb)", proc)

	var out []byte
	if err := p.pool.QueryRow(ctx, q, inJSON).Scan(&out); err != nil {
		// A procedure that fails after a write re-raises a structured error with
		// SQLSTATE P0001 (Pattern B); its message is the util.result_error JSON.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "P0001" {
			var env envelope
			if json.Unmarshal([]byte(pgErr.Message), &env) == nil && env.Result == "error" {
				return nil, mapCode(proc, env.Code, env.Message)
			}
		}

		return nil, fmt.Errorf("store: %s: %w", proc, err)
	}

	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		return nil, fmt.Errorf("store: %s: decode result: %w", proc, err)
	}
	if env.Result != "success" {
		return nil, mapCode(proc, env.Code, env.Message)
	}

	return env.Data, nil
}

// SaveJob persists the slot↔jobId mapping via signing.save_job.
func (p *Postgres) SaveJob(ctx context.Context, in SaveJobInput) error {
	body := map[string]any{
		"job_id":      in.JobID,
		"envelope_id": in.EnvelopeID,
		"slot_id":     in.SlotID,
		"flow":        in.Flow,
		"sig_format":  in.SigFormat,
		"caller_sub":  in.CallerSub,
	}
	putOpt(body, "state", in.State)
	putOpt(body, "login_method", in.LoginMethod)
	putOpt(body, "loa", in.LoA)

	_, err := p.call(ctx, "signing.save_job", body)

	return err
}

// ReconcileJob idempotently updates a job's state via signing.reconcile_job.
func (p *Postgres) ReconcileJob(ctx context.Context, jobID, state string) error {
	_, err := p.call(ctx, "signing.reconcile_job", map[string]any{"job_id": jobID, "state": state})

	return err
}

// GetJob reads one job via signing.get_job.
func (p *Postgres) GetJob(ctx context.Context, jobID string) (*Job, error) {
	data, err := p.call(ctx, "signing.get_job", map[string]any{"job_id": jobID})
	if err != nil {
		return nil, err
	}

	var j Job
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("store: get_job: decode: %w", err)
	}

	return &j, nil
}

// InsertSignature records a signature_record via signing.insert_signature.
func (p *Postgres) InsertSignature(ctx context.Context, in SignatureInput) (string, error) {
	body := map[string]any{
		"job_id":      in.JobID,
		"envelope_id": in.EnvelopeID,
		"slot_id":     in.SlotID,
		"flow_used":   in.FlowUsed,
		"sig_format":  in.SigFormat,
		"validated":   in.Validated,
	}
	putOpt(body, "level", in.Level)
	putOpt(body, "signed_document_ref", in.SignedDocumentRef)
	putOpt(body, "timestamp_ref", in.TimestampRef)
	putOpt(body, "validation_id", in.ValidationID)
	putOpt(body, "preservation_class", in.PreservationClass)
	putOpt(body, "login_method", in.LoginMethod)
	putOpt(body, "loa", in.LoA)

	return p.callID(ctx, "signing.insert_signature", body)
}

// GetSignature reads one signature_record via signing.get_signature.
func (p *Postgres) GetSignature(ctx context.Context, id string) (*Signature, error) {
	data, err := p.call(ctx, "signing.get_signature", map[string]any{"id": id})
	if err != nil {
		return nil, err
	}

	var s Signature
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("store: get_signature: decode: %w", err)
	}

	return &s, nil
}

// RecordValidation links a validation result onto a signature_record via
// signing.record_validation.
func (p *Postgres) RecordValidation(ctx context.Context, signatureID, validationID string, validated bool, level string) error {
	body := map[string]any{
		"signature_id": signatureID,
		"validated":    validated,
	}
	putOpt(body, "validation_id", validationID)
	putOpt(body, "level", level)

	_, err := p.call(ctx, "signing.record_validation", body)

	return err
}

// StoreReport persists the normalized validation result via validation.store_report.
// The signer serial/registration is sent as the real value; the file/warning/error
// lists go as JSON arrays the procedure stores verbatim ([] is an explicit empty
// set, not a missing field).
func (p *Postgres) StoreReport(ctx context.Context, in ReportInput) (string, error) {
	body := map[string]any{
		"signature_id": in.SignatureID,
		"verdict":      in.Verdict,
	}
	putOpt(body, "format", in.Format)
	putOpt(body, "level", in.Level)
	putOpt(body, "result_s3_ref", in.ResultRef)
	putOpt(body, "signer", in.Signer)
	putOpt(body, "signer_serial", in.SignerSerial)
	putOpt(body, "organization", in.Organization)
	putOpt(body, "container_form", in.ContainerForm)
	putOpt(body, "signing_time", in.SigningTime)
	putOpt(body, "revocation_time", in.RevocationTime)
	putOpt(body, "max_validity_time", in.MaxValidityTime)
	if in.SignedFiles != nil {
		body["signed_files"] = in.SignedFiles
	}
	if in.Warnings != nil {
		body["warnings"] = in.Warnings
	}
	if in.Errors != nil {
		body["errors"] = in.Errors
	}

	return p.callID(ctx, "validation.store_report", body)
}

// AcquireChainLock claims the chain's active-signer slot via signing.acquire_chain_lock.
func (p *Postgres) AcquireChainLock(ctx context.Context, chainKey, holderSlot, holderRef string, ttlSeconds int) (bool, error) {
	body := map[string]any{
		"chain_key":   chainKey,
		"holder_slot": holderSlot,
	}
	putOpt(body, "holder_ref", holderRef)
	if ttlSeconds > 0 {
		body["ttl_seconds"] = ttlSeconds
	}

	data, err := p.call(ctx, "signing.acquire_chain_lock", body)
	if err != nil {
		return false, err
	}

	var res struct {
		Acquired bool `json:"acquired"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return false, fmt.Errorf("store: acquire_chain_lock: decode: %w", err)
	}

	return res.Acquired, nil
}

// ReleaseChainLock releases the caller's own hold via signing.release_chain_lock.
func (p *Postgres) ReleaseChainLock(ctx context.Context, chainKey, holderSlot string) error {
	_, err := p.call(ctx, "signing.release_chain_lock", map[string]any{
		"chain_key":   chainKey,
		"holder_slot": holderSlot,
	})

	return err
}

// ChainLockStatus reads whether a chain is locked via signing.chain_lock_status.
func (p *Postgres) ChainLockStatus(ctx context.Context, chainKey string) (bool, string, error) {
	data, err := p.call(ctx, "signing.chain_lock_status", map[string]any{"chain_key": chainKey})
	if err != nil {
		return false, "", err
	}

	var res struct {
		Locked     bool   `json:"locked"`
		HolderSlot string `json:"holder_slot"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return false, "", fmt.Errorf("store: chain_lock_status: decode: %w", err)
	}

	return res.Locked, res.HolderSlot, nil
}

// callID invokes a procedure that returns { id } and decodes it.
func (p *Postgres) callID(ctx context.Context, proc string, body map[string]any) (string, error) {
	data, err := p.call(ctx, proc, body)
	if err != nil {
		return "", err
	}

	var res struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return "", fmt.Errorf("store: %s: decode: %w", proc, err)
	}

	return res.ID, nil
}

// putOpt adds key=val to body only when val is non-empty (so the procedure's
// COALESCE/NULLIF defaults apply for omitted optionals).
func putOpt(body map[string]any, key, val string) {
	if val != "" {
		body[key] = val
	}
}
