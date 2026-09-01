// Package audit records signflow's signing-lifecycle evidence to the eIDAS-audit
// regime. signflow is the portal's second source of signing evidence (alongside
// the signing provider): where the provider records its per-job signing steps,
// signflow records the portal's own material events — beginning with the
// validation answer it owns. Events are lean references only; no document bytes,
// no certificates, no report contents, no signer names.
package audit

import (
	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-eidas-audit/eidas"
	"github.com/gmb-lib/go-platform-kit/broker"
)

// Recorder emits signflow's lifecycle/validation evidence over the audit broker.
// A nil emitter makes every method a no-op, so the service runs in development
// without a broker configured.
type Recorder struct {
	eidas *eidas.Emitter
	log   *zap.Logger
}

// New builds a Recorder. A nil emitter (no broker) yields a no-op recorder; a nil
// logger is replaced with a no-op.
func New(emitter *eidas.Emitter, log *zap.Logger) *Recorder {
	if log == nil {
		log = zap.NewNop()
	}

	return &Recorder{eidas: emitter, log: log}
}

// Validation is the normalized validation answer for one signed document, as a
// lean evidence record: the verdict-derived pass/fail, the container format, and a
// reference to the stored normalized result. The signer name and the report
// contents are deliberately excluded.
type Validation struct {
	CallerSub  string
	EnvelopeID string
	DocumentID string
	Format     string
	Passed     bool
	ReportRef  string
}

// ValidationPerformed records that a validation / re-validation completed.
// Emission never blocks signing — a durable outbox spools the event and a
// background drainer publishes it — so a failure here is logged, not propagated.
func (r *Recorder) ValidationPerformed(ctx *azugo.Context, v Validation) {
	if r == nil || r.eidas == nil {
		return
	}

	err := r.eidas.ValidationPerformed(ctx, eidas.Validation{
		Actor:       broker.Actor{ID: v.CallerSub, Type: "user"},
		EnvelopeID:  v.EnvelopeID,
		DocumentID:  v.DocumentID,
		Format:      v.Format,
		Passed:      v.Passed,
		ReportS3Ref: v.ReportRef,
	})
	if err != nil {
		r.log.Error("eidas validation emit failed", zap.Error(err))
	}
}

// Assurance is the login⇒signing binding evidence for one signing request: the
// login method that authorized it, the level of assurance, and whether the
// requested flow was bound to that method or rejected. It carries no PII — method,
// LoA, and the binding outcome only.
type Assurance struct {
	CallerSub  string
	EnvelopeID string
	Method     string
	LoA        string
	// BindingOutcome is "bound" when the login method permitted the requested flow,
	// or "rejected" when it did not (the rejection is itself evidence).
	BindingOutcome string
}

// AuthAssurance records the login⇒signing binding established (or rejected) at the
// signing request. Like the other lifecycle events, emission is best-effort and
// never blocks the request.
func (r *Recorder) AuthAssurance(ctx *azugo.Context, a Assurance) {
	if r == nil || r.eidas == nil {
		return
	}

	err := r.eidas.AuthAssurance(ctx, eidas.Assurance{
		Actor:            broker.Actor{ID: a.CallerSub, Type: "user"},
		EnvelopeID:       a.EnvelopeID,
		Method:           a.Method,
		LevelOfAssurance: a.LoA,
		BindingOutcome:   a.BindingOutcome,
	})
	if err != nil {
		r.log.Error("eidas assurance emit failed", zap.Error(err))
	}
}
