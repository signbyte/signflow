package audit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/gmb-lib/go-eidas-audit/eidas"
	"github.com/gmb-lib/go-platform-kit/broker"
)

// withCtx runs fn inside a real request handler so it receives a fully
// initialized *azugo.Context — azugo's MockContext supplies a nil request and
// panics once Stamp touches correlation/tracing off of it.
func withCtx(t *testing.T, fn func(ctx *azugo.Context)) {
	t.Helper()

	app := azugo.NewTestApp()
	app.Get("/t", func(ctx *azugo.Context) {
		fn(ctx)
		ctx.StatusCode(fasthttp.StatusNoContent)
	})
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/t")
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)
}

// fakeTransport records every published envelope and can be scripted to fail,
// so the recorder's real (non-nil-emitter) emission path is exercised without a
// broker connection.
type fakeTransport struct {
	err       error
	published []publishedMsg
}

type publishedMsg struct {
	topic, key string
	payload    []byte
}

func (f *fakeTransport) Publish(_ context.Context, topic, key string, payload []byte) error {
	f.published = append(f.published, publishedMsg{topic: topic, key: key, payload: payload})

	return f.err
}

// newTestEmitter builds a real *eidas.Emitter (legacy synchronous mode, no
// outbox) over the fake transport.
func newTestEmitter(transport broker.Transport, log *zap.Logger) *eidas.Emitter {
	pub := broker.NewPublisher(transport, "signflow-test")

	return eidas.New(pub, "audit.signing.test", eidas.Options{Logger: log})
}

func TestNewNilEmitterIsNoOp(t *testing.T) {
	r := New(nil, nil)

	withCtx(t, func(ctx *azugo.Context) {
		r.ValidationPerformed(ctx, Validation{CallerSub: "u1"})
		r.AuthAssurance(ctx, Assurance{CallerSub: "u1"})
	})
}

func TestNilRecorderIsNoOp(t *testing.T) {
	var r *Recorder

	withCtx(t, func(ctx *azugo.Context) {
		r.ValidationPerformed(ctx, Validation{})
		r.AuthAssurance(ctx, Assurance{})
	})
}

func TestValidationPerformedPublishesEvidence(t *testing.T) {
	transport := &fakeTransport{}
	r := New(newTestEmitter(transport, nil), nil)

	withCtx(t, func(ctx *azugo.Context) {
		r.ValidationPerformed(ctx, Validation{
			CallerSub:  "user-1",
			EnvelopeID: "env-1",
			DocumentID: "doc-1",
			Format:     "PAdES",
			Passed:     true,
			ReportRef:  "report-ref-1",
		})
	})

	qt.Assert(t, qt.Equals(len(transport.published), 1))
	qt.Assert(t, qt.Equals(transport.published[0].topic, "audit.signing.test"))

	var ev broker.Envelope
	qt.Assert(t, qt.IsNil(json.Unmarshal(transport.published[0].payload, &ev)))
	qt.Assert(t, qt.Equals(ev.Actor.ID, "user-1"))
	qt.Assert(t, qt.Equals(ev.Actor.Type, "user"))
	qt.Assert(t, qt.Equals(ev.Resource.Type, "envelope"))
	qt.Assert(t, qt.Equals(ev.Resource.ID, "env-1"))
	qt.Assert(t, qt.Equals(ev.Outcome, broker.OutcomeSuccess))
}

func TestValidationPerformedFailedSetsFailureOutcome(t *testing.T) {
	transport := &fakeTransport{}
	r := New(newTestEmitter(transport, nil), nil)

	withCtx(t, func(ctx *azugo.Context) {
		r.ValidationPerformed(ctx, Validation{CallerSub: "u1", DocumentID: "doc-1", Passed: false})
	})

	var ev broker.Envelope
	qt.Assert(t, qt.IsNil(json.Unmarshal(transport.published[0].payload, &ev)))
	qt.Assert(t, qt.Equals(ev.Outcome, broker.OutcomeFailure))
	// No envelope id — resource falls back to the document.
	qt.Assert(t, qt.Equals(ev.Resource.Type, "document"))
	qt.Assert(t, qt.Equals(ev.Resource.ID, "doc-1"))
}

func TestAuthAssurancePublishesEvidence(t *testing.T) {
	transport := &fakeTransport{}
	r := New(newTestEmitter(transport, nil), nil)

	withCtx(t, func(ctx *azugo.Context) {
		r.AuthAssurance(ctx, Assurance{
			CallerSub:      "user-1",
			EnvelopeID:     "env-1",
			Method:         "eparakstsMobile",
			LoA:            "high",
			BindingOutcome: "bound",
		})
	})

	qt.Assert(t, qt.Equals(len(transport.published), 1))

	var ev broker.Envelope
	qt.Assert(t, qt.IsNil(json.Unmarshal(transport.published[0].payload, &ev)))
	qt.Assert(t, qt.Equals(ev.Actor.Assurance, "high"))
	qt.Assert(t, qt.Equals(ev.Attributes["binding_outcome"], "bound"))
	qt.Assert(t, qt.Equals(ev.Outcome, broker.OutcomeSuccess))
}

func TestEmitFailureIsLoggedNotPropagated(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	log := zap.New(core)

	transport := &fakeTransport{err: errors.New("broker unavailable")}
	r := New(newTestEmitter(transport, nil), log)

	withCtx(t, func(ctx *azugo.Context) {
		r.ValidationPerformed(ctx, Validation{CallerSub: "u1", DocumentID: "doc-1"})
	})

	found := false
	for _, entry := range logs.All() {
		if entry.Level == zapcore.ErrorLevel && entry.Message == "eidas validation emit failed" {
			found = true
		}
	}
	qt.Assert(t, qt.IsTrue(found))
}
