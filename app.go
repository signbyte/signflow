// Package signflow is the Signing Orchestrator: the portal's signing conductor.
// It turns a "sign this slot with this flow" request into a signing job on the
// signing provider, reconciles the result back onto the envelope, owns the
// signature-record lifecycle, and owns the validation answer — the user-facing
// validate call plus normalizing the provider's verbatim validation report into
// the portal's field set. It is byte-free for hash-only XAdES/ASiC-E (only the
// document digest transits) and a transient byte conduit for PAdES and
// full-container validation.
//
// Cross-cutting concerns (logging with redaction, tracing, correlation) are
// installed once by the shared platform-kit and are never wired per-service.
//
// Status: walking skeleton — it boots, serves /healthz, validates inbound DPoP
// service tokens, and exposes the API surface; the orchestration, the
// signing/validation persistence, the collaborator clients, and audit emission
// are added in later work.
package signflow

import (
	"fmt"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-eidas-audit/eidas"
	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-platform-kit/broker/natsbroker"
	"github.com/gmb-lib/go-platform-kit/platform"

	"github.com/signbyte/signflow/audit"
	"github.com/signbyte/signflow/clients"
	"github.com/signbyte/signflow/orchestrator"
	"github.com/signbyte/signflow/store"
)

// App is the signflow application container.
type App struct {
	*azugo.App

	config *Configuration

	// Durable portal-side state: the `signing` + `validation` schemas via the
	// EXECUTE-only signing_public role (or in-memory in dev/test).
	store store.Store

	// Inbound service authentication (go-authbyte DPoP; aud svc:signflow). Callers
	// are the Envelope/Workflow service + Portal-API.
	authClient *authclient.Client
	authMW     azugo.RequestHandlerFunc

	// Outbound DPoP service client — used to call eparaksts-signer, the Document
	// Service, the Envelope service, and access-audit. Nil until a collaborator
	// base URL is configured (skeleton/dev).
	outboundClient *authclient.Client

	// Signing conductor — drives prepare → status → download against the signer and
	// assembles the container via the document service. Nil until both the signer
	// and the document base URLs are configured.
	conductor *orchestrator.Conductor

	// natsConn backs the eIDAS-audit transport; held so Stop can close it after the
	// outbox flush. Nil when no broker is configured.
	natsConn *natsbroker.Conn

	// audit emits signflow's lifecycle/validation evidence to eIDAS-audit. Always
	// non-nil; a no-op recorder when no broker is configured (dev).
	audit *audit.Recorder
}

// New constructs the application.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := NewConfiguration()

	a, err := server.New(cmd, server.Options{
		AppName:       "Signing Orchestrator (signflow)",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	app := &App{App: a, config: config}
	if err := app.init(); err != nil {
		return nil, err
	}

	return app, nil
}

func (a *App) init() error {
	cfg := a.config

	// Platform glue FIRST: logging + redaction, OpenTelemetry tracing, correlation.
	if err := platform.Setup(a.App, platform.Options{Config: cfg.BaseConfiguration}); err != nil {
		return err
	}

	var err error

	// Durable portal-side state: the `signing` + `validation` schemas via the
	// EXECUTE-only signing_public role, or in-memory (dev/test).
	if cfg.StorePostgres() {
		a.store, err = store.NewPostgres(a.BackgroundContext(), cfg.StoreDSN)
		if err != nil {
			return err
		}
	} else {
		a.Log().Warn("no store DSN configured (SIGNING_STORE_DSN) — using in-memory store; signing jobs + records will NOT survive restarts (development only)")
		a.store = store.NewMemory()
	}

	// Inbound service authentication (go-authbyte DPoP): callers present
	// svc:signflow service tokens (the BFF's delegated tokens included).
	a.authClient, err = authclient.New(cfg.Auth)
	if err != nil {
		return fmt.Errorf("signflow: auth client: %w", err)
	}
	a.authMW = a.authClient.Authenticate()

	// Outbound DPoP service client — serves the calls to eparaksts-signer /
	// document-store / envelope / access-audit. Built only when at least one
	// collaborator base URL is configured.
	if cfg.OutboundEnabled() {
		a.outboundClient, err = authclient.New(cfg.OutboundAuthClientConfig())
		if err != nil {
			return fmt.Errorf("signflow: outbound auth client: %w", err)
		}
	} else {
		a.Log().Warn("no collaborator base URLs set (SIGNER_BASE_URL / DOCUMENT_BASE_URL / ENVELOPE_BASE_URL) — signflow cannot conduct a signing yet (skeleton/dev)")
	}

	// The conductor needs both the signer and the document service to drive a
	// hash-only XAdES signing end-to-end. Build it only when both are configured;
	// otherwise the signing routes report not-ready.
	if cfg.ConductorReady() {
		signer := clients.NewSigner(a.outboundClient, cfg.SignerBaseURL, cfg.SignerAudience)
		docs := clients.NewDocuments(a.outboundClient, cfg.DocumentBaseURL, cfg.DocumentAudience)
		a.conductor = orchestrator.New(a.store, signer, docs, a.Log())

		// Attach the envelope-service notifier only when it is configured: on finalize
		// the conductor reports the slot's completion so the envelope advances its
		// state machine. Unset → the notification is skipped (single-document/demo
		// path with no envelope service).
		if cfg.EnvelopeReady() {
			a.conductor.WithEnvelope(clients.NewEnvelope(a.outboundClient, cfg.EnvelopeBaseURL, cfg.EnvelopeAudience))
			a.Log().Info("envelope service configured — slot completions will be reported to it", zap.String("envelope_base_url", cfg.EnvelopeBaseURL))
		}
	} else {
		a.Log().Warn("signer + document base URLs are not both set — the signing routes will report not-ready until they are (SIGNER_BASE_URL + DOCUMENT_BASE_URL)")
	}

	// eIDAS-audit producer: signflow's lifecycle/validation evidence. Built only
	// when a broker is configured; with EIDAS_AUDIT_OUTBOX_DIR set, emission is
	// durable + non-blocking (events spool to disk and a background task publishes
	// them + flushes on shutdown). Without a broker the recorder is a no-op (dev).
	if err := a.initAudit(); err != nil {
		return err
	}

	return nil
}

// initAudit wires the eIDAS-audit emitter + recorder. Mirrors the signing
// provider's transport selection so both producers feed the same audit sink.
func (a *App) initAudit() error {
	cfg := a.config

	if cfg.Broker == nil || cfg.Broker.URL == "" {
		a.Log().Warn("BROKER_URL unset — signflow will NOT emit eIDAS-audit lifecycle/validation evidence (development); set BROKER_URL to publish to the audit sink")
		a.audit = audit.New(nil, a.Log())

		return nil
	}

	conn, err := natsbroker.Connect(natsbroker.Config{
		URL:     cfg.Broker.URL,
		TLSCert: cfg.Broker.TLSCert,
		TLSKey:  cfg.Broker.TLSKey,
		TLSCA:   cfg.Broker.TLSCA,
		Name:    cfg.ServiceName,
	})
	if err != nil {
		return fmt.Errorf("signflow: broker connect: %w", err)
	}
	a.natsConn = conn

	pub := broker.NewPublisher(natsbroker.NewTransport(conn), cfg.ServiceName)

	var outbox eidas.Outbox
	if dir := cfg.EidasAuditOutboxDir; dir != "" {
		ob, err := eidas.NewFileOutbox(dir, eidas.DefaultOutboxCapacity)
		if err != nil {
			return fmt.Errorf("signflow: eidas-audit outbox: %w", err)
		}
		outbox = ob
		a.Log().Info("eIDAS-audit emission is durable (non-blocking outbox)", zap.String("outbox_dir", dir))
	}

	emitter := eidas.New(pub, cfg.EIDASAuditTopic, eidas.Options{Outbox: outbox, Logger: a.Log()})
	if outbox != nil {
		if err := a.AddTask(audit.NewEmitterDrainTask("eidas-audit-drain", emitter)); err != nil {
			return fmt.Errorf("signflow: eidas-audit drain task: %w", err)
		}
	}

	a.audit = audit.New(emitter, a.Log())
	a.Log().Info("eIDAS-audit lifecycle/validation evidence → broker", zap.String("topic", cfg.EIDASAuditTopic))

	return nil
}

// Start verifies store connectivity (non-fatal) then starts the server + tasks.
func (a *App) Start() error {
	if err := a.store.Ping(a.BackgroundContext()); err != nil {
		a.Log().Warn("signing store not reachable at start — readiness will report not-ready until it recovers", zap.Error(err))
	}

	return a.App.Start()
}

// Stop releases the store, then stops the server, then closes the broker
// connection. Ordering matters: a.App.Stop() runs the audit drain task's Stop
// (flushing the outbox) while the broker connection is still live; only then is it
// closed.
func (a *App) Stop() {
	if a.store != nil {
		a.store.Close()
	}
	a.App.Stop()
	if a.natsConn != nil {
		a.natsConn.Close()
	}
}

// Config returns the loaded configuration.
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}

	return a.config
}

// Store returns the durable-state store (signing + validation schemas).
func (a *App) Store() store.Store { return a.store }

// AuthMiddleware returns the inbound service-authentication middleware.
func (a *App) AuthMiddleware() azugo.RequestHandlerFunc { return a.authMW }

// OutboundClient returns the outbound DPoP service client (nil until a
// collaborator base URL is configured).
func (a *App) OutboundClient() *authclient.Client { return a.outboundClient }

// Conductor returns the signing conductor (nil until both the signer and the
// document base URLs are configured).
func (a *App) Conductor() *orchestrator.Conductor { return a.conductor }

// Audit returns the eIDAS-audit lifecycle/validation recorder (a no-op recorder
// when no broker is configured).
func (a *App) Audit() *audit.Recorder { return a.audit }

// SetAuthMiddleware overrides the inbound auth middleware (test use only).
func (a *App) SetAuthMiddleware(mw azugo.RequestHandlerFunc) { a.authMW = mw }

// SetConductor injects the signing conductor (test use only).
func (a *App) SetConductor(c *orchestrator.Conductor) { a.conductor = c }
