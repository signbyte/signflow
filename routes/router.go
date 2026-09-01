// Package routes registers the signflow (Signing Orchestrator) HTTP API.
package routes

import (
	signflow "github.com/signbyte/signflow"
)

type router struct {
	*signflow.App
}

// Init registers all routes. The inbound API is DPoP-gated (go-authbyte; aud
// svc:signflow); callers are the Envelope/Workflow service and Portal-API.
func Init(a *signflow.App) error {
	r := &router{App: a}

	// Public liveness/readiness.
	a.Get("/healthz", r.healthz)
	a.Get("/readyz", r.readyz)

	// Authenticated API.
	v1 := a.Group("/api/v1")
	v1.Use(a.AuthMiddleware())

	// Signing lifecycle (the conductor).
	v1.Post("/signings", r.createSigning)
	v1.Get("/signings/{jobId}/status", r.signingStatus)
	v1.Post("/signings/{jobId}/client-signature", r.clientSignature)
	// Release a signing attempt's chain lock without declining (the signer cancelled at
	// the provider / picked the wrong method and will retry), so a co-signer isn't left
	// waiting on a dead attempt.
	v1.Post("/signings/{jobId}/abandon", r.abandonSigning)
	// A blocked co-signer's "wait until the chain frees" long-poll (avoids a countdown /
	// tight polling). Root path to avoid a static-vs-{jobId} route conflict.
	v1.Get("/chain-free", r.chainFree)

	// Validation answer (validate / re-validate).
	v1.Post("/validations", r.validate)
	v1.Post("/document-validations", r.validateDocument)
	v1.Post("/archive-timestamps", r.archiveTimestamp)

	return nil
}
