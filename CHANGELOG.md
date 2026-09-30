# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.2.0

### Changed — starting a signing waits for the signing service up to 90 s

Starting a signing now waits up to **90 s** for the signing service to begin the job, the same ceiling
validation and archive-timestamping already have; it used to give up after the default 15 s. The provider
behind the signing service sometimes takes a minute to answer a request of a signing, and the signing
service then began the job after signflow had already reported a failure. Nothing to configure.

### Changed — each card login may also sign through CSC, reading the card the same way

A Web eID login now permits `cscEidPlugin` besides `webEid`, and an eID Scan login permits `cscEidScan`
besides `eidScan`: the CSC flow that reads the card the way the login did. Neither crosses over — a Web eID
login asking for `cscEidScan` (or an eID Scan login asking for `cscEidPlugin`) is refused like any other
flow its login does not permit (`403 err:signing:bindingMismatch`).

```http
POST /api/v1/signings        (a session that logged in with Web eID)
{ "flow": "cscEidPlugin", "documentId": "…", … }
```

### Changed — the CSC signing flow is two flows

`flow` on a new signing accepts `cscEidScan` (the eID card read by a phone) and `cscEidPlugin` (the card in
a reader, through the provider's browser extension) in place of `csc`, which is now refused as invalid. An
eParaksts Mobile login no longer permits either: the CSC flows authenticate with the eID card only.

```http
POST /api/v1/signings
{ "flow": "cscEidScan", "documentId": "…", … }
```

Needs the database migration that knows the two names (the platform database's 2026-09-28 entry).

## v0.1.1

### Fixed — a version tag points at the signed image digest again

Publishing a release re-pointed the version tag by rewrapping the image manifest into a new
manifest list, which gave the tag a **different digest from the one the signature covers** — so
verifying the signature on a version tag failed. The retag is now a plain pull, tag and push, which
keeps the digest and therefore keeps the signature valid. Separately, a release published right
after a merge could race the branch build; the job now waits for the image to be published before
tagging.

**A version tag published before this needs one release re-publish** to be re-pointed at the signed
digest. Verifying the rolling `:develop` or `:latest` tag was never affected.

### Changed — the metrics endpoint no longer offers OpenMetrics

A scraper that asked for the OpenMetrics format by sending `Accept: application/openmetrics-text`
used to be answered in it, with the `# EOF` terminator that format requires. This service now
answers in the Prometheus text format whatever the scraper asks for, and writes no `# EOF`:

```http
GET /metrics
Accept: application/openmetrics-text

200 OK
Content-Type: text/plain; version=0.0.4; charset=utf-8
```

**The metric names, labels and values are unchanged**, so Prometheus — and anything else that
accepts the plain-text exposition format — needs nothing done. Two setups need a look: a scrape
configuration that *requires* the OpenMetrics content type, and a check that reads a missing
`# EOF` as a truncated scrape. Both need their expectation relaxed.

The endpoint itself is unchanged otherwise: still `/metrics` (or `METRICS_PATH`), still enabled by
default, and still answered only for trusted addresses (`METRICS_TRUSTED_IPS`, `127.0.0.1` by
default) — so if nothing scrapes this service, there is nothing to do. The change arrives from the
web framework this service is built on rather than from a change of its own, carried in with the
shared libraries below.

### Notes

- The shared libraries moved to their current releases — the auth client at v0.21.0 and the
  platform kit at v1.11.2 — which carried the web framework, the HTTP stack and the JOSE library up
  with them. No endpoint, field, error or setting of this service changed, and no configuration
  needs touching. The move also clears two published advisories in the cryptography library this
  service depends on; a third has no fix available yet and was already present before the move, and
  the vulnerability scanner reports nothing this service's own code can reach.

### Changed — the shared libraries move to their current releases

`go-platform-kit` v1.11.3, `go-authbyte` v0.23.1, `go-eidas-audit` v1.2.5 and
`go-validation-answer` v1.1.2. No endpoint, field, error or setting changes with them, nothing in
your configuration needs touching, and this service's own behaviour is unchanged — the validation
answer it produces has the same shape, and the frozen audit envelope is untouched. `go-authbyte`
crosses v0.23.0 on the way, which adds a way to tell a natural person's identity code from an
organisation's. The Postgres driver `pgx/v5` moves to v5.11.0 in the same pass.

## v0.1.0

Initial code.

The signing conductor as first released: turns a "sign this slot with this flow" request into
a completed, validated signature — decides how a slot is signed, drives the signing provider
through the multi-step signing dance, reconciles the result onto the document and the
envelope, owns the durable signature record, and owns the validation answer the portal shows
the user. AGPL-3.0-only.
