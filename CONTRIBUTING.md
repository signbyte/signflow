# Contributing

Thank you for considering a contribution. Bug reports, fixes and improvements are welcome. For
anything that could be exploited, use the private route in [SECURITY.md](SECURITY.md) — never a
public issue.

For anything larger than a small fix, please open an issue first and describe what you want to
change and why. This service decides whether a legally effective signature may be produced and what
gets signed, so a change that fights its design is better redirected before it is written than
after.

## Building and testing

You need the Go toolchain at the version named in [go.mod](go.mod). Every dependency is public, so
nothing needs credentials, a `GOPRIVATE` setting or a vendor directory. The gate a change must pass
is the same one CI runs:

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
```

Three more checks run in CI and are worth running before you push:

- **Lint** — `golangci-lint run`, at the version pinned in
  [.github/workflows/ci.yml](.github/workflows/ci.yml); the repo's [.golangci.yml](.golangci.yml)
  carries the configuration.
- **Vulnerabilities** — `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`.
- **The image** — CI builds it, generates an SBOM, fails on HIGH/CRITICAL findings from a
  vulnerability scan, and signs it. A change to the [Dockerfile](Dockerfile) should be built
  locally before you push, because that job is slow to fail.

The committed tree must already be tidy: CI runs `go mod tidy -diff` and fails if it would change
anything, so run `go mod tidy` after touching dependencies. All Go code is `gofmt`-formatted, and
`.gitattributes` pins Go files to LF line endings — leave that alone, it keeps the tidy-diff gate
stable across platforms.

The tests need no database and no collaborator service: the document, envelope and signing-provider
surfaces are behind interfaces with test doubles. If a change makes a test need a live system, that
is a design signal worth raising in the issue rather than solving with a fixture.

## What a change to this service needs

Read the **Security invariants** and **Login⇒signing binding** sections of the [README](README.md)
before changing anything on the signing path. They are not statements of good intent; each one is
the reason a specific class of defect cannot happen, and a change that weakens one is the change,
not a side effect.

The three that carry the most weight:

- **The binding gate is fail-closed and runs first.** An unknown or absent login method permits
  nothing, and no provider work happens before the check. A change to the permitted-flow table, to
  where the gate runs, or to how a method is read from the token needs a test that a *rejected*
  combination still cannot proceed — not only that a permitted one can.
- **Which document is signed is resolved server-side.** The chain root comes from the envelope and
  the current live head from the document service; the caller's document id is deliberately not
  trusted, because a co-signer's client can hold a stale one. Anything that reintroduces the client
  id into that decision, or that guesses when the head cannot be resolved, drops a signature
  silently. It fails instead, on purpose.
- **Finalisation is idempotent.** The job is marked conductor-terminal before validation runs so a
  replayed poll cannot record a second signature. Retry or polling logic added near it needs to say
  why it cannot double-record.

Also load-bearing:

- **On-behalf-of has no fallback.** Document and envelope reads act as the signing user through
  token exchange; a call without a subject token must fail rather than quietly use this service's
  own identity.
- **The validation answer never improves on the report.** Unrecognised status or level codes pass
  through unchanged rather than being mapped to something plausible, and the verbatim provider
  report is not stored — only the normalised answer.
- **Audit events stay lean and PII-free** — references, not contents: no bytes, no certificates, no
  report bodies, no signer names. Emission is best-effort and must never block or roll back a
  signing.
- **Tables are never touched directly.** Durable state goes through the security-definer procedures
  under an execute-only role.
- **The hash-only path stays byte-free.** Only a digest transits this service for XAdES and ASiC-E;
  the PAdES conduit is transient and buffered nowhere durably.

## Proposing a change

- Work on a branch and open a pull request against `develop`. `develop` is merged into `main` and
  tagged there when a release goes out, so `main` is never committed to directly.
- **Sign off every commit.** This project uses the
  [Developer Certificate of Origin](https://developercertificate.org/): by adding a
  `Signed-off-by: Your Name <you@example.org>` line you certify that you wrote the change or
  otherwise have the right to submit it under this project's licence. `git commit -s` adds the line
  for you; the name and address must match the commit author. A pull request whose commits lack it
  fails the DCO check and cannot be merged.
- Keep the change focused: one concern per pull request.
- A change in behaviour comes with a test that fails without it.
- Match the style around you — naming, error handling, comment density. Comments explain what and
  why in plain domain terms; a reference to a standard is cited in the bracket form already used in
  the code.
- A change that an operator or an integrator can feel — a new or changed endpoint, field, error
  code, configuration knob or default — belongs in [CHANGELOG.md](CHANGELOG.md) in the same pull
  request.
- Pull requests also run a dependency review. A new dependency needs a reason the standard library
  or the existing ones cannot cover.

## Licence

This project is licensed under the **GNU Affero General Public License, version 3 only** (see
[LICENSE](LICENSE)). By submitting a contribution you agree that it is provided under the same
licence.

Worth knowing what AGPL means here, because this is a service rather than a library: if you run a
modified version and let others interact with it over a network, the licence requires you to offer
those users the corresponding source of your modified version. Using it unmodified, or modifying it
for purely internal use with no network users, does not trigger that.
