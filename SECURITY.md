# Security policy

This service conducts a signing. It decides whether a session is allowed to sign with the flow it
asked for, resolves *which document* is actually signed, drives the signing provider, owns the
durable **signature record**, and computes the **validation answer** a person is shown. It holds no
signing keys, no qualified-trust-service credentials, and — on the hash-only path — no document
bytes.

So its failures are not cryptographic. They are failures of **authority** (a signing that should
have been refused), of **identity of the object** (signing something other than what the person
meant), and of **evidence** (a record or an answer that says something other than what happened).
All three end in a legally effective signature that nobody can honestly account for.

Please report security problems privately. Do not open a public issue, pull request or discussion
for anything that could be exploited before a fix exists.

## How to report

Use **[private vulnerability reporting](https://github.com/signbyte/signflow/security/advisories/new)**
on this repository. The report stays visible only to you and the maintainers until an advisory is
published, and it gives us one place to discuss and co-ordinate a fix with you.

Please include, as far as you can establish it:

- what the problem is, and what an attacker gains from it;
- the smallest set of steps that reproduces it, and against which version or commit;
- which signing flow and login method it needs, and the configuration it needs if it only appears
  under particular settings;
- whether you have told anyone else, and whether a disclosure date already binds you.

**Please do not send us real tokens, certificates, signed containers or personal data.** A redacted
trace, or the shape of the value, explains almost any finding here.

## What happens next

- We acknowledge a report within **five working days**.
- We tell you whether we can reproduce it, and what we think its severity is, as soon as we know.
- We keep you updated while a fix is prepared, and we agree a disclosure date with you. Our default
  is to publish an advisory once a fix is available, and in any case within **90 days** of the
  report — earlier if the problem is already public or being exploited.
- We credit you in the advisory unless you would rather stay anonymous.

There is no bug-bounty programme. We are grateful anyway, and we say so publicly.

## What we consider most serious

**The binding gate failing open.** The authentication method a session logged in with decides which
signing flows it may drive, the check runs before any provider work, and an unknown or absent
method must permit *nothing*. Anything that lets a signing begin outside that rule — a method that
is not recognised being treated as permissive, a flow reaching the provider before the check, a
path into the conductor that skips it — is the most serious class here, because it produces a
qualified signature under an authentication that was never good enough for it.

**Signing the wrong document.** Which document is signed is resolved server-side from the chain
root on purpose: the caller's document id is deliberately not trusted, because a co-signer's client
can hold a stale one. Serious findings are anything that lets a caller steer that resolution, any
path that falls back to the client-supplied id, and any case where the resolved head is not the
chain's current live head — which would silently drop the previous signer's signature.

**The validation answer saying more than the report does.** The portal shows a person this answer.
Reporting a signature as valid, qualified, or covering a document when the provider's report does
not say so is the worst version; mapping an unrecognised status or level code into a favourable one
rather than passing it through is the same defect with a smaller blast radius.

**Acting as the wrong subject.** Document and envelope reads act on behalf of the signing user
through token exchange, fail-closed. Any fallback to this service's own identity, any exchange for
a different subject, or any path that reaches a user-owned document without a subject token is a
serious finding — it is how one person's document becomes reachable through another's signing.

**The signature record and the evidence.** The record is what later accounts for a signature, so a
record naming the wrong slot, flow, login method or level of assurance is a security defect and not
a data-quality one. Likewise: a replayed poll recording a second signature (finalisation is
idempotent for exactly this reason); an audit event carrying what it must not — document bytes,
certificates, verbatim report contents, signer names or any personal data; and the verbatim
provider report being stored anywhere.

**The service boundary.** Reaching the HTTP surface without a valid, DPoP-bound token, with a token
bound to a different key, or with a scope the endpoint does not require. This surface is
cluster-internal and is not meant to be reachable by a browser or an end user at all.

**Bytes that should not persist.** Document bytes surviving the transient PAdES conduit, or any
byte reaching this service on the hash-only path where only a digest belongs.

**Reaching the database outside its procedures.** All durable state goes through security-definer
procedures under an execute-only role; a direct table access is a finding even if it reads
correctly today.

Denial of service and findings that need an already-compromised host or an already-authenticated
administrator are in scope but lower priority. Reports about outdated dependencies are welcome
where you can show the vulnerable path is actually reachable.

## What is deliberately not a finding

This service performs **no cryptography** and holds **no keys or qualified-trust-service
credentials**. It does not evaluate certificate chains, revocation or timestamps — the signing
provider owns the signing session and certificate selection, and validation is the validator's
answer. That a bad certificate or an invalid signature got through is not a defect here unless this
service mishandled the answer it was given, or reported it as better than it was.

A report that an API *implies* one of those guarantees, or that a caller is likely to read it that
way, is a real finding. A report that this service failed to catch what a validator is responsible
for catching is not.

Best-effort behaviour that is documented as best-effort — audit emission never blocking a signing,
and validation at signing time being allowed to fail and be retried later — is deliberate. A report
that one of them *silently changes the recorded outcome* is very much a finding; a report that one
of them did not block is not.

## Scope

This policy covers the code in this repository. It does not cover the signing provider, the
document or envelope services, the authentication service, the external qualified trust service, or
any deployment operated by someone other than us — report those to the parties that run them. How a
deployment configures this service is the operator's responsibility, but a report that a **default**
is unsafe is very much in scope.

## Supported versions

Security fixes land on the most recent release. Older tags are not patched; if you are pinned to
one, the fix is to move forward.
