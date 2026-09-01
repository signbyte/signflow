# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.1.0

Initial code.

The signing conductor as first released: turns a "sign this slot with this flow" request into
a completed, validated signature — decides how a slot is signed, drives the signing provider
through the multi-step signing dance, reconciles the result onto the document and the
envelope, owns the durable signature record, and owns the validation answer the portal shows
the user. AGPL-3.0-only.
