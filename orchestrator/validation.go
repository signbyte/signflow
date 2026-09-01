package orchestrator

import (
	"time"

	answer "github.com/gmb-lib/go-validation-answer"
)

// The validation answer — the normalized field set, its verdict vocabulary,
// and the report normalization itself — is owned by the shared
// validation-answer library, so every consumer serves and renders one shape.
// The aliases below keep this package's established names.

// ValidationResult is the normalized validation answer for one signed
// document (the shared wire shape). See the validation-answer library for the
// field semantics.
type ValidationResult = answer.Validation

// SignatureValidation is the normalized answer for one signature within a
// signed document — a container can hold several (parallel co-signatures).
type SignatureValidation = answer.Signature

// normalizeReport maps a verbatim provider validation report onto the
// normalized answer (delegated to the shared library), stamped with the moment
// the validation ran — validation is time-anchored (revocation can post-date
// it), so an answer rendered later is presented "as of" this moment, never as
// current.
func normalizeReport(raw []byte) (*ValidationResult, error) {
	res, err := answer.NormalizeReport(raw)
	if err != nil {
		return nil, err
	}
	res.ValidatedAt = time.Now().UTC().Format(time.RFC3339)

	return res, nil
}
