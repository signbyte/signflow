package routes

import (
	"encoding/json"
	"testing"

	answer "github.com/gmb-lib/go-validation-answer"

	"github.com/go-quicktest/qt"
)

// The validation answer's wire JSON is a frozen contract: consumers parse these
// exact keys. This golden pins the serialized form of a normalized report (with
// the route-added caller context), so a change to the shared answer shape or
// its tags can never slip through as a refactoring side effect.
func TestValidationAnswerWireGolden(t *testing.T) {
	report := `{"data":{"signatureForm":"ASiC-E",` +
		`"signaturesExt":[{"id":"S1","indication":"TOTAL-PASSED","signatureLevel":"QESIG",` +
		`"signatureFormat":"XAdES_BASELINE_LT",` +
		`"signerExt":{"signedby":"TEST SIGNER","signerSerialNumber":"` + testIDCodeLV(1) + `"},` +
		`"timeStamp":"2026-06-27T07:22:26Z","ocspResponceTime":"2026-06-27T07:22:27Z",` +
		`"maximumValidityTime":"2030-01-01T00:00:00Z","errors":[],"warnings":[]}],` +
		`"signaturesCount":1,"validSignaturesCount":1,` +
		`"validatedDocument":{"fileName":"c.asice","includedFiles":["contract.pdf"]}}}`

	res, err := answer.NormalizeReport([]byte(report))
	qt.Assert(t, qt.IsNil(err))
	res.SignatureID = "sig-1"

	raw, err := json.Marshal(res)
	qt.Assert(t, qt.IsNil(err))

	golden := `{"signatureId":"sig-1","verdict":"PASSED","format":"XAdES_BASELINE_LT",` +
		`"level":"QES","signer":"TEST SIGNER","signerSerial":"` + testIDCodeLV(1) + `",` +
		`"containerForm":"ASiC-E","signingTime":"2026-06-27T07:22:26Z",` +
		`"revocationTime":"2026-06-27T07:22:27Z","maxValidityTime":"2030-01-01T00:00:00Z",` +
		`"signedFiles":["contract.pdf"],` +
		`"signatures":[{"verdict":"PASSED","format":"XAdES_BASELINE_LT","level":"QES",` +
		`"signer":"TEST SIGNER","signerSerial":"` + testIDCodeLV(1) + `",` +
		`"signingTime":"2026-06-27T07:22:26Z","revocationTime":"2026-06-27T07:22:27Z",` +
		`"maxValidityTime":"2030-01-01T00:00:00Z"}],"pass":true}`
	qt.Assert(t, qt.Equals(string(raw), golden))
}
