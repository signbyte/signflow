package store

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestMapCodeNotFound(t *testing.T) {
	err := mapCode("signing.get_job", "signing:not_found", "job absent")
	qt.Assert(t, qt.ErrorIs(err, ErrNotFound))
}

func TestMapCodeDuplicate(t *testing.T) {
	err := mapCode("signing.save_job", "signing:duplicate", "job exists")
	qt.Assert(t, qt.ErrorIs(err, ErrDuplicate))
}

func TestMapCodeUnknownWrapsDetails(t *testing.T) {
	err := mapCode("signing.save_job", "signing:invalid_input", "bad flow")
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.StringContains(err.Error(), "signing.save_job"))
	qt.Assert(t, qt.StringContains(err.Error(), "signing:invalid_input"))
	qt.Assert(t, qt.StringContains(err.Error(), "bad flow"))
	qt.Assert(t, qt.Not(qt.ErrorIs(err, ErrNotFound)))
	qt.Assert(t, qt.Not(qt.ErrorIs(err, ErrDuplicate)))
}

func TestPutOptSkipsEmptyValue(t *testing.T) {
	body := map[string]any{}
	putOpt(body, "login_method", "")
	qt.Assert(t, qt.Equals(len(body), 0))
}

func TestPutOptAddsNonEmptyValue(t *testing.T) {
	body := map[string]any{}
	putOpt(body, "login_method", "eparakstsMobile")
	qt.Assert(t, qt.Equals(body["login_method"], "eparakstsMobile"))
}
