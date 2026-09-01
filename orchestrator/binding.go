package orchestrator

import "errors"

// ErrBindingMismatch is returned when the session's login method does not permit
// the requested signing flow. Routes map it to a 403.
var ErrBindingMismatch = errors.New("orchestrator: login method does not permit this signing flow")

// permitted maps a login method to the signing flows it may drive. The portal
// authentication method determines which signing flows a session is allowed to
// start: a Web eID login signs only via Web eID, an eID Scan login only via eID
// Scan, and an eParaksts Mobile login may drive its personal cloud signature, the
// mobile-bound organisation seal, and the CSC flow. This mirrors the same binding
// the authentication service enforces at login, so the two never diverge. The
// fine-grained signing credential within a flow is resolved by the signing
// service, not here.
var permitted = map[string][]string{
	"webEid":          {"webEid"},
	"eidScan":         {"eidScan"},
	"eparakstsMobile": {"eparakstsMobile", "eparakstsMobileEseal", "csc"},
}

// permittedFlows returns the signing flows a login method may drive. An unknown or
// empty method permits nothing (the binding fails closed).
func permittedFlows(loginMethod string) []string {
	return permitted[loginMethod]
}

// checkBinding allows the request only when the requested flow is reachable from
// the session's login method. An absent or unknown method permits nothing — the
// gate fails closed.
func checkBinding(loginMethod, flow string) error {
	for _, f := range permittedFlows(loginMethod) {
		if f == flow {
			return nil
		}
	}

	return ErrBindingMismatch
}
