package orchestrator

import "errors"

// ErrBindingMismatch is returned when the session's login method does not permit
// the requested signing flow. Routes map it to a 403.
var ErrBindingMismatch = errors.New("orchestrator: login method does not permit this signing flow")

// permitted maps a login method to the signing flows it may drive. The portal
// authentication method determines which signing flows a session is allowed to
// start: a card login signs with the card read the way the login read it — a Web
// eID login via Web eID or the CSC flow through the provider's browser extension,
// an eID Scan login via eID Scan or the CSC flow read by eID Scan — and an
// eParaksts Mobile login may drive its personal cloud signature and the
// mobile-bound organisation seal. The CSC flows authenticate with the eID card only,
// so no eParaksts Mobile login reaches them. This mirrors the same binding
// the authentication service enforces at login, so the two never diverge. The
// fine-grained signing credential within a flow is resolved by the signing
// service, not here.
var permitted = map[string][]string{
	"webEid":          {"webEid", "cscEidPlugin"},
	"eidScan":         {"eidScan", "cscEidScan"},
	"eparakstsMobile": {"eparakstsMobile", "eparakstsMobileEseal"},
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
