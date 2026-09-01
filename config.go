package signflow

import (
	"strings"

	azugocfg "azugo.io/azugo/config"
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"

	"github.com/gmb-lib/go-authbyte/authclient"
	pkconfig "github.com/gmb-lib/go-platform-kit/config"
)

// Configuration is the signflow service configuration: the platform base config,
// the inbound go-authbyte DPoP validation, the collaborator base URLs it conducts
// (the signing provider, the document service, the envelope service), the
// outbound service-client identity, the durable-state DSN (signing + validation
// schemas), and the signing-evidence audit topic.
type Configuration struct {
	*pkconfig.BaseConfiguration `mapstructure:",squash"`

	// Auth is the inbound DPoP validation config (AUTH_ISSUER_URL /
	// SERVICE_AUDIENCE=svc:signflow / …). Inbound callers: Envelope/Workflow +
	// Portal-API, presenting svc:signflow service tokens.
	Auth *authclient.Configuration `mapstructure:"auth"`

	// --- Collaborators (the services signflow conducts, all DPoP service calls) ---
	SignerBaseURL   string `mapstructure:"signer_base_url" validate:"omitempty,url"`   // eparaksts-signer
	DocumentBaseURL string `mapstructure:"document_base_url" validate:"omitempty,url"` // document-store
	EnvelopeBaseURL string `mapstructure:"envelope_base_url" validate:"omitempty,url"` // envelope/workflow

	// Target audiences for the outbound service tokens (one per collaborator). The
	// token mint grants the registered scopes for this client against the audience.
	SignerAudience   string `mapstructure:"signer_audience"`
	DocumentAudience string `mapstructure:"document_audience"`
	EnvelopeAudience string `mapstructure:"envelope_audience"`

	// StoreDSN selects + configures the PostgreSQL backend for the `signing` +
	// `validation` schemas (reached via SECURITY DEFINER procedures under the
	// EXECUTE-only signing_public role). Empty → in-memory (dev/test).
	StoreDSN string `mapstructure:"signing_store_dsn"`

	// --- Outbound service-client identity (svc:signflow) ---
	// SERVICE_CLIENT_ID/SECRET authenticate the outbound DPoP service tokens.
	// OutboundIssuerURL points the token mint at the in-network auth address (the
	// `iss` stays Auth.IssuerURL).
	ServiceClientID     string `mapstructure:"service_client_id"`
	ServiceClientSecret string `mapstructure:"service_client_secret"`
	OutboundIssuerURL   string `mapstructure:"outbound_issuer_url" validate:"omitempty,url"`

	// --- Signing-evidence audit ---
	// The broker connection comes from BROKER_URL (BaseConfiguration.Broker); the
	// emitter publishes signflow's lifecycle/validation evidence to EIDASAuditTopic
	// (the same topic the audit sink consumes, shared with the signing provider).
	EIDASAuditTopic string `mapstructure:"eidas_audit_topic"`
	// EidasAuditOutboxDir, when set, makes eIDAS-audit emission durable +
	// non-blocking: events spool to this directory and a background drainer
	// publishes them, so the request path never blocks on the broker and evidence
	// survives a broker outage / restart. Unset → synchronous publish (dev/test).
	EidasAuditOutboxDir string `mapstructure:"eidas_audit_outbox_dir"`
}

// NewConfiguration returns the configuration skeleton for binding.
func NewConfiguration() *Configuration {
	return &Configuration{BaseConfiguration: pkconfig.New()}
}

// ServerCore returns the embedded azugo configuration.
func (c *Configuration) ServerCore() *azugocfg.Configuration {
	return c.Configuration
}

// Bind registers defaults and environment bindings.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.BaseConfiguration.Bind("", v)
	c.Auth = azugocfg.Bind(c.Auth, "auth", v)

	// Dev-only user-token concession (off by default).

	// Collaborators.
	_ = v.BindEnv("signer_base_url", "SIGNER_BASE_URL")
	_ = v.BindEnv("document_base_url", "DOCUMENT_BASE_URL")
	_ = v.BindEnv("envelope_base_url", "ENVELOPE_BASE_URL")

	// Outbound token audiences (default to the collaborators' service principals).
	v.SetDefault("signer_audience", "svc:eparaksts-signer")
	v.SetDefault("document_audience", "svc:document")
	v.SetDefault("envelope_audience", "svc:envelope")
	_ = v.BindEnv("signer_audience", "SIGNER_AUDIENCE")
	_ = v.BindEnv("document_audience", "DOCUMENT_AUDIENCE")
	_ = v.BindEnv("envelope_audience", "ENVELOPE_AUDIENCE")

	// Durable state.
	_ = v.BindEnv("signing_store_dsn", "SIGNING_STORE_DSN")

	// Outbound service-client identity.
	v.SetDefault("service_client_id", "svc:signflow")
	loadSecret(v, "service_client_secret", "SERVICE_CLIENT_SECRET")
	_ = v.BindEnv("service_client_id", "SERVICE_CLIENT_ID")
	_ = v.BindEnv("service_client_secret", "SERVICE_CLIENT_SECRET")
	_ = v.BindEnv("outbound_issuer_url", "OUTBOUND_ISSUER_URL")

	// eIDAS-audit producer. The topic default matches the audit sink + the signing
	// provider so both producers feed one hash-chain.
	v.SetDefault("eidas_audit_topic", "audit.signing")
	_ = v.BindEnv("eidas_audit_topic", "EIDAS_AUDIT_TOPIC")
	_ = v.BindEnv("eidas_audit_outbox_dir", "EIDAS_AUDIT_OUTBOX_DIR")
}

// Validate validates the full configuration tree.
func (c *Configuration) Validate(valid *validation.Validate) error {
	if err := c.BaseConfiguration.Validate(valid); err != nil {
		return err
	}
	if err := c.Auth.Validate(valid); err != nil {
		return err
	}

	return valid.Struct(c)
}

// OutboundEnabled reports whether at least one collaborator base URL is set, so
// the outbound DPoP service client is worth building.
func (c *Configuration) OutboundEnabled() bool {
	return strings.TrimSpace(c.SignerBaseURL) != "" ||
		strings.TrimSpace(c.DocumentBaseURL) != "" ||
		strings.TrimSpace(c.EnvelopeBaseURL) != ""
}

// StorePostgres reports whether a Postgres DSN is configured (else in-memory).
func (c *Configuration) StorePostgres() bool {
	return strings.TrimSpace(c.StoreDSN) != ""
}

// ConductorReady reports whether both collaborators needed to conduct a hash-only
// XAdES signing (the signer + the document service) are configured.
func (c *Configuration) ConductorReady() bool {
	return strings.TrimSpace(c.SignerBaseURL) != "" && strings.TrimSpace(c.DocumentBaseURL) != ""
}

// EnvelopeReady reports whether the envelope service is configured, so a slot's
// completion can be reported back to it. Unset → slot-completion notification is
// skipped (single-document/demo path with no envelope service).
func (c *Configuration) EnvelopeReady() bool {
	return strings.TrimSpace(c.EnvelopeBaseURL) != ""
}

// outboundIssuer returns the issuer base for the outbound service-token mint.
func (c *Configuration) outboundIssuer() string {
	if u := strings.TrimSpace(c.OutboundIssuerURL); u != "" {
		return u
	}

	return c.Auth.IssuerURL
}

// OutboundAuthClientConfig builds the OUTBOUND auth-client config: it reuses the
// validated inbound Auth settings and adds this service's client-credentials + the
// (optional) issuer override.
func (c *Configuration) OutboundAuthClientConfig() *authclient.Configuration {
	cfg := *c.Auth // copy the validated inbound config
	cfg.IssuerURL = c.outboundIssuer()
	cfg.ServiceClientID = c.ServiceClientID
	cfg.ServiceClientSecret = c.ServiceClientSecret

	return &cfg
}

// loadSecret resolves a secret from the secret store (Vault agent → <NAME>_FILE)
// and registers it as a default so an explicit env value still overrides it.
func loadSecret(v *viper.Viper, key, name string) {
	if secret, err := corecfg.LoadRemoteSecret(name); err == nil && secret != "" {
		v.SetDefault(key, secret)
	}
}
