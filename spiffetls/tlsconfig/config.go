package tlsconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// TLSClientConfig returns a TLS configuration which verifies and authorizes
// the server X509-SVID.
func TLSClientConfig(bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *tls.Config {
	config := newTLSConfig()
	HookTLSClientConfig(config, bundle, authorizer, opts...)
	return config
}

// HookTLSClientConfig sets up the TLS configuration to verify and authorize
// the server X509-SVID. Existing VerifyPeerCertificate and VerifyConnection
// callbacks are wrapped and invoked after SPIFFE authentication.
func HookTLSClientConfig(config *tls.Config, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) {
	resetAuthFields(config)
	config.InsecureSkipVerify = true
	hookPeerVerification(config, bundle, authorizer, opts...)
}

// A Option changes the defaults used to by mTLS ClientConfig functions.
type Option interface {
	apply(*options)
}

type option func(*options)

func (fn option) apply(o *options) { fn(o) }

type options struct {
	trace Trace
}

func newOptions(opts []Option) *options {
	out := &options{}
	for _, opt := range opts {
		opt.apply(out)
	}
	return out
}

// WithTrace will use the provided tracing callbacks
// when various TLS config functions gets invoked.
func WithTrace(trace Trace) Option {
	return option(func(opts *options) {
		opts.trace = trace
	})
}

// MTLSClientConfig returns a TLS configuration which presents an X509-SVID
// to the server and verifies and authorizes the server X509-SVID.
func MTLSClientConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *tls.Config {
	config := newTLSConfig()
	HookMTLSClientConfig(config, svid, bundle, authorizer, opts...)
	return config
}

// HookMTLSClientConfig sets up the TLS configuration to present an X509-SVID
// to the server and verify and authorize the server X509-SVID. Existing
// VerifyPeerCertificate and VerifyConnection callbacks are wrapped and
// invoked after SPIFFE authentication.
func HookMTLSClientConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) {
	resetAuthFields(config)
	config.GetClientCertificate = GetClientCertificate(svid, opts...)
	config.InsecureSkipVerify = true
	hookPeerVerification(config, bundle, authorizer, opts...)
}

// MTLSWebClientConfig returns a TLS configuration which presents an X509-SVID
// to the server and verifies the server certificate using provided roots (or
// the system roots if nil).
func MTLSWebClientConfig(svid x509svid.Source, roots *x509.CertPool, opts ...Option) *tls.Config {
	config := newTLSConfig()
	HookMTLSWebClientConfig(config, svid, roots, opts...)
	return config
}

// HookMTLSWebClientConfig sets up the TLS configuration to present an
// X509-SVID to the server and verifies the server certificate using the
// provided roots (or the system roots if nil).
func HookMTLSWebClientConfig(config *tls.Config, svid x509svid.Source, roots *x509.CertPool, opts ...Option) {
	resetAuthFields(config)
	config.GetClientCertificate = GetClientCertificate(svid, opts...)
	config.RootCAs = roots
}

// TLSServerConfig returns a TLS configuration which presents an X509-SVID
// to the client and does not require or verify client certificates.
func TLSServerConfig(svid x509svid.Source, opts ...Option) *tls.Config {
	config := newTLSConfig()
	HookTLSServerConfig(config, svid, opts...)
	return config
}

// HookTLSServerConfig sets up the TLS configuration to present an X509-SVID
// to the client and to not require or verify client certificates.
func HookTLSServerConfig(config *tls.Config, svid x509svid.Source, opts ...Option) {
	resetAuthFields(config)
	config.GetCertificate = GetCertificate(svid, opts...)
}

// MTLSServerConfig returns a TLS configuration which presents an X509-SVID
// to the client and requires, verifies, and authorizes client X509-SVIDs.
func MTLSServerConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *tls.Config {
	config := newTLSConfig()
	HookMTLSServerConfig(config, svid, bundle, authorizer, opts...)
	return config
}

// HookMTLSServerConfig sets up the TLS configuration to present an X509-SVID
// to the client and require, verify, and authorize the client X509-SVID.
// Existing VerifyPeerCertificate and VerifyConnection callbacks are wrapped
// and invoked after SPIFFE authentication.
func HookMTLSServerConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) {
	resetAuthFields(config)
	config.ClientAuth = tls.RequireAnyClientCert
	config.GetCertificate = GetCertificate(svid, opts...)
	hookPeerVerification(config, bundle, authorizer, opts...)
	hookServerSessions(config, bundle)
}

// MTLSWebServerConfig returns a TLS configuration which presents a web
// server certificate to the client and requires, verifies, and authorizes
// client X509-SVIDs.
func MTLSWebServerConfig(cert *tls.Certificate, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *tls.Config {
	config := newTLSConfig()
	HookMTLSWebServerConfig(config, cert, bundle, authorizer, opts...)
	return config
}

// HookMTLSWebServerConfig sets up the TLS configuration to presents a web
// server certificate to the client and require, verify, and authorize client
// X509-SVIDs. Existing VerifyPeerCertificate and VerifyConnection callbacks
// are wrapped and invoked after SPIFFE authentication.
func HookMTLSWebServerConfig(config *tls.Config, cert *tls.Certificate, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) {
	resetAuthFields(config)
	config.ClientAuth = tls.RequireAnyClientCert
	config.Certificates = []tls.Certificate{*cert}
	hookPeerVerification(config, bundle, authorizer, opts...)
	hookServerSessions(config, bundle)
}

// GetCertificate returns a GetCertificate callback for tls.Config. It uses the
// given X509-SVID getter to obtain a server X509-SVID for the TLS handshake.
func GetCertificate(svid x509svid.Source, opts ...Option) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	opt := newOptions(opts)
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return getTLSCertificate(svid, opt.trace)
	}
}

// GetClientCertificate returns a GetClientCertificate callback for tls.Config.
// It uses the given X509-SVID getter to obtain a client X509-SVID for the TLS
// handshake.
func GetClientCertificate(svid x509svid.Source, opts ...Option) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	opt := newOptions(opts)
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return getTLSCertificate(svid, opt.trace)
	}
}

// VerifyPeerCertificate returns a VerifyPeerCertificate callback for
// tls.Config. It uses the given bundle source and authorizer to verify and
// authorize X509-SVIDs provided by peers during the TLS handshake. Go does
// not call it on resumed sessions; use VerifyConnection instead.
func VerifyPeerCertificate(bundle x509bundle.Source, authorizer Authorizer, opts ...Option) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		id, certs, err := x509svid.ParseAndVerify(raw, bundle)
		if err != nil {
			return err
		}

		return authorizer(id, certs)
	}
}

// WrapVerifyPeerCertificate wraps a VerifyPeerCertificate callback, performing
// SPIFFE authentication against the peer certificates using the given bundle and
// authorizer. The wrapped callback will be passed the verified chains.
// Go does not call it on resumed sessions; use WrapVerifyConnection instead.
// Note: TLS clients must set `InsecureSkipVerify` when doing SPIFFE authentication to disable hostname verification.
func WrapVerifyPeerCertificate(wrapped func([][]byte, [][]*x509.Certificate) error, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) func([][]byte, [][]*x509.Certificate) error {
	if wrapped == nil {
		return VerifyPeerCertificate(bundle, authorizer, opts...)
	}

	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		id, certs, err := x509svid.ParseAndVerify(raw, bundle)
		if err != nil {
			return err
		}

		if err := authorizer(id, certs); err != nil {
			return err
		}

		return wrapped(raw, certs)
	}
}

// VerifyConnection returns a VerifyConnection callback for tls.Config. It
// verifies and authorizes the peer X509-SVID on every handshake, including
// resumed sessions.
// On a TLS 1.3 server, a rejected resumption makes the client retry the same
// ticket; HookMTLSServerConfig avoids this by declining resumption instead.
// Note: TLS clients must set `InsecureSkipVerify` when doing SPIFFE authentication to disable hostname verification.
func VerifyConnection(bundle x509bundle.Source, authorizer Authorizer, opts ...Option) func(tls.ConnectionState) error {
	return WrapVerifyConnection(nil, bundle, authorizer, opts...)
}

// WrapVerifyConnection wraps a VerifyConnection callback, invoking it after
// SPIFFE authentication of the peer on every handshake, including resumed
// sessions. The wrapped callback receives the verified chains in VerifiedChains.
// Note: TLS clients must set `InsecureSkipVerify` when doing SPIFFE authentication to disable hostname verification.
func WrapVerifyConnection(wrapped func(tls.ConnectionState) error, bundle x509bundle.Source, authorizer Authorizer, _ ...Option) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		chains, err := verifyPeer(cs.PeerCertificates, bundle, authorizer)
		if err != nil {
			return err
		}
		if wrapped != nil {
			cs.VerifiedChains = chains
			return wrapped(cs)
		}
		return nil
	}
}

func verifyPeer(certs []*x509.Certificate, bundle x509bundle.Source, authorizer Authorizer) ([][]*x509.Certificate, error) {
	id, chains, err := x509svid.Verify(certs, bundle)
	if err != nil {
		return nil, err
	}
	if err := authorizer(id, chains); err != nil {
		return nil, err
	}
	return chains, nil
}

// hookPeerVerification authenticates in both callbacks, so replacing
// VerifyPeerCertificate cannot leave a handshake unauthenticated, but
// authorizes only in VerifyConnection, so the authorizer runs once.
func hookPeerVerification(config *tls.Config, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) {
	wrapped := config.VerifyPeerCertificate
	config.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		_, chains, err := x509svid.ParseAndVerify(raw, bundle)
		if err != nil {
			return err
		}
		if wrapped != nil {
			return wrapped(raw, chains)
		}
		return nil
	}
	config.VerifyConnection = WrapVerifyConnection(config.VerifyConnection, bundle, authorizer, opts...)
}

// peerChainExtra marks the SessionState.Extra entry holding the client
// certificate chain, which SessionState does not expose.
var peerChainExtra = []byte("go-spiffe/peer-chain/v1:")

// hookServerSessions makes the server decline resuming a session whose client
// certificate no longer verifies. Rejecting it later in VerifyConnection would
// fail every TLS 1.3 reconnect, since the client keeps its ticket.
func hookServerSessions(config *tls.Config, bundle x509bundle.Source) {
	wrapSession, unwrapSession := config.WrapSession, config.UnwrapSession

	config.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
		entry := bytes.Clone(peerChainExtra)
		for _, cert := range cs.PeerCertificates {
			entry = append(entry, cert.Raw...)
		}
		ss.Extra = append(ss.Extra, entry)
		if wrapSession != nil {
			return wrapSession(cs, ss)
		}
		return config.EncryptTicket(cs, ss)
	}

	config.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		var ss *tls.SessionState
		var err error
		if unwrapSession != nil {
			ss, err = unwrapSession(identity, cs)
		} else {
			ss, err = config.DecryptTicket(identity, cs)
		}
		if ss == nil || err != nil {
			return ss, err
		}
		for _, entry := range ss.Extra {
			if chain, ok := bytes.CutPrefix(entry, peerChainExtra); ok {
				certs, err := x509.ParseCertificates(chain)
				if err == nil {
					if _, _, err := x509svid.Verify(certs, bundle); err == nil {
						return ss, nil
					}
				}
				break
			}
		}
		// Fall back to a full handshake.
		return nil, nil
	}
}

func getTLSCertificate(svid x509svid.Source, trace Trace) (*tls.Certificate, error) {
	var traceVal any
	if trace.GetCertificate != nil {
		traceVal = trace.GetCertificate(GetCertificateInfo{})
	}

	s, err := svid.GetX509SVID()
	if err != nil {
		if trace.GotCertificate != nil {
			trace.GotCertificate(GotCertificateInfo{Err: err}, traceVal)
		}
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: make([][]byte, 0, len(s.Certificates)),
		PrivateKey:  s.PrivateKey,
		Leaf:        s.Certificates[0],
	}

	for _, svidCert := range s.Certificates {
		cert.Certificate = append(cert.Certificate, svidCert.Raw)
	}

	if trace.GotCertificate != nil {
		trace.GotCertificate(GotCertificateInfo{Cert: cert}, traceVal)
	}

	return cert, nil
}

func newTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

func resetAuthFields(config *tls.Config) {
	if config.MinVersion < tls.VersionTLS12 {
		config.MinVersion = tls.VersionTLS12
	}
	config.Certificates = nil
	config.ClientAuth = tls.NoClientCert
	config.GetCertificate = nil
	config.GetClientCertificate = nil
	config.InsecureSkipVerify = false
	config.NameToCertificate = nil //nolint:staticcheck // setting to nil is OK
	config.RootCAs = nil
}
