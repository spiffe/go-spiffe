package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// TLSClientConfig returns a TLS configuration which verifies and authorizes
// the server X509-SVID.
func TLSClientConfig(bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	config := new(tls.Config)
	HookTLSClientConfig(config, bundle, authorizer)
	return config
}

// HookTLSClientConfig sets up the TLS configuration to verify and authorize
// the server X509-SVID. If there is an existing callback set for
// VerifyPeerCertificate it will be wrapped by by this package and invoked
// after SPIFFE authentication has completed.
func HookTLSClientConfig(config *tls.Config, bundle x509bundle.Source, authorizer Authorizer) {
	resetAuthFields(config)
	config.InsecureSkipVerify = true
	config.VerifyPeerCertificate = WrapVerifyPeerCertificate(config.VerifyPeerCertificate, bundle, authorizer)
}

// MTLSClientConfig returns a TLS configuration which presents an X509-SVID
// to the server and verifies and authorizes the server X509-SVID.
func MTLSClientConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	config := new(tls.Config)
	HookMTLSClientConfig(config, svid, bundle, authorizer)
	return config
}

// HookMTLSClientConfig sets up the TLS configuration to present an X509-SVID
// to the server and verify and authorize the server X509-SVID. If there is an
// existing callback set for VerifyPeerCertificate it will be wrapped by by
// this package and invoked after SPIFFE authentication has completed.
func HookMTLSClientConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) {
	resetAuthFields(config)
	config.GetClientCertificate = GetClientCertificate(svid)
	config.InsecureSkipVerify = true
	config.VerifyPeerCertificate = WrapVerifyPeerCertificate(config.VerifyPeerCertificate, bundle, authorizer)
}

// MTLSWebClientConfig returns a TLS configuration which presents an X509-SVID
// to the server and verifies the server certificate using provided roots (or
// the system roots if nil).
func MTLSWebClientConfig(svid x509svid.Source, roots *x509.CertPool) *tls.Config {
	config := new(tls.Config)
	HookMTLSWebClientConfig(config, svid, roots)
	return config
}

// HookMTLSWebClientConfig sets up the TLS configuration to present an
// X509-SVID to the server and verifies the server certificate using the
// provided roots (or the system roots if nil).
func HookMTLSWebClientConfig(config *tls.Config, svid x509svid.Source, roots *x509.CertPool) {
	resetAuthFields(config)
	config.GetClientCertificate = GetClientCertificate(svid)
	config.RootCAs = roots
}

// TLSServerConfig returns a TLS configuration which presents an X509-SVID
// to the client and does not require or verify client certificates.
func TLSServerConfig(svid x509svid.Source) *tls.Config {
	config := new(tls.Config)
	HookTLSServerConfig(config, svid)
	return config
}

// HookTLSServerConfig sets up the TLS configuration to present an X509-SVID
// to the client and to not require or verify client certificates.
func HookTLSServerConfig(config *tls.Config, svid x509svid.Source) {
	resetAuthFields(config)
	config.GetCertificate = GetCertificate(svid)
}

// MTLSServerConfig returns a TLS configuration which presents an X509-SVID
// to the client and requires, verifies, and authorizes client X509-SVIDs.
func MTLSServerConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	config := new(tls.Config)
	HookMTLSServerConfig(config, svid, bundle, authorizer)
	return config
}

// HookMTLSServerConfig sets up the TLS configuration to present an X509-SVID
// to the client and require, verify, and authorize the client X509-SVID. If
// there is an existing callback set for VerifyPeerCertificate it will be
// wrapped by by this package and invoked after SPIFFE authentication has
// completed.
func HookMTLSServerConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) {
	resetAuthFields(config)
	config.ClientAuth = tls.RequireAnyClientCert
	config.GetCertificate = GetCertificate(svid)
	config.VerifyPeerCertificate = WrapVerifyPeerCertificate(config.VerifyPeerCertificate, bundle, authorizer)
}

// MTLSWebServerConfig returns a TLS configuration which presents a web
// server certificate to the client and requires, verifies, and authorizes
// client X509-SVIDs.
func MTLSWebServerConfig(cert *tls.Certificate, bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	config := new(tls.Config)
	HookMTLSWebServerConfig(config, cert, bundle, authorizer)
	return config
}

// HookMTLSWebServerConfig sets up the TLS configuration to presents a web
// server certificate to the client and require, verify, and authorize client
// X509-SVIDs. If there is an existing callback set for VerifyPeerCertificate
// it will be wrapped by by this package and invoked after SPIFFE
// authentication has completed.
func HookMTLSWebServerConfig(config *tls.Config, cert *tls.Certificate, bundle x509bundle.Source, authorizer Authorizer) {
	resetAuthFields(config)
	config.ClientAuth = tls.RequireAnyClientCert
	config.Certificates = []tls.Certificate{*cert}
	config.VerifyPeerCertificate = WrapVerifyPeerCertificate(config.VerifyPeerCertificate, bundle, authorizer)
}

// GetCertificate returns a GetCertificate callback for tls.Config. It uses the
// given X509-SVID getter to obtain a server X509-SVID for the TLS handshake.
func GetCertificate(svid x509svid.Source) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return getTLSCertificate(svid)
	}
}

// GetClientCertificate returns a GetClientCertificate callback for tls.Config.
// It uses the given X509-SVID getter to obtain a client X509-SVID for the TLS
// handshake.
func GetClientCertificate(svid x509svid.Source) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return getTLSCertificate(svid)
	}
}

// VerifyPeerCertificate returns a VerifyPeerCertificate callback for
// tls.Config. It uses the given bundle source and authorizer to verify and
// authorize X509-SVIDs provided by peers during the TLS handshake.
func VerifyPeerCertificate(bundle x509bundle.Source, authorizer Authorizer) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		id, certs, err := x509svid.ParseAndVerify(raw, bundle)
		if err != nil {
			return err
		}

		return authorizer(id, certs)
	}
}

// WrapVerifyPeerCertificate wraps a VeriyPeerCertificate callback, performing
// SPIFFE authentication against the peer certificates using the given bundle and
// authorizer. The wrapped callback will be passed the verified chains.
// Note: TLS clients must set `InsecureSkipVerify` when doing SPIFFE authentication to disable hostname verification.
func WrapVerifyPeerCertificate(wrapped func([][]byte, [][]*x509.Certificate) error, bundle x509bundle.Source, authorizer Authorizer) func([][]byte, [][]*x509.Certificate) error {
	if wrapped == nil {
		return VerifyPeerCertificate(bundle, authorizer)
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

func getTLSCertificate(svid x509svid.Source) (*tls.Certificate, error) {
	s, err := svid.GetX509SVID()
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: make([][]byte, 0, len(s.Certificates)),
		PrivateKey:  s.PrivateKey,
	}

	for _, svidCert := range s.Certificates {
		cert.Certificate = append(cert.Certificate, svidCert.Raw)
	}

	return cert, nil
}

func resetAuthFields(config *tls.Config) {
	config.Certificates = nil
	config.ClientAuth = tls.NoClientCert
	config.GetCertificate = nil
	config.GetClientCertificate = nil
	config.InsecureSkipVerify = false
	config.NameToCertificate = nil //nolint:staticcheck // setting to nil is OK
	config.RootCAs = nil
}
