// Package tlsconfig provides SPIFFE-aware TLS configuration.
//
// The implementation lives in
// [github.com/spiffe/go-spiffe/lite/spiffetls/tlsconfig].
// This package re-exports it so that existing importers of
// github.com/spiffe/go-spiffe/v2 continue to work unchanged. See that
// package for full documentation.
package tlsconfig

import lite "github.com/spiffe/go-spiffe/lite/spiffetls/tlsconfig"

// Type aliases. These must be aliases rather than definitions so that values
// cross the module boundary and interface satisfaction is preserved.
type (
	// Authorizer authorizes an X509-SVID given the SPIFFE ID and the chain of trust. The certificate chain starts with the X509-SVID certificate back to an X.509 root for the trust domain.
	Authorizer = lite.Authorizer

	// GetCertificateInfo is an empty placeholder for future expansion
	GetCertificateInfo = lite.GetCertificateInfo

	// GotCertificateInfo provides err and TLS certificate info to Trace
	GotCertificateInfo = lite.GotCertificateInfo

	// A Option changes the defaults used to by mTLS ClientConfig functions.
	Option = lite.Option

	// Trace is the interface to define what functions are triggered when functions in tlsconfig are called
	Trace = lite.Trace
)

var (
	// AdaptMatcher adapts any spiffeid.Matcher for use as an Authorizer which only authorizes the SPIFFE ID but otherwise ignores the verified chains.
	AdaptMatcher = lite.AdaptMatcher

	// AuthorizeAny allows any SPIFFE ID.
	AuthorizeAny = lite.AuthorizeAny

	// AuthorizeID allows a specific SPIFFE ID.
	AuthorizeID = lite.AuthorizeID

	// AuthorizeMemberOf allows any SPIFFE ID in the given trust domain.
	AuthorizeMemberOf = lite.AuthorizeMemberOf

	// AuthorizeOneOf allows any SPIFFE ID in the given list of IDs.
	AuthorizeOneOf = lite.AuthorizeOneOf

	// GetCertificate returns a GetCertificate callback for tls.Config. It uses the given X509-SVID getter to obtain a server X509-SVID for the TLS handshake.
	GetCertificate = lite.GetCertificate

	// GetClientCertificate returns a GetClientCertificate callback for tls.Config. It uses the given X509-SVID getter to obtain a client X509-SVID for the TLS handshake.
	GetClientCertificate = lite.GetClientCertificate

	// HookMTLSClientConfig sets up the TLS configuration to present an X509-SVID to the server and verify and authorize the server X509-SVID. If there is an existing callback set for VerifyPeerCertificate it will be wrapped by this package and invoked after SPIFFE authentication has completed.
	HookMTLSClientConfig = lite.HookMTLSClientConfig

	// HookMTLSServerConfig sets up the TLS configuration to present an X509-SVID to the client and require, verify, and authorize the client X509-SVID. If there is an existing callback set for VerifyPeerCertificate it will be wrapped by this package and invoked after SPIFFE authentication has completed.
	HookMTLSServerConfig = lite.HookMTLSServerConfig

	// HookMTLSWebClientConfig sets up the TLS configuration to present an X509-SVID to the server and verifies the server certificate using the provided roots (or the system roots if nil).
	HookMTLSWebClientConfig = lite.HookMTLSWebClientConfig

	// HookMTLSWebServerConfig sets up the TLS configuration to presents a web server certificate to the client and require, verify, and authorize client X509-SVIDs. If there is an existing callback set for VerifyPeerCertificate it will be wrapped by this package and invoked after SPIFFE authentication has completed.
	HookMTLSWebServerConfig = lite.HookMTLSWebServerConfig

	// HookTLSClientConfig sets up the TLS configuration to verify and authorize the server X509-SVID. If there is an existing callback set for VerifyPeerCertificate it will be wrapped by this package and invoked after SPIFFE authentication has completed.
	HookTLSClientConfig = lite.HookTLSClientConfig

	// HookTLSServerConfig sets up the TLS configuration to present an X509-SVID to the client and to not require or verify client certificates.
	HookTLSServerConfig = lite.HookTLSServerConfig

	// MTLSClientConfig returns a TLS configuration which presents an X509-SVID to the server and verifies and authorizes the server X509-SVID.
	MTLSClientConfig = lite.MTLSClientConfig

	// MTLSServerConfig returns a TLS configuration which presents an X509-SVID to the client and requires, verifies, and authorizes client X509-SVIDs.
	MTLSServerConfig = lite.MTLSServerConfig

	// MTLSWebClientConfig returns a TLS configuration which presents an X509-SVID to the server and verifies the server certificate using provided roots (or the system roots if nil).
	MTLSWebClientConfig = lite.MTLSWebClientConfig

	// MTLSWebServerConfig returns a TLS configuration which presents a web server certificate to the client and requires, verifies, and authorizes client X509-SVIDs.
	MTLSWebServerConfig = lite.MTLSWebServerConfig

	// TLSClientConfig returns a TLS configuration which verifies and authorizes the server X509-SVID.
	TLSClientConfig = lite.TLSClientConfig

	// TLSServerConfig returns a TLS configuration which presents an X509-SVID to the client and does not require or verify client certificates.
	TLSServerConfig = lite.TLSServerConfig

	// VerifyPeerCertificate returns a VerifyPeerCertificate callback for tls.Config. It uses the given bundle source and authorizer to verify and authorize X509-SVIDs provided by peers during the TLS handshake.
	VerifyPeerCertificate = lite.VerifyPeerCertificate

	// WithTrace will use the provided tracing callbacks when various TLS config functions gets invoked.
	WithTrace = lite.WithTrace

	// WrapVerifyPeerCertificate wraps a VerifyPeerCertificate callback, performing SPIFFE authentication against the peer certificates using the given bundle and authorizer. The wrapped callback will be passed the verified chains. Note: TLS clients must set `InsecureSkipVerify` when doing SPIFFE authentication to disable hostname verification.
	WrapVerifyPeerCertificate = lite.WrapVerifyPeerCertificate
)
