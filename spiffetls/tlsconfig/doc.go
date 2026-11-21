// Package tlsconfig provides TLS configurations that authenticate peers using
// SPIFFE X509-SVIDs.
//
// # Session resumption
//
// Go does not call VerifyPeerCertificate on resumed TLS sessions, so the
// configurations returned by this package authenticate the peer in
// VerifyPeerCertificate on full handshakes and in VerifyConnection on resumed
// ones. A callback wrapping VerifyPeerCertificate on a returned configuration
// only runs on full handshakes; use VerifyConnection for checks that must
// also apply to resumed sessions. Chain onto VerifyConnection instead of
// replacing it, or resumed sessions will not be re-authenticated.
package tlsconfig
