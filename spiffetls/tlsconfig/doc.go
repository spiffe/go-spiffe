// Package tlsconfig provides TLS configurations that authenticate peers using
// SPIFFE X509-SVIDs.
//
// Go skips VerifyPeerCertificate on resumed sessions, so the Hook functions
// also authenticate them in VerifyConnection. Chain onto VerifyConnection
// rather than replacing it, and hook a configuration only once.
package tlsconfig
