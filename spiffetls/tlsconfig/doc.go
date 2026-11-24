// Package tlsconfig provides TLS configurations that authenticate peers using
// SPIFFE X509-SVIDs.
//
// Go skips VerifyPeerCertificate on resumed sessions, so the Hook functions
// also authenticate every handshake in VerifyConnection, and mTLS servers
// decline to resume sessions whose client certificate no longer verifies. Set
// VerifyPeerCertificate, VerifyConnection, WrapSession and UnwrapSession before
// hooking rather than replacing them after, and hook a configuration only once.
// mTLS server session tickets use the hooked configuration's keys, so set
// ticket keys on it rather than on a clone or a config returned by
// GetConfigForClient.
package tlsconfig
