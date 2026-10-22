// Package x509svid provides X509-SVID related functionality.
//
// The implementation lives in
// [github.com/spiffe/go-spiffe/lite/svid/x509svid].
// This package re-exports it so that existing importers of
// github.com/spiffe/go-spiffe/v2 continue to work unchanged. See that
// package for full documentation.
package x509svid

import lite "github.com/spiffe/go-spiffe/lite/svid/x509svid"

// Type aliases. These must be aliases rather than definitions so that values
// cross the module boundary and interface satisfaction is preserved.
type (
	// SVID represents a SPIFFE X509-SVID.
	SVID = lite.SVID

	// Source represents a source of X509-SVIDs.
	Source = lite.Source

	// VerifyOption is an option used when verifying X509-SVIDs.
	VerifyOption = lite.VerifyOption
)

var (
	// IDFromCert extracts the SPIFFE ID from the URI SAN of the provided certificate. It will return an an error if the certificate does not have exactly one URI SAN with a well-formed SPIFFE ID.
	IDFromCert = lite.IDFromCert

	// Load loads the X509-SVID from PEM encoded files on disk. certFile and keyFile may be the same file.
	Load = lite.Load

	// Parse parses the X509-SVID from PEM blocks containing certificate and key bytes. The certificate must be one or more PEM blocks with ASN.1 DER. The key must be a PEM block with PKCS#8 ASN.1 DER.
	Parse = lite.Parse

	// ParseAndVerify parses and verifies an X509-SVID chain using the X.509 bundle source. It returns the SPIFFE ID of the X509-SVID and one or more chains back to a root in the bundle.
	ParseAndVerify = lite.ParseAndVerify

	// ParseRaw parses the X509-SVID from certificate and key bytes. The certificate must be ASN.1 DER (concatenated with no intermediate padding if there are more than one certificate). The key must be a PKCS#8 ASN.1 DER.
	ParseRaw = lite.ParseRaw

	// Verify verifies an X509-SVID chain using the X.509 bundle source. It returns the SPIFFE ID of the X509-SVID and one or more chains back to a root in the bundle.
	Verify = lite.Verify

	// WithTime sets the time used when verifying validity periods on the X509-SVID. If not used, the current time will be used.
	WithTime = lite.WithTime
)
