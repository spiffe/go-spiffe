package spiffebundle

import (
	"crypto/x509"
	"io"

	"gopkg.in/square/go-jose.v2"
)

// Bundle is a SPIFFE bundle
type Bundle struct {
	jose.JSONWebKeySet

	Sequence    uint64 `json:"spiffe_sequence,omitempty"`
	RefreshHint int    `json:"spiffe_refresh_hint,omitempty"`
}

// Load loads a Bundle from a file on disk
func Load(path string) (*Bundle, error) {
	panic("not implemented")
}

// Read decodes a bundle from a reader
func Read(r io.Reader) (*Bundle, error) {
	panic("not implemented")
}

// Parse parses a bundle from bytes
func Parse(b []byte) (*Bundle, error) {
	panic("not implemented")
}

// FromX509Roots creates a bundle from a set of X.509 root certificates
func FromX509Roots(roots []*x509.Certificate) (*Bundle, error) {
	panic("not implemented")
}

// FromJWKS creates a bundle from a JWKS. Each key in the JWKS will be intended
// for use in validating JWT-SVIDs and must not have the "use" field set
// beforehand.
func FromJWKS(jose.JSONWebKeySet) (*Bundle, error) {
	panic("not implemented")
}
