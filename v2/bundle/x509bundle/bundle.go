package x509bundle

import (
	"crypto/x509"
	"io"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Bundle is a collection of trusted public key material for a trust domain.
type Bundle struct {
}

// New creates a new bundle
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	panic("not implemented")
}

// Load loads a Bundle from a file on disk.
func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
	panic("not implemented")
}

// Read decodes a bundle from a reader.
func Read(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	panic("not implemented")
}

// Parse parses a bundle from bytes.
func Parse(trustDomain spiffeid.TrustDomain, b []byte) (*Bundle, error) {
	panic("not implemented")
}

// TrustDomain returns the trust domain of the bundle.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	panic("not implemented")
}

// X509Roots returns the X.509 roots in the bundle.
func (b *Bundle) X509Roots() []*x509.Certificate {
	panic("not implemented")
}

// AddX509Root adds an X.509 root to the bundle. If the root already
// exists in the bundle, the contents of the bundle will remain unchanged.
func (b *Bundle) AddX509Root(*x509.Certificate) {
	panic("not implemented")
}

// RemoveX509Root removes an X.509 root to the bundle.
func (b *Bundle) RemoveX509Root(*x509.Certificate) {
	panic("not implemented")
}

// Marshal marshals the X.509 bundle into PEM-encoded certificate blocks.
func (b *Bundle) Marshal() ([]byte, error) {
	panic("not implemented")
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the Source interface. It will fail if
// called with a trust domain other than the one the bundle belongs to.
func (b *Bundle) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	panic("not implemented")
}
