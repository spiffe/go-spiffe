package x509bundle

import (
	"bytes"
	"crypto/x509"
	"io"
	"io/ioutil"
	"sync"

	"github.com/spiffe/go-spiffe/v2/internal/pemutil"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/zeebo/errs"
)

var x509bundleErr = errs.Class("x509bundle")

// Bundle is a collection of trusted X.509 roots for a trust domain.
type Bundle struct {
	trustDomain spiffeid.TrustDomain

	rootsMtx sync.RWMutex
	roots    []*x509.Certificate
}

// New creates a new bundle.
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		trustDomain: trustDomain,
	}
}

// Load loads a bundle from a file on disk.
func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, x509bundleErr.New("unable to load X.509 bundle file: %w", err)
	}

	return Parse(trustDomain, fileBytes)
}

// Read decodes a bundle from a reader.
func Read(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, x509bundleErr.New("unable to read X.509 bundle: %v", err)
	}

	return Parse(trustDomain, b)
}

// Parse parses a bundle from bytes.
func Parse(trustDomain spiffeid.TrustDomain, b []byte) (*Bundle, error) {
	bundle := New(trustDomain)
	for {
		if len(b) == 0 {
			break
		}
		cert, rest, err := pemutil.ParseCertificate(b)
		b = rest
		if err != nil {
			return nil, x509bundleErr.New("cannot parse certificate: %v", err)
		}
		bundle.AddX509Root(cert)
	}
	return bundle, nil
}

// TrustDomain returns the trust domain that the bundle belongs to.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	return b.trustDomain
}

// X509Roots returns the X.509 roots in the bundle.
func (b *Bundle) X509Roots() []*x509.Certificate {
	b.rootsMtx.RLock()
	defer b.rootsMtx.RUnlock()
	return b.roots
}

// AddX509Root adds an X.509 root to the bundle. If the root already
// exists in the bundle, the contents of the bundle will remain unchanged.
func (b *Bundle) AddX509Root(root *x509.Certificate) {
	b.rootsMtx.Lock()
	defer b.rootsMtx.Unlock()

	for _, r := range b.roots {
		if areCertsEqual(r, root) {
			return
		}
	}

	b.roots = append(b.roots, root)
}

// RemoveX509Root removes an X.509 root from the bundle.
func (b *Bundle) RemoveX509Root(root *x509.Certificate) {
	b.rootsMtx.Lock()
	defer b.rootsMtx.Unlock()

	for i, r := range b.roots {
		if areCertsEqual(r, root) {
			//remove element from slice
			b.roots = append(b.roots[:i], b.roots[i+1:]...)
			return
		}
	}
}

// HasX509Root checks if the given X.509 root exists in the bundle.
func (b *Bundle) HasX509Root(root *x509.Certificate) bool {
	b.rootsMtx.RLock()
	defer b.rootsMtx.RUnlock()

	for _, r := range b.roots {
		if areCertsEqual(r, root) {
			return true
		}
	}
	return false
}

// Marshal marshals the X.509 bundle into PEM-encoded certificate blocks.
func (b *Bundle) Marshal() ([]byte, error) {
	b.rootsMtx.RLock()
	defer b.rootsMtx.RUnlock()
	return pemutil.EncodeCertificates(b.roots), nil
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the Source interface. An error will be
// returned if the trust domain does not match that of the bundle.
func (b *Bundle) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	if b.trustDomain != trustDomain {
		return nil, x509bundleErr.New("no X.509 bundle found for trust domain: %q", trustDomain)
	}

	return b, nil
}

// areCertsEqual checks if two X.509 certificates are equal by comparing its raw bytes
func areCertsEqual(a, b *x509.Certificate) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	return bytes.Equal(a.Raw, b.Raw)
}
