package x509bundle

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const certType string = "CERTIFICATE"

// Bundle is a collection of trusted public key material for a trust domain.
type Bundle struct {
	tdMtx       *sync.RWMutex
	trustDomain spiffeid.TrustDomain

	rootsMtx *sync.RWMutex
	roots    []*x509.Certificate
}

// New creates a new bundle
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		trustDomain: trustDomain,
		tdMtx:       &sync.RWMutex{},
		roots:       []*x509.Certificate{},
		rootsMtx:    &sync.RWMutex{},
	}
}

// Load loads a Bundle from a file on disk.
func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open file: %v", err)
	}

	return Parse(trustDomain, fileBytes)
}

// Read decodes a bundle from a reader.
func Read(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("unable to read: %v", err)
	}

	return Parse(trustDomain, b.Bytes())
}

// Parse parses a bundle from bytes.
func Parse(trustDomain spiffeid.TrustDomain, b []byte) (*Bundle, error) {
	bundle := New(trustDomain)
	for {
		if len(b) == 0 {
			break
		}
		pemBlock, pemBytes := pem.Decode(b)
		b = pemBytes
		if pemBlock == nil {
			return nil, errors.New("no PEM data found while decoding block")
		}

		if pemBlock.Type != certType {
			return nil, fmt.Errorf(`block does not contain %q type, current type is: %q`, certType, pemBlock.Type)
		}

		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cannot parse certificate: %v", err)
		}
		bundle.AddX509Root(cert)
	}
	return bundle, nil
}

// TrustDomain returns the trust domain of the bundle.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	b.tdMtx.RLock()
	defer b.tdMtx.RUnlock()
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
		if reflect.DeepEqual(r, root) {
			return
		}
	}

	b.roots = append(b.roots, root)
}

// RemoveX509Root removes an X.509 root to the bundle.
func (b *Bundle) RemoveX509Root(root *x509.Certificate) {
	b.rootsMtx.Lock()
	defer b.rootsMtx.Unlock()

	for i, r := range b.roots {
		if reflect.DeepEqual(r, root) {
			// Error can be safely ignored since the index comes from
			// iterating on the root certificates slice
			b.roots, _ = removeElement(b.roots, i)
			return
		}
	}
}

// HasX509Root checks if the given X.509 root exists in the bundle
func (b *Bundle) HasX509Root(root *x509.Certificate) bool {
	b.rootsMtx.RLock()
	defer b.rootsMtx.RUnlock()

	for _, r := range b.roots {
		if reflect.DeepEqual(r, root) {
			return true
		}
	}
	return false
}

// Marshal marshals the X.509 bundle into PEM-encoded certificate blocks.
func (b *Bundle) Marshal() ([]byte, error) {
	b.rootsMtx.RLock()
	defer b.rootsMtx.RUnlock()

	var buf bytes.Buffer
	for _, root := range b.roots {
		err := pem.Encode(&buf, &pem.Block{
			Type:  certType,
			Bytes: root.Raw,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to encode root certificate: %v", err)
		}
	}

	return buf.Bytes(), nil
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the Source interface. It will fail if
// called with a trust domain other than the one the bundle belongs to.
func (b *Bundle) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	b.tdMtx.RLock()
	defer b.tdMtx.RUnlock()

	if b.trustDomain != trustDomain {
		return nil, errors.New("wrong td")
	}

	return b, nil
}

// removeElement removes an element from slice, slice order is not preserved.
func removeElement(slice []*x509.Certificate, index int) ([]*x509.Certificate, error) {
	if index < 0 || index >= len(slice) {
		return nil, fmt.Errorf("index %d is out of slice boundaries", index)
	}
	slice[index] = slice[len(slice)-1]
	return slice[:len(slice)-1], nil
}
