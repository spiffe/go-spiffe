package jwtbundle

import (
	"crypto"
	"encoding/json"
	"io"
	"io/ioutil"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2"
)

var (
	jwtbundleErr = errs.Class("jwtbundle")
)

// Bundle is a collection of trusted JWT public keys for a trust domain.
type Bundle struct {
	trustDomain spiffeid.TrustDomain

	mtx     sync.RWMutex
	jwtKeys map[string]crypto.PublicKey
}

// New creates a new bundle.
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		trustDomain: trustDomain,
		jwtKeys:     make(map[string]crypto.PublicKey),
	}
}

// FromJWTKeys creates a new bundle from JWT public keys.
func FromJWTKeys(trustDomain spiffeid.TrustDomain, jwtKeys map[string]crypto.PublicKey) *Bundle {
	return &Bundle{
		trustDomain: trustDomain,
		jwtKeys:     jwtKeys,
	}
}

// Load loads a bundle from a file on disk.
func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
	bundleBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, jwtbundleErr.New("unable to read JWT bundle: %w", err)
	}

	return Parse(trustDomain, bundleBytes)
}

// Read decodes a bundle from a reader.
func Read(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, jwtbundleErr.New("unable to read: %v", err)
	}

	return Parse(trustDomain, b)
}

// Parse parses a bundle from bytes.
func Parse(trustDomain spiffeid.TrustDomain, bundleBytes []byte) (*Bundle, error) {
	jwks := new(jose.JSONWebKeySet)
	if err := json.Unmarshal(bundleBytes, jwks); err != nil {
		return nil, jwtbundleErr.New("unable to parse JWKS: %v", err)
	}

	bundle := New(trustDomain)
	for i, key := range jwks.Keys {
		if err := bundle.AddJWTKey(key.KeyID, key.Key); err != nil {
			return nil, jwtbundleErr.New("error adding key %d of JWKS: %v", i, errs.Unwrap(err))
		}
	}

	return bundle, nil
}

// TrustDomain returns the trust domain that the bundle belongs to.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	return b.trustDomain
}

// JWTKeys returns the JWT keys in the bundle, keyed by key ID.
func (b *Bundle) JWTKeys() map[string]crypto.PublicKey {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return b.jwtKeys
}

// FindJWTKey finds the JWT key with the given key id from the bundle. If the key
// is found, it is returned and the boolean is true. Otherwise, the returned
// value is nil and the boolean is false.
func (b *Bundle) FindJWTKey(keyID string) (crypto.PublicKey, bool) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if jwtKey, ok := b.jwtKeys[keyID]; ok {
		return jwtKey, true
	}
	return nil, false
}

// HasJWTKey returns true if the bundle has a JWT key with the given key id.
func (b *Bundle) HasJWTKey(keyID string) bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	_, ok := b.jwtKeys[keyID]
	return ok
}

// AddJWTKey adds a JWT key to the bundle. If a JWT key already exists
// under the given key ID, it is replaced. A key ID must be specified.
func (b *Bundle) AddJWTKey(keyID string, key crypto.PublicKey) error {
	if keyID == "" {
		return jwtbundleErr.New("keyID cannot be empty")
	}

	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.jwtKeys[keyID] = key
	return nil
}

// RemoveJWTKey removes the JWT key identified by the key ID from the bundle.
func (b *Bundle) RemoveJWTKey(keyID string) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	delete(b.jwtKeys, keyID)
}

// Marshal marshals the JWT bundle into a standard RFC 7517 JWKS document. The
// JWKS does not contain any SPIFFE-specific parameters.
func (b *Bundle) Marshal() ([]byte, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	jwks := jose.JSONWebKeySet{}
	for keyID, jwtKey := range b.jwtKeys {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   jwtKey,
			KeyID: keyID,
		})
	}

	return json.Marshal(jwks)
}

// GetJWTBundleForTrustDomain returns the JWT bundle for the given trust
// domain. It implements the Source interface. An error will be returned if
// the trust domain does not match that of the bundle.
func (b *Bundle) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if b.trustDomain != trustDomain {
		return nil, jwtbundleErr.New("no JWT bundle for trust domain %q", trustDomain)
	}

	return b, nil
}
