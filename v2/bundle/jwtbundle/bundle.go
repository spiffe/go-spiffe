package jwtbundle

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"gopkg.in/square/go-jose.v2"
)

// Bundle is a collection of trusted JWT public keys for a trust domain.
type Bundle struct {
	mtx            sync.RWMutex
	trustDomain    spiffeid.TrustDomain
	jwtSigningKeys map[string]crypto.PublicKey
}

// New creates a new bundle.
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		mtx:            sync.RWMutex{},
		trustDomain:    trustDomain,
		jwtSigningKeys: make(map[string]crypto.PublicKey),
	}
}

// Load loads a Bundle from a file on disk.
func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
	bundleBytes, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, fmt.Errorf("unble to read JWT bundle: %w", err)
	}

	return Parse(trustDomain, bundleBytes)
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
func Parse(trustDomain spiffeid.TrustDomain, bundleBytes []byte) (*Bundle, error) {
	jwks := new(jose.JSONWebKeySet)
	if err := json.Unmarshal(bundleBytes, jwks); err != nil {
		return nil, fmt.Errorf("unable to parse JWK Set: %v", err)
	}

	bundle := New(trustDomain)
	for i, key := range jwks.Keys {
		if err := bundle.AddJWTKey(key.KeyID, key.Key); err != nil {
			return nil, fmt.Errorf("error adding entry %d of JWK Set: %v", i, err)
		}
	}

	return bundle, nil
}

// TrustDomain returns the trust domain the bundle belongs to.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return b.trustDomain
}

// JWTKeys returns the JWT keys in the bundle, keyed by key ID.
func (b *Bundle) JWTKeys() map[string]crypto.PublicKey {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return b.jwtSigningKeys
}

// FindJWTKey finds the JWT key with the given key id from the bundle. If the key
// is found, it is returned and the boolean is true. Otherwise, the returned
// value is nil and the boolean is false.
func (b *Bundle) FindJWTKey(keyID string) (crypto.PublicKey, bool) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if jwtKey, ok := b.jwtSigningKeys[keyID]; ok {
		return jwtKey, true
	}
	return nil, false
}

// HasJWTKey returns true if the bundle has a JWT key with the given key id.
func (b *Bundle) HasJWTKey(keyID string) bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	_, ok := b.jwtSigningKeys[keyID]
	return ok
}

// AddJWTKey adds a JWT key to the bundle. If a JWT key already exists
// under the given key ID, it is replaced. A key ID must be specified.
func (b *Bundle) AddJWTKey(keyID string, key crypto.PublicKey) error {
	if keyID == "" {
		return errors.New("missing key ID")
	}

	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.jwtSigningKeys[keyID] = key
	return nil
}

// RemoveJWTKey removes the JWT key identified by the key ID from the bundle.
func (b *Bundle) RemoveJWTKey(keyID string) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	delete(b.jwtSigningKeys, keyID)
}

// Marshal marshals the JWT bundle into a standard RFC 7517 JWKS document. The
// JWKS does not contain any SPIFFE-specific parameters.
func (b *Bundle) Marshal() ([]byte, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	jwks := jose.JSONWebKeySet{}
	for keyID, jwtSigningKey := range b.jwtSigningKeys {
		if keyID == "" {
			return nil, errors.New("missing key ID")
		}
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   jwtSigningKey,
			KeyID: keyID,
		})
	}

	return json.MarshalIndent(jwks, "", "    ")
}

// GetJWTBundleForTrustDomain returns the JWT bundle of the given trust domain.
// It implements the Source interface. It will fail if called with a trust
// domain other than the one the bundle belongs to.
func (b *Bundle) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if b.trustDomain != trustDomain {
		return nil, fmt.Errorf("this bundle does not belong to trust domain %q", trustDomain)
	}

	return b, nil
}
