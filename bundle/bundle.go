// Package bundle implements a SPIFFE-compliant bundle type.
package bundle

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"

	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2"
)

// Use represent the 'use' parameter of a JWK
type Use string

// Identity documents available for the 'use' parameter
const (
	UseX509SVID Use = "x509-svid"
	UseJWTSVID  Use = "jwt-svid"
)

// InvalidKeyReason describes why a JWK is not SPIFFE-compliant.
type InvalidKeyReason string

// SPIFFE key invalidity reasons.
const (
	ReasonMissingUse         InvalidKeyReason = "key is missing 'use' parameter"
	ReasonUnrecognizedUse    InvalidKeyReason = "key has unrecognized value for 'use'"
	ReasonSingleCertExpected InvalidKeyReason = "expected a single certificate"
)

// Bundle is a SPIFFE bundle object. It follows the definitions given in the
// SPIFFE standard:
//
// https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format
type Bundle struct {
	// SPIFFE bundles are represented as an RFC 7517 compliant JWK Set.
	jose.JSONWebKeySet

	// Sequence is a monotonically increasing integer that is changed whenever
	// the contents of the bundle are updated.
	Sequence uint64 `json:"spiffe_sequence,omitempty"`

	// RefreshHint indicates how often a consumer should check back for updates
	// (in seconds).
	RefreshHint int `json:"spiffe_refresh_hint,omitempty"`
}

// InvalidKey is used to describe why the wrapped JWK is not SPIFFE-compliant.
type InvalidKey struct {
	jose.JSONWebKey
	Reason InvalidKeyReason
}

// KeysForUse provides a subset of keys filtered by the 'use' parameter
func (b *Bundle) KeysForUse(use Use) []jose.JSONWebKey {
	keys := []jose.JSONWebKey{}
	for _, key := range b.Keys {
		if key.Use == string(use) {
			keys = append(keys, key)
		}
	}
	return keys
}

// RootCAs provide RootCAs from bundle
func (b *Bundle) RootCAs() []*x509.Certificate {
	var certs []*x509.Certificate

	for _, key := range b.KeysForUse(UseX509SVID) {
		if len(key.Certificates) > 0 {
			certs = append(certs, key.Certificates...)
		}
	}

	return certs
}

// Decode reads a json document from a Reader interface and turns it into a
// bundle object. It fails if an invalid key is found.
func Decode(r io.Reader) (*Bundle, error) {
	doc := new(Bundle)
	if err := json.NewDecoder(r).Decode(doc); err != nil {
		return nil, fmt.Errorf("failed to decode bundle: %v", err)
	}

	_, invalidKeys := ValidateKeys(doc.Keys)
	if len(invalidKeys) > 0 {
		return nil, errs.New("key validation failed: found %d invalid key(s)", len(invalidKeys))
	}

	return doc, nil
}

// Decode reads a json document from a Reader interface and turns it into a
// bundle object. If invalid keys are found, they are returned in a separated slice.
func DecodeLenient(r io.Reader) (*Bundle, []*InvalidKey, error) {
	doc := new(Bundle)
	if err := json.NewDecoder(r).Decode(doc); err != nil {
		return nil, nil, fmt.Errorf("failed to decode bundle: %v", err)
	}

	validKeys, invalidKeys := ValidateKeys(doc.Keys)
	doc.Keys = validKeys

	return doc, invalidKeys, nil
}

// ValidateKeys validates if the keys contained in a JSONWebKey array are
// SPIFFE-compliant. It returns two separated slices for valid and invalid keys.
func ValidateKeys(keys []jose.JSONWebKey) ([]jose.JSONWebKey, []*InvalidKey) {
	invalid := []*InvalidKey{}
	valid := []jose.JSONWebKey{}

	for _, key := range keys {
		switch Use(key.Use) {
		case UseX509SVID:
			if len(key.Certificates) != 1 {
				invalid = append(invalid, &InvalidKey{
					JSONWebKey: key,
					Reason:     ReasonSingleCertExpected,
				})
				continue
			}
			valid = append(valid, key)

		case UseJWTSVID:
			valid = append(valid, key)

		case "":
			invalid = append(invalid, &InvalidKey{
				JSONWebKey: key,
				Reason:     ReasonMissingUse,
			})

		default:
			invalid = append(invalid, &InvalidKey{
				JSONWebKey: key,
				Reason:     ReasonUnrecognizedUse,
			})
		}
	}

	return valid, invalid
}
