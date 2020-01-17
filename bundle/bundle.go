// Package bundle implements a SPIFFE-compliant bundle type.
package bundle

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2"
)

const (
	x509SVIDUse = "x509-svid"
	jwtSVIDUse  = "jwt-svid"
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

// SPIFFEInvalidJWK is used to describe why a key is not SPIFFE-compliant.
type SPIFFEInvalidJWK struct {
	jose.JSONWebKey
	reason error
}

// Decode reads a json document from a Reader interface and turns it into a
// bundle object.
func Decode(r io.Reader) (*Bundle, error) {
	doc := new(Bundle)
	if err := json.NewDecoder(r).Decode(doc); err != nil {
		return nil, fmt.Errorf("failed to decode bundle: %v", err)
	}

	return doc, nil
}

// ValidateKeys validates if the keys contained in a JSONWebKey array are
// SPIFFE-compliant. It returns two separated slices for valid and invalid keys.
func ValidateKeys(keys []jose.JSONWebKey) ([]jose.JSONWebKey, []*SPIFFEInvalidJWK) {
	invalid := []*SPIFFEInvalidJWK{}
	valid := []jose.JSONWebKey{}

	for i, key := range keys {
		switch key.Use {
		case x509SVIDUse:
			if len(key.Certificates) != 1 {
				invalid = append(invalid, &SPIFFEInvalidJWK{
					JSONWebKey: key,
					reason:     errs.New("expected a single certificate in x509-svid entry %d; got %d", i, len(key.Certificates)),
				})
				continue
			}
			valid = append(valid, key)

		case jwtSVIDUse:
			valid = append(valid, key)

		case "":
			invalid = append(invalid, &SPIFFEInvalidJWK{
				JSONWebKey: key,
				reason:     errs.New("missing use for key entry %d", i),
			})

		default:
			invalid = append(invalid, &SPIFFEInvalidJWK{
				JSONWebKey: key,
				reason:     errs.New("unrecognized use %q for key entry %d", key.Use, i),
			})
		}
	}

	return valid, invalid
}
