package spiffebundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// bundleMapDoc is the JSON representation of a SPIFFE Bundle Map. Bundles are
// keyed by trust domain name under the top-level "trust_domains" key.
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#5-spiffe-bundle-map
type bundleMapDoc struct {
	TrustDomains map[string]json.RawMessage `json:"trust_domains"`
}

// BundleMap is a collection of SPIFFE bundles keyed by trust domain, conforming
// to the SPIFFE Bundle Map format as part of the SPIFFE Trust Domain and Bundle
// specification:
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#5-spiffe-bundle-map
//
// It embeds Set and therefore provides the same collection and Source
// interface methods, adding serialization to and from the SPIFFE Bundle Map
// format.
type BundleMap struct {
	*Set
}

// NewBundleMap creates a new bundle map initialized with the given bundles.
func NewBundleMap(bundles ...*Bundle) *BundleMap {
	return &BundleMap{Set: NewSet(bundles...)}
}

// LoadBundleMap loads a bundle map from a file on disk. The file must contain a
// document following the SPIFFE Bundle Map format.
func LoadBundleMap(path string) (*BundleMap, error) {
	bundleMapBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, wrapSpiffebundleErr(fmt.Errorf("unable to read SPIFFE bundle map: %w", err))
	}

	return ParseBundleMap(bundleMapBytes)
}

// ReadBundleMap decodes a bundle map from a reader. The contents must contain a
// document following the SPIFFE Bundle Map format.
func ReadBundleMap(r io.Reader) (*BundleMap, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, wrapSpiffebundleErr(fmt.Errorf("unable to read: %v", err))
	}

	return ParseBundleMap(b)
}

// ParseBundleMap parses a bundle map from bytes. The data must be a document
// following the SPIFFE Bundle Map format.
func ParseBundleMap(bundleMapBytes []byte) (*BundleMap, error) {
	doc := &bundleMapDoc{}
	if err := json.Unmarshal(bundleMapBytes, doc); err != nil {
		return nil, wrapSpiffebundleErr(fmt.Errorf("unable to parse SPIFFE bundle map: %v", err))
	}

	if doc.TrustDomains == nil {
		// The trust_domains key MUST be present. It MAY be empty.
		// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#5-spiffe-bundle-map
		return nil, wrapSpiffebundleErr(errors.New("no trust_domains found"))
	}

	bundleMap := NewBundleMap()
	seen := map[string]struct{}{}
	for name, raw := range doc.TrustDomains {
		trustDomain, err := spiffeid.TrustDomainFromString(name)
		if err != nil {
			return nil, wrapSpiffebundleErr(fmt.Errorf("invalid trust domain %q: %w", name, err))
		}

		if _, ok := seen[trustDomain.Name()]; ok {
			return nil, wrapSpiffebundleErr(fmt.Errorf("duplicate entry found for trust domain %q", name))
		}
		seen[trustDomain.Name()] = struct{}{}

		bundle, err := Parse(trustDomain, raw)
		if err != nil {
			return nil, wrapSpiffebundleErr(fmt.Errorf("error parsing bundle for trust domain %q: %w", name, errors.Unwrap(err)))
		}

		bundleMap.Add(bundle)
	}

	return bundleMap, nil
}

// Marshal marshals the bundle map according to the SPIFFE Bundle Map format.
// The refresh hint is omitted from the bundles in the map, as recommended by
// the specification.
func (m *BundleMap) Marshal() ([]byte, error) {
	doc := bundleMapDoc{
		TrustDomains: make(map[string]json.RawMessage),
	}

	for _, bundle := range m.Bundles() {
		// The refresh_hint SHOULD be omitted from bundles included in a map.
		clone := bundle.Clone()
		clone.ClearRefreshHint()

		raw, err := clone.Marshal()
		if err != nil {
			return nil, wrapSpiffebundleErr(fmt.Errorf("error marshaling bundle for trust domain %q: %w", bundle.TrustDomain(), errors.Unwrap(err)))
		}

		doc.TrustDomains[bundle.TrustDomain().String()] = raw
	}

	return json.Marshal(doc)
}

// Clone clones the bundle map.
func (m *BundleMap) Clone() *BundleMap {
	bundles := m.Bundles()
	cloned := make([]*Bundle, 0, len(bundles))
	for _, bundle := range bundles {
		cloned = append(cloned, bundle.Clone())
	}

	return NewBundleMap(cloned...)
}

// Equal compares the bundle map for equality against the given bundle map.
func (m *BundleMap) Equal(other *BundleMap) bool {
	if m == nil || other == nil {
		return m == other
	}

	if m.Len() != other.Len() {
		return false
	}

	for _, bundle := range m.Bundles() {
		otherBundle, ok := other.Get(bundle.TrustDomain())
		if !ok || !bundle.Equal(otherBundle) {
			return false
		}
	}

	return true
}
