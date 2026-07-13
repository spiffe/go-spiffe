package spiffebundle_test

import (
	"bytes"
	"crypto/x509"
	"os"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test/errstrings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type bundleMapTestCase struct {
	filePath string
	err      string
	len      int
}

var (
	bundleMapTestCases = []bundleMapTestCase{
		{
			filePath: "testdata/does-not-exist.json",
		},
		{
			filePath: "testdata/bundlemap_valid.json",
			len:      2,
		},
		{
			filePath: "testdata/bundlemap_empty.json",
			len:      0,
		},
		{
			filePath: "testdata/bundlemap_missing_trust_domains.json",
			err:      "spiffebundle: no trust_domains found",
		},
		{
			filePath: "testdata/bundlemap_invalid_td.json",
			err:      `spiffebundle: invalid trust domain "invalid domain": trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores`,
		},
		{
			filePath: "testdata/bundlemap_invalid_bundle.json",
			err:      `spiffebundle: error parsing bundle for trust domain "domain.test": no authorities found`,
		},
	}
)

func checkBundleMapProperties(t *testing.T, err error, tc bundleMapTestCase, bundleMap *spiffebundle.BundleMap) {
	if tc.err != "" {
		require.EqualError(t, err, tc.err)
		return
	}
	require.NoError(t, err)
	require.NotNil(t, bundleMap)
	assert.Equal(t, tc.len, bundleMap.Len())
}

func TestNewBundleMap(t *testing.T) {
	m := spiffebundle.NewBundleMap()
	require.NotNil(t, m)
	require.Equal(t, 0, m.Len())

	m = spiffebundle.NewBundleMap(spiffebundle.New(td), spiffebundle.New(td2))
	require.Equal(t, 2, m.Len())
	require.True(t, m.Has(td))
	require.True(t, m.Has(td2))
}

func TestLoadBundleMap(t *testing.T) {
	bundleMapTestCases[0].err = "spiffebundle: unable to read SPIFFE bundle map: open testdata/does-not-exist.json: " + errstrings.FileNotFound

	for _, tc := range bundleMapTestCases {
		t.Run(tc.filePath, func(t *testing.T) {
			bundleMap, err := spiffebundle.LoadBundleMap(tc.filePath)
			checkBundleMapProperties(t, err, tc, bundleMap)
		})
	}
}

func TestReadBundleMap(t *testing.T) {
	bundleMapTestCases[0].err = "spiffebundle: unable to read: invalid argument"

	for _, tc := range bundleMapTestCases {
		t.Run(tc.filePath, func(t *testing.T) {
			// we expect the Open call to fail in some cases
			file, _ := os.Open(tc.filePath)
			defer file.Close()

			bundleMap, err := spiffebundle.ReadBundleMap(file)
			checkBundleMapProperties(t, err, tc, bundleMap)
		})
	}
}

func TestParseBundleMap(t *testing.T) {
	bundleMapTestCases[0].err = "spiffebundle: unable to parse SPIFFE bundle map: unexpected end of JSON input"

	for _, tc := range bundleMapTestCases {
		t.Run(tc.filePath, func(t *testing.T) {
			// we expect the ReadFile call to fail in some cases
			bundleMapBytes, _ := os.ReadFile(tc.filePath)

			bundleMap, err := spiffebundle.ParseBundleMap(bundleMapBytes)
			checkBundleMapProperties(t, err, tc, bundleMap)
		})
	}
}

func TestBundleMapMarshal(t *testing.T) {
	bundleMap, err := spiffebundle.LoadBundleMap("testdata/bundlemap_valid.json")
	require.NoError(t, err)

	bundleMapBytes, err := bundleMap.Marshal()
	require.NoError(t, err)
	require.Contains(t, string(bundleMapBytes), "trust_domains")

	bundleMapParsed, err := spiffebundle.ParseBundleMap(bundleMapBytes)
	require.NoError(t, err)
	assert.True(t, bundleMap.Equal(bundleMapParsed))
}

func TestBundleMapMarshalEmpty(t *testing.T) {
	bundleMap := spiffebundle.NewBundleMap()

	bundleMapBytes, err := bundleMap.Marshal()
	require.NoError(t, err)
	assert.JSONEq(t, `{"trust_domains":{}}`, string(bundleMapBytes))
}

func TestBundleMapMarshalOmitsRefreshHint(t *testing.T) {
	bundleMap, err := spiffebundle.LoadBundleMap("testdata/bundlemap_with_refresh_hint.json")
	require.NoError(t, err)

	// The bundle retains the refresh hint when parsed on its own.
	bundle, ok := bundleMap.Get(td)
	require.True(t, ok)
	_, ok = bundle.RefreshHint()
	require.True(t, ok)

	bundleMapBytes, err := bundleMap.Marshal()
	require.NoError(t, err)
	require.False(t, bytes.Contains(bundleMapBytes, []byte("spiffe_refresh_hint")))

	bundleMapParsed, err := spiffebundle.ParseBundleMap(bundleMapBytes)
	require.NoError(t, err)
	bundleParsed, ok := bundleMapParsed.Get(td)
	require.True(t, ok)
	_, ok = bundleParsed.RefreshHint()
	require.False(t, ok)
}

func TestBundleMapClone(t *testing.T) {
	bundleMap, err := spiffebundle.LoadBundleMap("testdata/bundlemap_valid.json")
	require.NoError(t, err)

	cloned := bundleMap.Clone()
	require.True(t, bundleMap.Equal(cloned))

	// Mutating the clone must not affect the original.
	cloned.Remove(td)
	require.True(t, bundleMap.Has(td))
	require.False(t, cloned.Has(td))
	require.False(t, bundleMap.Equal(cloned))
}

func TestBundleMapEqual(t *testing.T) {
	empty := spiffebundle.NewBundleMap()
	m1 := spiffebundle.NewBundleMap(spiffebundle.New(td))
	m1Dup := spiffebundle.NewBundleMap(spiffebundle.New(td))
	m2 := spiffebundle.NewBundleMap(spiffebundle.New(td), spiffebundle.New(td2))
	other := spiffebundle.NewBundleMap(spiffebundle.New(td2))

	assert.True(t, m1.Equal(m1Dup))
	assert.False(t, m1.Equal(m2))
	assert.False(t, m1.Equal(other))
	assert.False(t, m1.Equal(empty))

	// nil handling
	var nilMap *spiffebundle.BundleMap
	assert.True(t, nilMap.Equal(nil))
	assert.False(t, m1.Equal(nil))
	assert.False(t, nilMap.Equal(m1))
}

func TestBundleMapEmbeddedSet(t *testing.T) {
	// Smoke test that the embedded Set methods are reachable on *BundleMap.
	xb := x509bundle.FromX509Authorities(td, []*x509.Certificate{x509Cert1})
	b := spiffebundle.FromX509Bundle(xb)

	m := spiffebundle.NewBundleMap()
	require.False(t, m.Has(td))

	m.Add(b)
	require.True(t, m.Has(td))
	require.Equal(t, 1, m.Len())

	got, ok := m.Get(td)
	require.True(t, ok)
	require.Equal(t, b, got)

	require.Len(t, m.Bundles(), 1)

	xb2, err := m.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, xb, xb2)

	_, err = m.GetX509BundleForTrustDomain(td2)
	require.EqualError(t, err, `spiffebundle: no X.509 bundle for trust domain "domain2.test"`)

	m.Remove(td)
	require.False(t, m.Has(td))
}
