package jwtbundle

import (
	"crypto"
	"io/ioutil"
	"os"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testFile struct {
	filePath  string
	keysCount int
}

var (
	td, _     = spiffeid.TrustDomainFromString("example.org")
	testFiles = map[string]testFile{
		"valid 1": testFile{
			filePath:  "testdata/jwks_valid_1.json",
			keysCount: 1,
		},
		"valid 2": testFile{
			filePath:  "testdata/jwks_valid_2.json",
			keysCount: 2,
		},
		"non existent file": testFile{
			filePath: "testdata/does-not-exist.json",
		},
		"missing kid": testFile{
			filePath: "testdata/jwks_missing_kid.json",
		},
	}
)

func TestNew(t *testing.T) {
	b := New(td)
	require.NotNil(t, b)
	require.Len(t, b.JWTKeys(), 0)
	require.Equal(t, td, b.TrustDomain())
}

func TestLoad(t *testing.T) {
	testCases := []struct {
		tf  testFile
		err string
	}{
		{
			tf: testFiles["valid 1"],
		},
		{
			tf: testFiles["valid 2"],
		},
		{
			tf:  testFiles["non existent file"],
			err: "unble to read JWT bundle: open testdata/does-not-exist.json: no such file or directory",
		},
		{
			tf:  testFiles["missing kid"],
			err: "error adding entry 1 of JWK Set: missing key ID",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.tf.filePath, func(t *testing.T) {
			bundle, err := Load(td, testCase.tf.filePath)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, bundle)
			assert.Len(t, bundle.JWTKeys(), testCase.tf.keysCount)
		})
	}
}

func TestRead(t *testing.T) {
	testCases := []struct {
		tf  testFile
		err string
	}{
		{
			tf: testFiles["valid 1"],
		},
		{
			tf: testFiles["valid 2"],
		},
		{
			tf:  testFiles["non existent file"],
			err: "unable to read: invalid argument",
		},
		{
			tf:  testFiles["missing kid"],
			err: "error adding entry 1 of JWK Set: missing key ID",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.tf.filePath, func(t *testing.T) {
			// we expect the Open call to fail in some cases
			file, _ := os.Open(testCase.tf.filePath)
			t.Cleanup(func() {
				file.Close()
			})

			bundle, err := Read(td, file)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, bundle)
			assert.Len(t, bundle.JWTKeys(), testCase.tf.keysCount)
		})
	}
}

func TestParse(t *testing.T) {
	testCases := []struct {
		tf  testFile
		err string
	}{
		{
			tf: testFiles["valid 1"],
		},
		{
			tf: testFiles["valid 2"],
		},
		{
			tf:  testFiles["non existent file"],
			err: "unable to parse JWK Set: unexpected end of JSON input",
		},
		{
			tf:  testFiles["missing kid"],
			err: "error adding entry 1 of JWK Set: missing key ID",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.tf.filePath, func(t *testing.T) {
			// we expect the ReadFile call to fail in some cases
			bundleBytes, _ := ioutil.ReadFile(testCase.tf.filePath)

			bundle, err := Parse(td, bundleBytes)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, bundle)
			assert.Len(t, bundle.JWTKeys(), testCase.tf.keysCount)
		})
	}
}

func TestTrustDomain(t *testing.T) {
	b := New(td)
	btd := b.TrustDomain()
	require.Equal(t, td, btd)
}

func TestJWTKeys_crud(t *testing.T) {
	// Test AddJWTKey (missing key)
	b := New(td)
	err := b.AddJWTKey("", "test-1")
	require.EqualError(t, err, "missing key ID")

	// Test AddJWTKey (new key)
	err = b.AddJWTKey("key-1", "test-1")
	require.NoError(t, err)

	// Test JWTKeys
	keys := b.JWTKeys()
	require.Equal(t, map[string]crypto.PublicKey{"key-1": "test-1"}, keys)

	err = b.AddJWTKey("key-2", "test-2")
	require.NoError(t, err)

	keys = b.JWTKeys()
	require.Equal(t, map[string]crypto.PublicKey{
		"key-1": "test-1",
		"key-2": "test-2",
	}, keys)

	// Test FindJWTKey
	key, ok := b.FindJWTKey("key-1")
	require.True(t, ok)
	require.Equal(t, "test-1", key)

	key, ok = b.FindJWTKey("key-3")
	require.False(t, ok)

	require.Equal(t, true, b.HasJWTKey("key-1"))
	b.RemoveJWTKey("key-3")

	require.Equal(t, 2, len(b.JWTKeys()))
	require.Equal(t, true, b.HasJWTKey("key-1"))
	require.Equal(t, true, b.HasJWTKey("key-2"))

	// Test RemoveJWTKey
	b.RemoveJWTKey("key-2")
	require.Equal(t, 1, len(b.JWTKeys()))
	require.Equal(t, true, b.HasJWTKey("key-1"))

	// Test AddJWTKey (update key)
	err = b.AddJWTKey("key-1", "test-1-updated")
	require.NoError(t, err)
	keys = b.JWTKeys()
	require.Equal(t, map[string]crypto.PublicKey{
		"key-1": "test-1-updated",
	}, keys)
}

func TestMarshal(t *testing.T) {
	// Load a bundle to marshal
	bundle, err := Load(td, "testdata/jwks_valid_1.json")
	require.NoError(t, err)

	// Marshal the bundle
	bundleBytesMarshal, err := bundle.Marshal()
	require.NoError(t, err)
	require.NotNil(t, bundleBytesMarshal)

	// Load original bytes for comparison
	bundleBytesFile, err := ioutil.ReadFile("testdata/jwks_valid_1.json")
	require.NoError(t, err)

	// Assert the marshalled bundle is equal to the one loaded
	assert.Equal(t, bundleBytesFile, bundleBytesMarshal)

	// Try to marshal an invalid bundle
	b := &Bundle{
		trustDomain:    td,
		jwtSigningKeys: map[string]crypto.PublicKey{"": nil},
	}
	bundleBytesMarshal, err = b.Marshal()
	require.EqualError(t, err, "missing key ID")
}

func TestGetJWTBundleForTrustDomain(t *testing.T) {
	b := New(td)
	b1, err := b.GetJWTBundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, b, b1)

	td2, _ := spiffeid.TrustDomainFromString("example-2.org")
	b2, err := b.GetJWTBundleForTrustDomain(td2)
	require.Nil(t, b2)
	require.EqualError(t, err, `this bundle does not belong to trust domain "example-2.org"`)
}
