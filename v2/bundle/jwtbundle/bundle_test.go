package jwtbundle_test

import (
	"crypto"
	"os"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/errstrings"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testFile struct {
	filePath  string
	keysCount int
}

var (
	td        = spiffeid.RequireTrustDomainFromString("example.org")
	testFiles = map[string]testFile{
		"valid 1": {
			filePath:  "testdata/jwks_valid_1.json",
			keysCount: 1,
		},
		"valid 2": {
			filePath:  "testdata/jwks_valid_2.json",
			keysCount: 2,
		},
		"non existent file": {
			filePath: "testdata/does-not-exist.json",
		},
		"missing kid": {
			filePath: "testdata/jwks_missing_kid.json",
		},
	}
)

func TestNew(t *testing.T) {
	b := jwtbundle.New(td)
	require.NotNil(t, b)
	require.Len(t, b.JWTAuthorities(), 0)
	require.Equal(t, td, b.TrustDomain())
}

func TestFromJWTAuthorities(t *testing.T) {
	jwtAuthorities := map[string]crypto.PublicKey{
		"key-1": "test-1",
		"key-2": "test-2",
	}
	b := jwtbundle.FromJWTAuthorities(td, jwtAuthorities)
	require.NotNil(t, b)
	assert.Equal(t, b.JWTAuthorities(), jwtAuthorities)
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
			err: "jwtbundle: unable to read JWT bundle: open testdata/does-not-exist.json: " + errstrings.FileNotFound,
		},
		{
			tf:  testFiles["missing kid"],
			err: "jwtbundle: error adding authority 1 of JWKS: keyID cannot be empty",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.tf.filePath, func(t *testing.T) {
			bundle, err := jwtbundle.Load(td, testCase.tf.filePath)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, bundle)
			assert.Len(t, bundle.JWTAuthorities(), testCase.tf.keysCount)
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
			err: "jwtbundle: unable to read: invalid argument",
		},
		{
			tf:  testFiles["missing kid"],
			err: "jwtbundle: error adding authority 1 of JWKS: keyID cannot be empty",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.tf.filePath, func(t *testing.T) {
			// we expect the Open call to fail in some cases
			file, _ := os.Open(testCase.tf.filePath)
			defer file.Close()

			bundle, err := jwtbundle.Read(td, file)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, bundle)
			assert.Len(t, bundle.JWTAuthorities(), testCase.tf.keysCount)
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
			err: "jwtbundle: unable to parse JWKS: unexpected end of JSON input",
		},
		{
			tf:  testFiles["missing kid"],
			err: "jwtbundle: error adding authority 1 of JWKS: keyID cannot be empty",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.tf.filePath, func(t *testing.T) {
			// we expect the ReadFile call to fail in some cases
			bundleBytes, _ := os.ReadFile(testCase.tf.filePath)

			bundle, err := jwtbundle.Parse(td, bundleBytes)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, bundle)
			assert.Len(t, bundle.JWTAuthorities(), testCase.tf.keysCount)
		})
	}
}

func TestTrustDomain(t *testing.T) {
	b := jwtbundle.New(td)
	btd := b.TrustDomain()
	require.Equal(t, td, btd)
}

func TestJWTAuthoritiesCRUD(t *testing.T) {
	// Test AddJWTAuthority (missing authority)
	b := jwtbundle.New(td)
	err := b.AddJWTAuthority("", "test-1")
	require.EqualError(t, err, "jwtbundle: keyID cannot be empty")

	// Test AddJWTAuthority (new authority)
	err = b.AddJWTAuthority("key-1", "test-1")
	require.NoError(t, err)

	// Test JWTAuthorities
	jwtAuthorities := b.JWTAuthorities()
	require.Equal(t, map[string]crypto.PublicKey{"key-1": "test-1"}, jwtAuthorities)

	err = b.AddJWTAuthority("key-2", "test-2")
	require.NoError(t, err)

	jwtAuthorities = b.JWTAuthorities()
	require.Equal(t, map[string]crypto.PublicKey{
		"key-1": "test-1",
		"key-2": "test-2",
	}, jwtAuthorities)

	// Test FindJWTAuthority
	authority, ok := b.FindJWTAuthority("key-1")
	require.True(t, ok)
	require.Equal(t, "test-1", authority)

	authority, ok = b.FindJWTAuthority("key-3")
	require.False(t, ok)
	require.Nil(t, authority)

	require.Equal(t, true, b.HasJWTAuthority("key-1"))
	b.RemoveJWTAuthority("key-3")

	require.Equal(t, 2, len(b.JWTAuthorities()))
	require.Equal(t, true, b.HasJWTAuthority("key-1"))
	require.Equal(t, true, b.HasJWTAuthority("key-2"))

	// Test RemoveJWTAuthority
	b.RemoveJWTAuthority("key-2")
	require.Equal(t, 1, len(b.JWTAuthorities()))
	require.Equal(t, true, b.HasJWTAuthority("key-1"))

	// Test AddJWTAuthority (update authority)
	err = b.AddJWTAuthority("key-1", "test-1-updated")
	require.NoError(t, err)
	jwtAuthorities = b.JWTAuthorities()
	require.Equal(t, map[string]crypto.PublicKey{
		"key-1": "test-1-updated",
	}, jwtAuthorities)
}

func TestMarshal(t *testing.T) {
	// Load a bundle to marshal
	bundle, err := jwtbundle.Load(td, "testdata/jwks_valid_2.json")
	require.NoError(t, err)

	// Marshal the bundle
	bundleBytesMarshal, err := bundle.Marshal()
	require.NoError(t, err)
	require.NotNil(t, bundleBytesMarshal)

	// Parse the marshaled bundle
	bundleParsed, err := jwtbundle.Parse(td, bundleBytesMarshal)
	require.NoError(t, err)

	// Assert that the marshaled bundle is equal to the parsed bundle
	assert.Equal(t, bundleParsed, bundle)
}

func TestGetJWTBundleForTrustDomain(t *testing.T) {
	b := jwtbundle.New(td)
	b1, err := b.GetJWTBundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, b, b1)

	td2 := spiffeid.RequireTrustDomainFromString("example-2.org")
	b2, err := b.GetJWTBundleForTrustDomain(td2)
	require.Nil(t, b2)
	require.EqualError(t, err, `jwtbundle: no JWT bundle for trust domain "example-2.org"`)
}

func TestEqual(t *testing.T) {
	ca1 := test.NewCA(t, td)
	ca2 := test.NewCA(t, td2)

	empty := jwtbundle.New(td)
	empty2 := jwtbundle.New(td2)

	jwtAuthorities1 := jwtbundle.FromJWTAuthorities(td, ca1.JWTAuthorities())
	jwtAuthorities2 := jwtbundle.FromJWTAuthorities(td, ca2.JWTAuthorities())

	for _, tt := range []struct {
		name        string
		a           *jwtbundle.Bundle
		b           *jwtbundle.Bundle
		expectEqual bool
	}{
		{
			name:        "empty equal",
			a:           empty,
			b:           empty,
			expectEqual: true,
		},
		{
			name:        "different trust domains",
			a:           empty,
			b:           empty2,
			expectEqual: false,
		},
		{
			name:        "JWT authorities equal",
			a:           jwtAuthorities1,
			b:           jwtAuthorities1,
			expectEqual: true,
		},
		{
			name:        "JWT authorities empty and not empty",
			a:           empty,
			b:           jwtAuthorities1,
			expectEqual: false,
		},
		{
			name:        "JWT authorities not empty but not equal",
			a:           jwtAuthorities1,
			b:           jwtAuthorities2,
			expectEqual: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expectEqual, tt.a.Equal(tt.b))
		})
	}
}

func TestClone(t *testing.T) {
	// Load a bundle to clone
	original, err := jwtbundle.Load(td, "testdata/jwks_valid_2.json")
	require.NoError(t, err)

	cloned := original.Clone()
	require.True(t, original.Equal(cloned))
}
