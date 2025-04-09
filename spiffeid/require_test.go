package spiffeid_test

import (
	"net/url"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
)

func TestRequireFromPath(t *testing.T) {
	assert.NotPanics(t, func() {
		id := spiffeid.RequireFromPath(td, "/path")
		assert.Equal(t, "spiffe://trustdomain/path", id.String())
	})
	assert.Panics(t, func() {
		spiffeid.RequireFromPath(td, "relative")
	})
}

func TestRequireFromPathf(t *testing.T) {
	assert.NotPanics(t, func() {
		id := spiffeid.RequireFromPathf(td, "/%s", "path")
		assert.Equal(t, "spiffe://trustdomain/path", id.String())
	})
	assert.Panics(t, func() {
		spiffeid.RequireFromPathf(td, "%s", "relative")
	})
}

func TestRequireFromSegments(t *testing.T) {
	assert.NotPanics(t, func() {
		id := spiffeid.RequireFromSegments(td, "path")
		assert.Equal(t, "spiffe://trustdomain/path", id.String())
	})
	assert.Panics(t, func() {
		spiffeid.RequireFromSegments(td, "/absolute")
	})
}

func TestRequireFromString(t *testing.T) {
	assert.NotPanics(t, func() {
		id := spiffeid.RequireFromString("spiffe://trustdomain/path")
		assert.Equal(t, "spiffe://trustdomain/path", id.String())
	})
	assert.Panics(t, func() {
		spiffeid.RequireFromString("")
	})
}

func TestRequireFromStringf(t *testing.T) {
	assert.NotPanics(t, func() {
		id := spiffeid.RequireFromStringf("spiffe://trustdomain/%s", "path")
		assert.Equal(t, "spiffe://trustdomain/path", id.String())
	})
	assert.Panics(t, func() {
		spiffeid.RequireFromStringf("%s://trustdomain/path", "sparfe")
	})
}

func TestRequireFromURI(t *testing.T) {
	assert.NotPanics(t, func() {
		id := spiffeid.RequireFromURI(&url.URL{Scheme: "spiffe", Host: "trustdomain", Path: "/path"})
		assert.Equal(t, "spiffe://trustdomain/path", id.String())
	})
	assert.Panics(t, func() {
		spiffeid.RequireFromURI(&url.URL{})
	})
}

func TestRequireTrustDomainFromString(t *testing.T) {
	assert.NotPanics(t, func() {
		td := spiffeid.RequireTrustDomainFromString("spiffe://trustdomain/path")
		assert.Equal(t, "trustdomain", td.String())
	})
	assert.Panics(t, func() {
		spiffeid.RequireTrustDomainFromString("spiffe://TRUSTDOMAIN/path")
	})
}

func TestRequireTrustDomainFromURI(t *testing.T) {
	assert.NotPanics(t, func() {
		td := spiffeid.RequireTrustDomainFromURI(&url.URL{Scheme: "spiffe", Host: "trustdomain", Path: "/path"})
		assert.Equal(t, "trustdomain", td.String())
	})
	assert.Panics(t, func() {
		spiffeid.RequireTrustDomainFromURI(&url.URL{})
	})
}

func TestRequireFormatPath(t *testing.T) {
	assert.NotPanics(t, func() {
		path := spiffeid.RequireFormatPath("/%s", "path")
		assert.Equal(t, "/path", path)
	})
	assert.Panics(t, func() {
		spiffeid.RequireFormatPath("%s", "path")
	})
}

func TestRequireJoinPathSegments(t *testing.T) {
	assert.NotPanics(t, func() {
		path := spiffeid.RequireJoinPathSegments("path")
		assert.Equal(t, "/path", path)
	})
	assert.Panics(t, func() {
		spiffeid.RequireJoinPathSegments("/absolute")
	})
}
