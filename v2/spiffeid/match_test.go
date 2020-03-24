package spiffeid_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
)

func TestMatchAny(t *testing.T) {
	matcher := spiffeid.MatchAny()
	assert.NoError(t, matcher(spiffeid.ID{}))
	assert.NoError(t, matcher(spiffeid.Must("domain.test", "path", "element")))
	assert.NoError(t, matcher(spiffeid.Must("domain.test")))
}

func TestMatchID_AgainstIDWithPath(t *testing.T) {
	matcher := spiffeid.MatchID(spiffeid.Must("domain.test", "path", "element"))

	// Common case
	err := matcher(spiffeid.Must("domain.test", "path", "element"))
	assert.NoError(t, err)

	// Different paths
	err = matcher(spiffeid.Must("domain.test", "path"))
	assert.EqualError(t, err, "unexpected ID \"spiffe://domain.test/path\"")

	// ID has empty path
	err = matcher(spiffeid.Must("domain.test"))
	assert.EqualError(t, err, "unexpected ID \"spiffe://domain.test\"")

	// Empty ID
	err = matcher(spiffeid.ID{})
	assert.EqualError(t, err, "unexpected ID \"\"")
}

func TestMatchID_AgainstIDWithoutPath(t *testing.T) {
	matcher := spiffeid.MatchID(spiffeid.Must("domain.test"))

	// With path
	err := matcher(spiffeid.Must("domain.test", "path", "element"))
	assert.EqualError(t, err, "unexpected ID \"spiffe://domain.test/path/element\"")

	// Without path
	err = matcher(spiffeid.Must("domain.test"))
	assert.NoError(t, err)
}

func TestMatchOneOf_OnAListOfIDs(t *testing.T) {
	matcher := spiffeid.MatchOneOf(
		spiffeid.Must("domain.test"),
		spiffeid.Must("domain.test", "path"),
		spiffeid.Must("domain.test", "path", "element"),
		spiffeid.Must("example.org"),
	)
	assert.NoError(t, matcher(spiffeid.Must("domain.test")))
	assert.NoError(t, matcher(spiffeid.Must("example.org")))
	assert.NoError(t, matcher(spiffeid.Must("domain.test", "path")))
	assert.NoError(t, matcher(spiffeid.Must("domain.test", "path", "element")))
	assert.EqualError(t, matcher(spiffeid.Must("domain.test", "element")), "unexpected ID \"spiffe://domain.test/element\"")
}

func TestMatchOneOf_OnAnEmptyListOfIDs(t *testing.T) {
	matcher := spiffeid.MatchOneOf()
	assert.EqualError(t, matcher(spiffeid.Must("domain.test")), "unexpected ID \"spiffe://domain.test\"")
	assert.EqualError(t, matcher(spiffeid.ID{}), "unexpected ID \"\"")
}

func TestMatchMemberOf_AgainstNonEmptyTrustDomain(t *testing.T) {
	matcher := spiffeid.MatchMemberOf(spiffeid.RequireTrustDomainFromString("domain.test"))
	assert.NoError(t, matcher(spiffeid.Must("domain.test")))
	assert.NoError(t, matcher(spiffeid.Must("domain.test", "path", "element")))
	assert.EqualError(t, matcher(spiffeid.Must("example.org")), "unexpected trust domain \"example.org\"")
	assert.EqualError(t, matcher(spiffeid.ID{}), "unexpected trust domain \"\"")
}

func TestMatchMemberOf_AgainstEmptyTrustDomain(t *testing.T) {
	matcher := spiffeid.MatchMemberOf(spiffeid.TrustDomain{})
	assert.EqualError(t, matcher(spiffeid.Must("domain.test")), "unexpected trust domain \"domain.test\"")
	assert.EqualError(t, matcher(spiffeid.Must("domain.test", "path", "element")), "unexpected trust domain \"domain.test\"")
	assert.EqualError(t, matcher(spiffeid.Must("example.org")), "unexpected trust domain \"example.org\"")
	assert.NoError(t, matcher(spiffeid.ID{}))
}
