package spiffe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpectAnyPeer(t *testing.T) {
	expect := ExpectAnyPeer()
	// It literally does not matter what is passed in here since the callback
	// returned from ExpectAnyPeer does not examine the input and simply
	// returns no error.
	assert.NoError(t, expect("", nil))
}

func TestExpectPeer(t *testing.T) {
	expect := ExpectPeer("spiffe://domain.test/workload1")
	assert.NoError(t, expect("spiffe://domain.test/workload1", nil))
	assert.EqualError(t, expect("spiffe://domain.test/workload2", nil),
		`unexpected peer ID "spiffe://domain.test/workload2": expected "spiffe://domain.test/workload1"`)
}

func TestExpectPeers(t *testing.T) {
	expect := ExpectPeers("spiffe://domain.test/workload1", "spiffe://domain.test/workload2")
	assert.NoError(t, expect("spiffe://domain.test/workload1", nil))
	assert.NoError(t, expect("spiffe://domain.test/workload2", nil))
	assert.EqualError(t, expect("spiffe://domain.test/workload3", nil),
		`unexpected peer ID "spiffe://domain.test/workload3": expected one of ["spiffe://domain.test/workload1" "spiffe://domain.test/workload2"]`)
}

func TestExpectPeerInDomain(t *testing.T) {
	expect := ExpectPeerInDomain("domain1.test")
	assert.NoError(t, expect("spiffe://domain1.test/workload", nil))
	assert.EqualError(t, expect("spiffe://domain2.test/workload", nil),
		`unexpected trust domain "domain2.test" for peer ID "spiffe://domain2.test/workload": expected trust domain "domain1.test"`)
}
