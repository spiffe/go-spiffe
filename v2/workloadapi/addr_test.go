package workloadapi

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDefaultAddress(t *testing.T) {
	if orig, ok := os.LookupEnv(SocketEnv); ok {
		defer os.Setenv(SocketEnv, orig)
	} else {
		defer os.Unsetenv(SocketEnv)
	}

	os.Unsetenv(SocketEnv)
	addr, ok := GetDefaultAddress()
	assert.False(t, ok)
	assert.Equal(t, "", addr)

	os.Setenv(SocketEnv, "ADDRESS")
	addr, ok = GetDefaultAddress()
	assert.True(t, ok)
	assert.Equal(t, "ADDRESS", addr)
}

func TestValidateAddress(t *testing.T) {
	testCases := []struct {
		addr string
		err  string
	}{
		{
			addr: "\t",
			err:  "workload endpoint socket is not a valid URI: parse \t: net/url: invalid control character in URL",
		},
		{
			addr: "blah",
			err:  "workload endpoint socket URI must have a tcp:// or unix:// scheme",
		},
		{
			addr: "unix:opaque",
			err:  "workload endpoint unix socket URI must not be opaque",
		},
		{
			addr: "unix://",
			err:  "workload endpoint unix socket URI must include a path",
		},
		{
			addr: "unix://foo?whatever",
			err:  "workload endpoint unix socket URI must not include query values",
		},
		{
			addr: "unix://foo#whatever",
			err:  "workload endpoint unix socket URI must not include a fragment",
		},
		{
			addr: "unix://john:doe@foo/path",
			err:  "workload endpoint unix socket URI must not include user info",
		},
		{
			addr: "unix://foo",
			err:  "",
		},
		{
			addr: "tcp:opaque",
			err:  "workload endpoint tcp socket URI must not be opaque",
		},
		{
			addr: "tcp://",
			err:  "workload endpoint tcp socket URI must include a host",
		},
		{
			addr: "tcp://1.2.3.4:5?whatever",
			err:  "workload endpoint tcp socket URI must not include query values",
		},
		{
			addr: "tcp://1.2.3.4:5#whatever",
			err:  "workload endpoint tcp socket URI must not include a fragment",
		},
		{
			addr: "tcp://john:doe@1.2.3.4:5/path",
			err:  "workload endpoint tcp socket URI must not include user info",
		},
		{
			addr: "tcp://1.2.3.4:5/path",
			err:  "workload endpoint tcp socket URI must not include a path",
		},
		{
			addr: "tcp://foo",
			err:  "workload endpoint tcp socket URI host component must be an IP:port",
		},
		{
			addr: "tcp://1.2.3.4",
			err:  "workload endpoint tcp socket URI host component must include a port",
		},
		{
			addr: "tcp://1.2.3.4:5",
			err:  "",
		},
	}

	for _, testCase := range testCases {
		err := ValidateAddress(testCase.addr)
		if testCase.err != "" {
			assert.EqualError(t, err, testCase.err)
			continue
		}
		assert.NoError(t, err)
	}
}
