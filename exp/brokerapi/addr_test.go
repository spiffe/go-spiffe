package brokerapi

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type validateAddressCase struct {
	addr string
	err  string
}

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
	testCases := []validateAddressCase{
		{
			addr: "\t",
			err:  "net/url: invalid control character in URL",
		},
		{
			addr: "blah",
			err:  ErrInvalidEndpointScheme.Error(),
		},
		{
			addr: "tcp:opaque",
			err:  "broker endpoint tcp socket URI must not be opaque",
		},
		{
			addr: "tcp://",
			err:  "broker endpoint tcp socket URI must include a host",
		},
		{
			addr: "tcp://1.2.3.4:5?whatever",
			err:  "broker endpoint tcp socket URI must not include query values",
		},
		{
			addr: "tcp://1.2.3.4:5#whatever",
			err:  "broker endpoint tcp socket URI must not include a fragment",
		},
		{ //nolint:gosec // G101: intentional userinfo fixture exercising the rejection path
			addr: "tcp://john:doe@1.2.3.4:5/path",
			err:  "broker endpoint tcp socket URI must not include user info",
		},
		{
			addr: "tcp://1.2.3.4:5/path",
			err:  "broker endpoint tcp socket URI must not include a path",
		},
		{
			addr: "tcp://foo",
			err:  "broker endpoint tcp socket URI host component must include a port",
		},
		{
			addr: "tcp://1.2.3.4",
			err:  "broker endpoint tcp socket URI host component must include a port",
		},
		{
			addr: "tcp://:8443",
			err:  "broker endpoint tcp socket URI host component must include a hostname or IP",
		},
		{
			addr: "tcp://1.2.3.4:5",
			err:  "",
		},
		{
			addr: "tcp://broker.example.com:8443",
			err:  "",
		},
		{
			addr: "tcp://[::1]:8443",
			err:  "",
		},
		{
			addr: "unix:opaque",
			err:  "broker endpoint unix socket URI must not be opaque",
		},
		{
			addr: "unix://",
			err:  "broker endpoint unix socket URI must include a path",
		},
		{
			addr: "unix:///foo?whatever",
			err:  "broker endpoint unix socket URI must not include query values",
		},
		{
			addr: "unix:///foo#whatever",
			err:  "broker endpoint unix socket URI must not include a fragment",
		},
		{ //nolint:gosec // G101: intentional userinfo fixture exercising the rejection path
			addr: "unix://john:doe@foo/path",
			err:  "broker endpoint unix socket URI must not include user info",
		},
		{
			addr: "unix://foo",
			err:  "broker endpoint unix socket URI must not include an authority",
		},
		{
			addr: "unix:///path/to/broker.sock",
			err:  "",
		},
	}

	for _, testCase := range testCases {
		err := ValidateAddress(testCase.addr)
		if testCase.err != "" {
			require.Error(t, err)
			assert.Contains(t, err.Error(), testCase.err)
			continue
		}
		assert.NoError(t, err)
	}
}

func TestTargetFromAddress(t *testing.T) {
	target, err := TargetFromAddress("tcp://1.2.3.4:5")
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4:5", target)

	target, err = TargetFromAddress("tcp://broker.example.com:8443")
	require.NoError(t, err)
	assert.Equal(t, "broker.example.com:8443", target)

	target, err = TargetFromAddress("unix:///path/to/broker.sock")
	require.NoError(t, err)
	assert.Equal(t, "unix:///path/to/broker.sock", target)
}
