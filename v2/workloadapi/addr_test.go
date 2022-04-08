package workloadapi

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
			err:  errInvalidScheme.Error(),
		},
	}
	testCases = append(testCases, validateAddressCasesOS()...)

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
