package brokerapi

import (
	"testing"

	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestNewWorkloadReference(t *testing.T) {
	pidReference := &brokerpb.WorkloadPIDReference{Pid: 1234}

	reference, err := newWorkloadReference(pidReference)
	require.NoError(t, err)
	require.Equal(t, "type.googleapis.com/spiffe.broker.WorkloadPIDReference", reference.Reference.TypeUrl)

	actual := new(brokerpb.WorkloadPIDReference)
	require.NoError(t, reference.Reference.UnmarshalTo(actual))
	require.Equal(t, pidReference.Pid, actual.Pid)
}

func TestNewWorkloadReferenceDoesNotDoubleWrap(t *testing.T) {
	anyReference, err := anypb.New(&brokerpb.WorkloadPIDReference{Pid: 1234})
	require.NoError(t, err)
	reference := &brokerpb.WorkloadReference{Reference: anyReference}

	actual, err := newWorkloadReference(reference)
	require.NoError(t, err)
	require.Same(t, reference, actual)
}

func TestNewWorkloadReferenceRejectsEmptyWorkloadReference(t *testing.T) {
	reference, err := newWorkloadReference(&brokerpb.WorkloadReference{})
	require.EqualError(t, err, "brokerapi: workload reference is not valid")
	require.Nil(t, reference)
}

func TestIsLocalAddress(t *testing.T) {
	testCases := []struct {
		address string
		local   bool
	}{
		{address: "unix:///run/spire/broker.sock", local: true},
		{address: "tcp://127.0.0.1:8443", local: true},
		{address: "tcp://[::1]:8443", local: true},
		{address: "tcp://localhost:8443", local: true},
		{address: "tcp://192.0.2.1:8443", local: false},
		{address: "tcp://broker.example.org:8443", local: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.address, func(t *testing.T) {
			require.Equal(t, testCase.local, isLocalAddress(testCase.address))
		})
	}
}

func TestValidateReferenceScope(t *testing.T) {
	anyReference, err := anypb.New(&brokerpb.WorkloadPIDReference{Pid: 1234})
	require.NoError(t, err)
	pidReference := &brokerpb.WorkloadReference{Reference: anyReference}

	require.EqualError(t,
		validateReferenceScope(pidReference, "tcp://192.0.2.1:8443"),
		"brokerapi: workload PID references can only be used with a local Broker API address",
	)
	require.NoError(t, validateReferenceScope(pidReference, "unix:///run/spire/broker.sock"))
	require.NoError(t, validateReferenceScope(pidReference, "tcp://127.0.0.1:8443"))
}
