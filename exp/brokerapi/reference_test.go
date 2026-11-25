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
