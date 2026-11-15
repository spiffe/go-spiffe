package brokerapi

import (
	"errors"
	"fmt"

	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func newWorkloadReference(reference proto.Message) (*brokerpb.WorkloadReference, error) {
	if reference == nil {
		return nil, errors.New("brokerapi: workload reference is required")
	}
	if !reference.ProtoReflect().IsValid() {
		return nil, errors.New("brokerapi: workload reference is not valid")
	}

	anyReference, err := anypb.New(reference)
	if err != nil {
		return nil, fmt.Errorf("brokerapi: failed to marshal workload reference: %w", err)
	}

	return &brokerpb.WorkloadReference{
		Reference: anyReference,
	}, nil
}
