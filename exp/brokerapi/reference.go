package brokerapi

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

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

	if workloadReference, ok := reference.(*brokerpb.WorkloadReference); ok {
		if workloadReference.Reference == nil {
			return nil, errors.New("brokerapi: workload reference is not valid")
		}
		return workloadReference, nil
	}

	anyReference, err := anypb.New(reference)
	if err != nil {
		return nil, fmt.Errorf("brokerapi: failed to marshal workload reference: %w", err)
	}

	return &brokerpb.WorkloadReference{
		Reference: anyReference,
	}, nil
}

func validateReferenceScope(reference *brokerpb.WorkloadReference, address string) error {
	if !isPIDReference(reference) || isLocalAddress(address) {
		return nil
	}
	return errors.New("brokerapi: workload PID references can only be used with a local Broker API address")
}

func isPIDReference(reference *brokerpb.WorkloadReference) bool {
	return reference != nil &&
		reference.Reference != nil &&
		reference.Reference.MessageIs(&brokerpb.WorkloadPIDReference{})
}

func isLocalAddress(address string) bool {
	u, err := url.Parse(address)
	if err != nil {
		return false
	}

	switch u.Scheme {
	case "unix":
		return true
	case "tcp":
		host := u.Hostname()
		if strings.EqualFold(host, "localhost") {
			return true
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	default:
		return false
	}
}
