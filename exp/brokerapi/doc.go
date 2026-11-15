// Package brokerapi provides high-level access to the SPIFFE Broker API.
//
// The package is split into two layers. The Client layer establishes and
// maintains a connection to the SPIFFE Broker API. The source layer provides
// implementations of the go-spiffe source interfaces for a specific workload
// reference, backed by a Client.
//
//	client, err := brokerapi.New(ctx,
//		tlsconfig.AuthorizeID(brokerID),
//		brokerapi.WithAddr(addr),
//	)
//	if err != nil {
//		// handle error
//	}
//	defer client.Close()
//
//	source, err := client.NewX509Source(ctx, &brokerpb.WorkloadPIDReference{
//		Pid: int32(os.Getpid()),
//	})
//	if err != nil {
//		// handle error
//	}
//	defer source.Close()
//
// Experimental: subject to change.
package brokerapi
