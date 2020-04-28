# go-spiffe (v2) Examples

This section contains a set of standalone examples that demonstrate different use cases for the go-spiffe library.

## Use cases

- [Mutually Authenticated TLS (mTLS)](spiffe-tls/README.md): _Establish mTLS connections between workloads using automatically rotated X.509 SVIDs obtained from the SPIFFE Workload API _

- [SVIDs stream](spiffe-watcher/README.md): _Get automatically rotated X.509 SVIDs and JWT Bundles for your workload._

- [gRPC over mTLS](spiffe-grpc/README.md): _Send gRPC requests between workloads over mTLS using automatically rotated X.509 SVIDs obtained from the SPIFFE Workload API_ 

- [HTTP over mTLS](spiffe-http/README.md): _Send HTTP requests between workloads over mTLS using automatically rotated X.509 SVIDs obtained from the SPIFFE Workload API_ 

- [HTTP over TLS with JWT](spiffe-jwt/README.md): _Send http requests between workload over a TLS + JWT authentication using automatically rotated X.509 SVIDs and JWT SVIDs from the SPIFFE Workload API_
