# gRPC SVID client 

This example shows how a workload can create a gRPC client to obtain X.509 and JWT SVIDs from the [SPIFFE Workload API](../../proto/spiffe/workload/workload.proto).

The first step is to create a SPIFFE client. It implements different methods to query the SPIFFE Workload API. It takes a `grpc.ClientConn` containing the Workload API address.

```go
client := workload.NewSpiffeWorkloadAPIClient(conn)
```

Once the client is created, it is possible to fetch SVIDs and bundles through it. For example:
```go
resp, err := client.FetchJWTSVID(ctx, req)
```

Check the methods of the `workload.SpiffeWorkloadAPIClient` interface for more details.


## Building
Build the svid-grpc-client example:

```bash
cd examples/svid-grpc-client
go build
```

## Running
This example assumes the following preconditions:
- There are a SPIRE server and agent up and running.
- There is a Unix workload attestor configured.
- The trust domain is `example.org`
- The agent SPIFFE ID is `spiffe://example.org/host`.
- There is a `svid-grpc-client` user in the system.

### 1. Create the registration entry
Create a registration entry for the svid-grpc-client workload:
```bash
./spire-server entry create -spiffeID spiffe://example.org/svid-grpc-client \
                            -parentID spiffe://example.org/host \
                            -selector unix:user:svid-grpc-client
```

### 2. Run the workload
Start the svid-grpc-client with the `svid-grpc-client` user:
```bash
sudo -u svid-grpc-client ./svid-grpc-client
```

The workload fetches its X.509 and JWT SVIDs from the workload API and prints them on the terminal.
```
2019/12/05 09:19:52 Received 1 X.509 SVID(s)
2019/12/05 09:19:52 SVID 0 is "spiffe://example.org/server":
-----BEGIN CERTIFICATE-----
MIICAzCCAYmgAwIBAgIRAIfn8KlWwbVefRk4FsqFruQwCgYIKoZIzj0EAwMwHjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTAeFw0xOTEyMDUxMjE3MDZaFw0x
OTEyMDUxMzE3MTZaMB0xCzAJBgNVBAYTAlVTMQ4wDAYDVQQKEwVTUElSRTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABG7gy4Ig7biW6iO3K0Yj2nNDyQH93VM7WbBv
yQb4xBhWEw6abW3ZsLqQE0FgL1zhRkAAL6C6MhVE3q3DfUwlQQijgagwgaUwDgYD
VR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNV
HRMBAf8EAjAAMB0GA1UdDgQWBBSxba8ylrBtt5MiMrGGg+8jnbkYEzAfBgNVHSME
GDAWgBS/tc5zshDnITfIZGTmk9wrDvE+NzAmBgNVHREEHzAdhhtzcGlmZmU6Ly9l
eGFtcGxlLm9yZy9zZXJ2ZXIwCgYIKoZIzj0EAwMDaAAwZQIxAIqAQb5sRcMJf1J3
F1MzEh5aTuIwzhpvShMLMEfXQtxvoUzASHGg6f0iLFXXzjWtqgIwaMVH9ANK52IB
91JqnM0+ynexHtcLEw2+HWsKLiY02Ma9FY+jri2hODMeTEn4sDxh
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB/TCCAYOgAwIBAgIQMEaojpeZslcp5itFbTa/ljAKBggqhkjOPQQDAzAeMQsw
CQYDVQQGEwJVUzEPMA0GA1UECgwGU1BJRkZFMB4XDTE5MTIwNTEyMTYyMloXDTE5
MTIwNjEyMTYzMlowHjELMAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTB2MBAG
ByqGSM49AgEGBSuBBAAiA2IABKnK1Mauqy+sK2vaezXiV7ODtWSox2EKSV3dENLM
XN3A7RJ8T3Wex6l9dp0zsJt2iT1Z4Bmol+5gXqsPBqU3zfj71WNPGtFZByTMCfNx
93ciH0zybZKTmcCSpvneDbg3FKOBhTCBgjAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUv7XOc7IQ5yE3yGRk5pPcKw7xPjcwHwYDVR0j
BBgwFoAUh6XzV6LwNazA+GTEVOdu07o5yOgwHwYDVR0RBBgwFoYUc3BpZmZlOi8v
ZXhhbXBsZS5vcmcwCgYIKoZIzj0EAwMDaAAwZQIwWgK6ZoU48zG2EqQFyhi0gDR4
j+Sq4/kjnW2rlUgiMV3YExQFSLnpcv9bmupjb2JhAjEA/cbs20YuGHIvXUDh65I7
Hk0vgNL8iUSWbc7XGNRvqHButHOv0dErJFYTAjvWonFV
-----END CERTIFICATE-----

2019/12/05 09:19:52 Received 1 JWT SVID(s)
2019/12/05 09:19:52 SVID 0 is "spiffe://example.org/server":
eyJhbGciOiJFUzI1NiIsImtpZCI6Ino0M0Vic0ZxM1Z0TWc4bU02YlFPcGlhZDNqSHhMdGpoIiwidHlwIjoiSldUIn0.eyJhdWQiOlsic3BpZmZlOi8vZXhhbXBsZS5vcmcvc2VydmljZS0xIl0sImV4cCI6MTU3NTU0ODY5MiwiaWF0IjoxNTc1NTQ4MzkyLCJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy9zZXJ2ZXIifQ.Oyi0LIln1CLLTWZFOCXmw1pl_MGu92XIPQaHi7
```
