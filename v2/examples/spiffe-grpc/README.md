# gRPC over mTLS example 

This example shows how two services using gRPC can communicate using mTLS with X509 SVIDs obtained from SPIFFE Workload API.

Each service is connecting to the Workload API to fetch its identities. Since this example assumes the SPIRE implementation, it uses the SPIRE default socket path: `/tmp/agent.sock`. 

```go
source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
```

When the socket path is not provided, the value from the `SPIFFE_ENDPOINT_SOCKET` environment variable is used.

```go
source, err := workloadapi.NewX509Source(ctx)
```

The **gRPC server** uses the [workloadapi.X509Source](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/workloadapi?tab=doc#X509Source) to create a `tls.Config` for mTLS that authenticates the client certificate and verifies that it has the SPIFFE ID `spiffe://examples.org/client`.

The `tls.Config` is used to create TLS transport credentials for the gRPC server.

```go
clientID := spiffeid.RequireFromString("spiffe://example.org/client")
tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeID(clientID))

s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
```
	
On the other side, the **gRPC client** uses the [workloadapi.X509Source](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/workloadapi?tab=doc#X509Source) to create a `tls.Config` for mTLS that authenticates the server certificate and verifies that it has the SPIFFE ID `spiffe://examples.org/server`.

```go
serverID := spiffeid.RequireFromString("spiffe://example.org/server")
tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(serverID))

conn, err := grpc.DialContext(ctx, "localhost:50051", grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
```

The [tlsconfig.Authorizer](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#Authorizer) is used to authorize the mTLS peer. In this example, both the client and server use it to authorize the specific SPIFFE ID of the other side of the connection.

That is it! The go-spiffe library fetches and automatically renews the X.509 SVIDs of both workloads from the Workload API provider (i.e. SPIRE).

As soon as the mTLS connection is established, the client sends a message to the server and gets a response.

## Building
Build the client workload:
```bash
cd examples/spiffe-grpc/client
go build
```

Build the server workload:
```bash
cd examples/spiffe-grpc/server
go build
```

## Running
This example assumes the following preconditions:
- There are a SPIRE server and agent up and running.
- There is a Unix workload attestor configured.
- The trust domain is `example.org`
- The agent SPIFFE ID is `spiffe://example.org/host`.
- There are a `server-workload` and `client-workload` users in the system.

### 1. Create the registration entries
Create the registration entries for the client and server workloads:

Server:
```bash
./spire-server entry create -spiffeID spiffe://example.org/server \
                            -parentID spiffe://example.org/host \
                            -selector unix:user:server-workload
```

Client: 
```bash
./spire-server entry create -spiffeID spiffe://example.org/client \
                            -parentID spiffe://example.org/host \
                            -selector unix:user:client-workload
```

### 2. Start the server
Start the server with the `server-workload` user:
```bash
sudo -u server-workload ./server
```

### 3. Run the client
Run the client with the `client-workload` user:
```bash
sudo -u client-workload ./client
```

The server should have received a _"world"_ message and responded with a _"Hello world"_ message.

If either workload encounters a peer with a different SPIFFE ID, they will abort the TLS handshake and the connection will fail. 

```
sudo -u server-workload ./client

Error connecting to server rpc error: code = Unavailable desc = connection closed
```
