# gRPC SVID example 

This example shows how two services using gRPC can communicate using mTLS with X509 SVIDs obtained from SPIFFE workload API.

Each service is connecting to workload API to fetch its identities. Since this example assumes the SPIRE implementation, it uses the SPIRE default socket path: `/tmp/agent.sock`. 

```go
source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
```

In case socket path is not provided using [SourceOption](../../workloadapi/option.go#L39) the value from the environment variable `SPIFFE_ENDPOINT_SOCKET` is used

```go
source, err := workloadapi.NewX509Source(ctx)
```

Then, the **gRPC server** creates a `tls.Config` with server configurations to allow mTLS connections, using previously created [workloadapi.X509Source](../../workloadapi/x509source.go#L17) and validates than the certificate presented to server from client has SPIFFE ID `spiffe://examples.org/client`.

Created `tls.Config` is used when creating gRPC server.

```go
clientID := spiffeid.Must("example.org", "client")
tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeID(clientID))

s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
```
	
On the other hand, the **gRPC client** creates a `tls.Config` with client configurations to allow mTLS connections, , using previously created [workloadapi.X509Source](../../workloadapi/x509source.go#L17) and validates than the certificate presented to server from client has SPIFFE ID `spiffe://examples.org/server`. 

```go
serverID := spiffeid.Must("example.org", "server")
tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(serverID))

conn, err := grpc.DialContext(ctx, "localhost:50051", grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
```

In both cases, a [tlsconfig.Authorizer](../../spiffetls/tlsconfig/authorizer.go#L12) is set to validate the workload is authorized to connect to the other peer. In this example, the [tlsconfig.Authorizer](../../spiffetls/tlsconfig/authorizer.go#L12) was used to allow the client to reach the server and vice versa.

That is it. The go-spiffe library fetches and automatically renews the X.509 SVIDs of both workloads according to the policy defined in the Workload API provider configuration. In this case, the SPIRE server configuration file.

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

The server should have got a _"world"_ message and responded with a _"Hello world"_ message.

If a workload with another SPIFFE ID tries to establish a connection, the server will reject it. 

```
sudo -u server-workload ./client

Error connecting to server rpc error: code = Unavailable desc = connection closed
```
