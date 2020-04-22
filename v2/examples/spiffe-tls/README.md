# Mutual TLS example

This example shows how two services can communicate using mTLS with X.509 SVIDs obtained from the SPIFFE workload API. 

One of the workloads acts as a client and the other as the server. , it uses the SPIRE default socket path: `/tmp/agent.sock`. This value can also be set directly in the environment or using the [workloadapi.ClientOption](../../workloadapi/option.go#L17) function.

The **server workload** creates a listener using the [spiffetls.Listen](../../spiffetls/listen.go#L38) function.
It uses [spiffetls.MTLSServerWithSourceOptions](../../spiffetls/mode.go#L281) to configure source, and validates presented certificate from client has expected SPIFFE ID.

```go
listener, err := spiffetls.ListenWithMode(ctx, "tcp", serverAddress,
    spiffetls.MTLSServerWithSourceOptions(
        tlsconfig.AuthorizeID(clientID),
        workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)),
    ))
```

Another alternative is to use [](../../spiffetls/listen.go#L21) it will use the value from environment variable `SPIFFE_ENDPOINT_SOCKET` to create connection to workload API

```go
listener, err := spiffetls.Listen(context.Background(), "tcp", serverAddress, tlsconfig.AuthorizeID(spiffeID))
```

On the other hand, the **client workload** creates a `net.Conn` using the [spiffetls.Dial](../../spiffetls/dial.go#L25) function. 
It uses [spiffetls.MTLSServerWithSourceOptions](../../spiffetls/mode.go#L281) to configure source, and validates than presented certificate from server has expected SPIFFE ID.

```go
conn, err := spiffetls.DialWithMode(ctx, "tcp", serverAddress,
    spiffetls.MTLSClientWithSourceOptions(
        tlsconfig.AuthorizeID(spiffeID),
        workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)),
    ))
```

In the same way than with Listen, Dial allows using environment variable `SPIFFE_ENDPOINT_SOCKET` to create connection to workload API

```go
conn, err := spiffetls.Dial(ctx, "tcp", serverAddress, tlsconfig.AuthorizeID(spiffeID))
``` 

In both cases, a [tlsconfig.Authorizer](../../spiffetls/tlsconfig/authorizer.go#L12) is set to validate the workload is authorized to connect to the other peer. In this example, the [tlsconfig.Authorizer](../../spiffetls/tlsconfig/authorizer.go#L12) was used to allow the client to reach the server and vice versa.

That is it. The go-spiffe library fetches and automatically renews the X.509 SVIDs of both workloads according to the policy defined in the Workload API provider configuration. In this case, the SPIRE server configuration file.

As soon as the mTLS connection is established, the client sends a message to the server and gets a response.


## Building
Build the client workload:
```bash
cd examples/spiffe-mTLS/client
go build
```

Build the server workload:
```bash
cd examples/spiffe-mTLS/server
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

The server should have got a _"Hello server"_ message and responded with a _"Hello client"_ message.

If a workload with another SPIFFE ID tries to establish a connection, the server will reject it. 
 
```
sudo -u server-workload ./client

Unable to read server response: remote error: tls: bad certificate
```

And the server log shows:
```
Error reading incoming data: unexpected ID "spiffe://example.org/server"
```
