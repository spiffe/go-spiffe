# Mutually Authenticated TLS (mTLS)

This example shows how to use the go-spiffe library to establish an mTLS connection between two workloads using X.509 SVIDs obtained from the SPIFFE Workload API. 

One workload acts as a client and the other as the server. 

The scenario goes like this:
1. The server starts listening for incoming SPIFFE-compliant mTLS connections.
2. The client establishes an SPIFFE-compliant mTLS connection to the server. 
3. The server starts waiting for a message from the client.
4. The client sends a "Hello server" message and starts waiting for a response.
5. The server reads the client's message, logs it to stdout, and sends a "Hello client" message as the response.
6. The client reads the server's response and then closes the connection.

## Listening
To start listening for incoming connections the **server workload** uses the [spiffetls.ListenWithMode](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls?tab=doc#ListenWithMode) function as follows:
```go
	listener, err := spiffetls.ListenWithMode(ctx, "tcp", serverAddress,
		spiffetls.MTLSServerWithSourceOptions(
			tlsconfig.AuthorizeID(clientID),
			workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)),
		))
```
Where:
- ctx is a `context.Context`. `ListenWithMode` blocks until the first Workload API response is received or this context times out or is cancelled.
- serverAddress is the address (`localhost:55555`) where the server workload is going to listen for client connections.
- [spiffetls.MTLSServerWithSourceOptions](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls?tab=doc#MTLSServerWithSourceOptions) is used to configure the [X509Source](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2@v2.0.0-alpha.3/workloadapi?tab=doc#X509Source) used by the internal Workload API client.
- clientID is a SPIFFE ID (`spiffe://example.org/client`), which along with the [tlsconfig.AuthorizeID](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#AuthorizeID) function configures the server to accept only clients that present an X509-SVID with a matching SPIFFE ID. You can pick any of the functions that return a [tlsconfig.Authorizer](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#Authorizer) included with the library, or you can make your own. 
- socketPath is the address of the Workload API (`unix:///tmp/agent.sock`) to which the internal Workload API client connects to get up-to-date SVIDs. Alternatively, we could have omitted this configuration option, in which case the listener would have used the `SPIFFE_ENDPOINT_SOCKET` environment variable to locate the Workload API. The code could have then been written like this:
```go
	listener, err := spiffetls.Listen(ctx, "tcp", serverAddress, tlsconfig.AuthorizeID(spiffeID))
```

## Dialing
To establish a connection, the **client workload** uses the [spiffetls.DialWithMode](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls?tab=doc#DialWithMode) function as follows:
```go
	conn, err := spiffetls.DialWithMode(ctx, "tcp", serverAddress,
		spiffetls.MTLSClientWithSourceOptions(
			tlsconfig.AuthorizeID(spiffeID),
			workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)),
		))
```
Where:
- ctx is a `context.Context`. `DialWithMode` blocks until the first Workload API response is received or this context times out or is cancelled.
- serverAddress is the address (`localhost:55555`) where the server workload is listening for client connections.
- [spiffetls.MTLSClientWithSourceOptions](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls?tab=doc#MTLSClientWithSourceOptions) is used to configure the [X509Source](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2@v2.0.0-alpha.3/workloadapi?tab=doc#X509Source) used by the internal Workload API client.
- spiffeID is a SPIFFE ID (`spiffe://example.org/server`), which along with the [tlsconfig.AuthorizeID](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#AuthorizeID) function configures the client to connect only to a server that presents an X509-SVID with a matching SPIFFE ID. You can pick any of the functions that return a [tlsconfig.Authorizer](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#Authorizer) included with the library, or you can make your own. 
- socketPath is the address of the Workload API (`unix:///tmp/agent.sock`) to which the internal Workload API client connects to get up-to-date SVIDs. Alternatively, we could have omitted this configuration option, in which case the dialer would have used the `SPIFFE_ENDPOINT_SOCKET` environment variable to locate the Workload API. The code could have then been written like this:
```go
	conn, err := spiffetls.Dial(ctx, "tcp", serverAddress, tlsconfig.AuthorizeID(spiffeID))
```

## That is it!
As we can see the go-spiffe library allows your application to use the Workload API transparently for both ends of the connection. The go-spiffe library takes care of fetching and automatically renewing the X.509 SVIDs needed to maintain a secure communication.

## Building
To build the client workload:
```bash
cd examples/spiffe-tls/client
go build
```

To build the server workload:
```bash
cd examples/spiffe-tls/server
go build
```

## Running
This example assumes the following preconditions:
- There is a SPIRE server and a SPIRE agent up and running.
- There is a Unix workload attestor configured.
- The trust domain is `example.org`.
- The agent's SPIFFE ID is `spiffe://example.org/host`.
- There is a `server-workload` user and a `client-workload` user in the system.

### 1. Create the registration entries
Create the registration entries for the workloads:

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

The server should have received a _"Hello server"_ message and responded with a _"Hello client"_ message.

If either workload encounters a peer with a different SPIFFE ID than the one it expects, the workload aborts the TLS handshake and the connection fails.  
For instance, when running the client with the server's user: 
```
sudo -u server-workload ./client

Unable to read server response: remote error: tls: bad certificate
```

The server log would contain:
```
Error reading incoming data: unexpected ID "spiffe://example.org/server"
```
