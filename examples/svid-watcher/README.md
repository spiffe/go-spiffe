# X.509 SVID Watcher example

This example shows how a service can obtain X.509 SVIDs from the SPIFFE workload API which are automatically rotated before expiration.

The library provides a watcher interface type (`workload.X509SVIDWatcher`) that must be implemented to get notifications for SVIDs rotation and errors.
 
Once the watcher is created, the `workload.NewX509SVIDClient` function is called to make the client.
```go
x509SVIDClient, err := workload.NewX509SVIDClient(watcher{}, workload.WithAddr("unix:///tmp/agent.sock"))

```

After checking for errors, the client is started with the `Start` method. It opens a stream to the workload API on separated go routine.

```go
err = x509SVIDClient.Start()
```

The watcher will be notified every time an SVID is updated or an error occurs. 


## Building
Build the svid-watcher example:

```bash
go build ./examples/svid-watcher/
```

## Running
This example assumes there are a SPIRE server and agent up and running with a Unix workload attestor configured. The trust domain is `example.org` and the agent SPIFFE ID is `spiffe://example.org/host`. 

### 1. Create the registration entry
Create the registration entry for the svid-watcher workload:
```bash
./spire-server entry create -spiffeID spiffe://example.org/svid-watcher \
                            -parentID spiffe://example.org/host \
                            -selector unix:user:svid-watcher
```

### 2. Start the workload
Start the svid-watcher with the `svid-watcher` user:
```bash
sudo -u svid-watcher ./svid-watcher
```

The watcher prints the SVID SPIFFE ID every time an SVID is updated.
 
```
2019/12/04 15:36:45 SVID updated for spiffeID: "spiffe://example.org/server"
```


