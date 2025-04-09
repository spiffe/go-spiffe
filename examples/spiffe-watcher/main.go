package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const socketPath = "unix:///tmp/agent.sock"

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	// Wait for an os.Interrupt signal
	go waitForCtrlC(cancel)

	// Start X.509 and JWT watchers
	startWatchers(ctx)
}

func startWatchers(ctx context.Context) {
	var wg sync.WaitGroup

	// Creates a new Workload API client, connecting to provided socket path
	// Environment variable `SPIFFE_ENDPOINT_SOCKET` is used as default
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		log.Fatalf("Unable to create workload API client: %v", err)
	}
	defer client.Close()

	wg.Add(1)
	// Start a watcher for X.509 SVID updates
	go func() {
		defer wg.Done()
		err := client.WatchX509Context(ctx, &x509Watcher{})
		if err != nil && status.Code(err) != codes.Canceled {
			log.Fatalf("Error watching X.509 context: %v", err)
		}
	}()

	wg.Add(1)
	// Start a watcher for JWT bundle updates
	go func() {
		defer wg.Done()
		err := client.WatchJWTBundles(ctx, &jwtWatcher{})
		if err != nil && status.Code(err) != codes.Canceled {
			log.Fatalf("Error watching JWT bundles: %v", err)
		}
	}()

	wg.Wait()
}

// x509Watcher is a sample implementation of the workloadapi.X509ContextWatcher interface
type x509Watcher struct{}

// UpdateX509SVIDs is run every time an SVID is updated
func (x509Watcher) OnX509ContextUpdate(c *workloadapi.X509Context) {
	for _, svid := range c.SVIDs {
		pem, _, err := svid.Marshal()
		if err != nil {
			log.Fatalf("Unable to marshal X.509 SVID: %v", err)
		}

		log.Printf("SVID updated for %q: \n%s\n", svid.ID, string(pem))
	}
}

// OnX509ContextWatchError is run when the client runs into an error
func (x509Watcher) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Printf("OnX509ContextWatchError error: %v", err)
	}
}

// jwtWatcher is a sample implementation of the workloadapi.JWTBundleWatcher interface
type jwtWatcher struct{}

// UpdateX509SVIDs is run every time a JWT Bundle is updated
func (jwtWatcher) OnJWTBundlesUpdate(bundleSet *jwtbundle.Set) {
	for _, bundle := range bundleSet.Bundles() {
		jwt, err := bundle.Marshal()
		if err != nil {
			log.Fatalf("Unable to marshal JWT Bundle : %v", err)
		}
		log.Printf("jwt bundle updated %q: %s", bundle.TrustDomain(), string(jwt))
	}
}

// OnJWTBundlesWatchError is run when the client runs into an error
func (jwtWatcher) OnJWTBundlesWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Printf("OnJWTBundlesWatchError error: %v", err)
	}
}

// waitForCtrlC waits until an os.Interrupt signal is sent (ctrl + c)
func waitForCtrlC(cancel context.CancelFunc) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	<-signalCh

	cancel()
}
