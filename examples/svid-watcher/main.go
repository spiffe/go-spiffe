package main

import (
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/spiffe/go-spiffe/workload"
)

func main() {
	// Creates a new Workload API client for X.509 SVIDs.
	// A watcher must be provided to get notifications for SVIDs updates and errors.
	x509SVIDClient, err := workload.NewX509SVIDClient(watcher{}, workload.WithAddr("unix:///tmp/agent.sock"))
	if err != nil {
		log.Fatalf("Unable to create x509SVIDClient: %v", err)
	}

	// Start the client.
	// The client starts in its own go routine and notifies updates through the watcher.
	// Note that calling Start() after Stop() is not supported.
	err = x509SVIDClient.Start()
	if err != nil {
		log.Fatalf("Unable to start x509SVIDClient: %v", err)
	}

	// Wait for an os.Interrupt signal
	waitForCtrlC()

	// Stop the X.509 SVID client
	err = x509SVIDClient.Stop()
	if err != nil {
		log.Fatalf("Unable to properly stop x509SVIDClient: %v", err)
	}
}

// watcher is a sample implementation of the workload.X509SVIDWatcher interface
type watcher struct{}

// UpdateX509SVIDs is run every time an SVID is updated
func (watcher) UpdateX509SVIDs(svids *workload.X509SVIDs) {
	for _, svid := range svids.SVIDs {
		log.Printf("SVID updated for spiffeID: %q", svid.SPIFFEID)
	}
}

// OnError is run when the client runs into an error
func (watcher) OnError(err error) {
	log.Printf("X509SVIDClient error: %v", err)
}

// waitForCtrlC waits until an os.Interrupt signal is sent (ctrl + c)
func waitForCtrlC() {
	var wg sync.WaitGroup
	wg.Add(1)
	var signalCh chan os.Signal
	signalCh = make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	go func() {
		<-signalCh
		wg.Done()
	}()
	wg.Wait()
}
