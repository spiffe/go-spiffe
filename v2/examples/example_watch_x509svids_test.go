package examples_test

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func Example_watchX509Context() {
	var watcher workloadapi.X509ContextWatcher
	err := workloadapi.WatchX509Context(context.TODO(), watcher)
	if err != nil {
		// TODO: handle error
	}
}
