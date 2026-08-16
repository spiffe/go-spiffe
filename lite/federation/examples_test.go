package federation_test

import (
	"context"

	"github.com/spiffe/go-spiffe/lite/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/lite/federation"
	"github.com/spiffe/go-spiffe/lite/spiffeid"
)

func ExampleFetchBundle_webPKI() {
	endpointURL := "https://example.org:8443/bundle"
	trustDomain, err := spiffeid.TrustDomainFromString("example.org")
	if err != nil {
		// TODO: handle error
	}

	bundle, err := federation.FetchBundle(context.TODO(), trustDomain, endpointURL)
	if err != nil {
		// TODO: handle error
	}

	// TODO: use bundle
	bundle = bundle
}

func ExampleFetchBundle_sPIFFEAuth() {
	// Obtain a bundle from the example.org trust domain from a server hosted
	// at https://example.org/bundle with the
	// spiffe://example.org/bundle-server SPIFFE ID.
	endpointURL := "https://example.org:8443/bundle"
	trustDomain, err := spiffeid.TrustDomainFromString("example.org")
	if err != nil {
		// TODO: handle error
	}
	serverID := spiffeid.RequireFromPath(trustDomain, "/bundle-server")

	bundle, err := spiffebundle.Load(trustDomain, "bundle.json")
	if err != nil {
		// TODO: handle error
	}

	bundleSet := spiffebundle.NewSet(bundle)
	bundleSet.Add(bundle)

	updatedBundle, err := federation.FetchBundle(context.TODO(), trustDomain, endpointURL,
		federation.WithSPIFFEAuth(bundleSet, serverID))
	if err != nil {
		// TODO: handle error
	}

	// TODO: use bundle, e.g. replace the bundle in the bundle set so it can
	// be used to fetch the next bundle.
	bundleSet.Add(updatedBundle)
}

func ExampleWatchBundle_webPKI() {
	endpointURL := "https://example.org:8443/bundle"
	trustDomain, err := spiffeid.TrustDomainFromString("example.org")
	if err != nil {
		// TODO: handle error
	}

	var watcher federation.BundleWatcher
	err = federation.WatchBundle(context.TODO(), trustDomain, endpointURL, watcher)
	if err != nil {
		// TODO: handle error
	}
}

func ExampleWatchBundle_sPIFFEAuth() {
	// Watch for bundle updates from the example.org trust domain from a server
	// hosted at https://example.org/bundle with the
	// spiffe://example.org/bundle-server SPIFFE ID.
	endpointURL := "https://example.org:8443/bundle"
	trustDomain, err := spiffeid.TrustDomainFromString("example.org")
	if err != nil {
		// TODO: handle error
	}
	serverID := spiffeid.RequireFromPath(trustDomain, "/bundle-server")

	bundle, err := spiffebundle.Load(trustDomain, "bundle.json")
	if err != nil {
		// TODO: handle error
	}

	bundleSet := spiffebundle.NewSet(bundle)
	bundleSet.Add(bundle)

	// TODO: When implementing the watcher's OnUpdate, replace the bundle for
	// the trust domain in the bundle set so the next connection uses the
	// updated bundle.
	var watcher federation.BundleWatcher

	err = federation.WatchBundle(context.TODO(), trustDomain, endpointURL,
		watcher, federation.WithSPIFFEAuth(bundleSet, serverID))
	if err != nil {
		// TODO: handle error
	}
}
