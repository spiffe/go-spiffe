// Package witbundle provides WIT bundle related functionality.
//
// A bundle represents a collection of WIT authorities, i.e., those that
// are used to authenticate SPIFFE WIT-SVIDs.
//
// You can create a new bundle for a specific trust domain:
//
//	td := spiffeid.RequireTrustDomainFromString("example.org")
//	bundle := witbundle.New(td)
//
// Or you can load it from disk:
//
//	td := spiffeid.RequireTrustDomainFromString("example.org")
//	bundle := witbundle.Load(td, "bundle.jwks")
//
// The bundle can be initialized with WIT authorities:
//
//	td := spiffeid.RequireTrustDomainFromString("example.org")
//	var witAuthorities map[string]crypto.PublicKey = ...
//	bundle := witbundle.FromWITAuthorities(td, witAuthorities)
//
// In addition, you can add WIT authorities to the bundle:
//
//	var keyID string = ...
//	var publicKey crypto.PublicKey = ...
//	bundle.AddWITAuthority(keyID, publicKey)
//
// Bundles can be organized into a set, keyed by trust domain:
//
//	set := witbundle.NewSet()
//	set.Add(bundle)
//
// A Source is source of WIT bundles for a trust domain. Both the Bundle
// and Set types implement Source:
//
//	// Initialize the source from a bundle or set
//	var source witbundle.Source = bundle
//	// ... or ...
//	var source witbundle.Source = set
//
//	// Use the source to query for bundles by trust domain
//	bundle, err := source.GetWITBundleForTrustDomain(td)
package witbundle
