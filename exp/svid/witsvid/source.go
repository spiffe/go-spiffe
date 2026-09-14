package witsvid

import "github.com/spiffe/go-spiffe/v2/spiffeid"

// Source is a source of WIT-SVIDs.
type Source interface {
	// GetWITSVID returns the default WIT-SVID from the source. It is used by
	// code that presents a credential and therefore has no ID to look up.
	GetWITSVID() (*SVID, error)

	// GetWITSVIDForID returns the WIT-SVID for the given SPIFFE ID.
	GetWITSVIDForID(id spiffeid.ID) (*SVID, error)
}
