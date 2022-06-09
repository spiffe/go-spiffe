//go:build windows
// +build windows

package spiffetls_test

import (
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

func listenAndDialCasesOS() []listenAndDialCase {
	return []listenAndDialCase{
		{
			name:             "Wrong workload API server socket",
			dialMode:         spiffetls.TLSClient(tlsconfig.AuthorizeID(serverID)),
			defaultWlAPIAddr: "wrong-socket-path",
			dialErr:          "spiffetls: cannot create X.509 source: workload endpoint socket URI must have a \"tcp\" or \"npipe\" scheme",
			listenErr:        "spiffetls: cannot create X.509 source: workload endpoint socket URI must have a \"tcp\" or \"npipe\" scheme",
		},
	}
}
