package workload

import (
	"crypto"
	"crypto/x509"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestClientUpdate(t *testing.T) {
	workloadAPI := spiffetest.NewWorkloadAPI(t, nil)
	defer workloadAPI.Stop()

	ca := spiffetest.NewCA(t)
	svidFoo, keyFoo := ca.CreateX509SVID("spiffe://example.org/foo")
	svidBar, keyBar := ca.CreateX509SVID("spiffe://example.org/bar")

	makeX509SVIDResponse := func(svid []*x509.Certificate, key crypto.Signer) *spiffetest.X509SVIDResponse {
		return &spiffetest.X509SVIDResponse{
			Bundle: ca.Roots(),
			SVIDs: []spiffetest.X509SVID{
				{
					CertChain: svid,
					Key:       key,
				},
			},
		}
	}

	w := newTestWatcher(t)
	c, err := NewX509SVIDClient(w, WithAddr(workloadAPI.Addr()))
	require.NoError(t, err)

	err = c.Start()
	require.NoError(t, err)

	t.Run("connect and update", func(t *testing.T) {
		workloadAPI.SetX509SVIDResponse(makeX509SVIDResponse(svidFoo, keyFoo))
		w.WaitForUpdates(1)

		assert.Len(t, w.Errors, 0)
		assert.Len(t, w.X509SVIDs, 1)
		assert.Equal(t, "spiffe://example.org/foo", w.X509SVIDs[0].Default().SPIFFEID)
		w.X509SVIDs = nil
	})

	t.Run("new update", func(t *testing.T) {
		workloadAPI.SetX509SVIDResponse(makeX509SVIDResponse(svidBar, keyBar))
		w.WaitForUpdates(1)

		assert.Len(t, w.X509SVIDs, 1)
		assert.Equal(t, "spiffe://example.org/bar", w.X509SVIDs[0].Default().SPIFFEID)
		assert.Len(t, w.Errors, 0)
		w.X509SVIDs = nil
	})

	t.Run("workload API error", func(t *testing.T) {
		workloadAPI.SetX509SVIDResponse(nil)
		w.WaitForUpdates(1)

		assert.Len(t, w.Errors, 1)
		// the test workload api implementation returns permission denied if
		// there is no SVID response set.
		assert.Equal(t, codes.PermissionDenied, status.Code(w.Errors[0]))
		assert.Len(t, w.X509SVIDs, 0)
		w.Errors = nil
	})

	t.Run("stop", func(t *testing.T) {
		err = c.Stop()

		assert.NoError(t, err)
		assert.Len(t, w.X509SVIDs, 0)
		assert.Len(t, w.Errors, 0)
	})
}

func TestStartStop(t *testing.T) {
	workloadAPI := spiffetest.NewWorkloadAPI(t, nil)
	defer workloadAPI.Stop()

	w := newTestWatcher(t)
	c, err := NewX509SVIDClient(w, WithAddr(workloadAPI.Addr()))
	require.NoError(t, err)

	t.Run("stop before start", func(t *testing.T) {
		err := c.Stop()
		require.Error(t, err)
		require.Contains(t, err.Error(), "client hasn't started")
	})

	t.Run("start once", func(t *testing.T) {
		err := c.Start()
		require.NoError(t, err)
	})

	t.Run("start twice", func(t *testing.T) {
		err := c.Start()
		require.Error(t, err)
		require.Contains(t, err.Error(), "client already started")
	})

	t.Run("stop", func(t *testing.T) {
		err := c.Stop()
		require.NoError(t, err)
	})

	t.Run("stop twice", func(t *testing.T) {
		err := c.Stop()
		require.Error(t, err)
		require.Contains(t, err.Error(), "client is already stopped")
	})

	t.Run("start after stop", func(t *testing.T) {
		err := c.Start()
		require.Error(t, err)
		require.Contains(t, err.Error(), "client cannot start once stopped")
	})
}

type testWatcher struct {
	t            *testing.T
	X509SVIDs    []*X509SVIDs
	Errors       []error
	updateSignal chan struct{}
	n            int
	timeout      time.Duration
}

func newTestWatcher(t *testing.T) *testWatcher {
	return &testWatcher{
		t:            t,
		updateSignal: make(chan struct{}, 100),
		timeout:      10 * time.Second,
	}
}

func (w *testWatcher) UpdateX509SVIDs(u *X509SVIDs) {
	w.X509SVIDs = append(w.X509SVIDs, u)
	w.n++
	w.updateSignal <- struct{}{}
}

func (w *testWatcher) OnError(err error) {
	w.Errors = append(w.Errors, err)
	w.n++
	w.updateSignal <- struct{}{}
}

func (w *testWatcher) WaitForUpdates(expectedNumUpdates int) {
	numUpdates := 0
	for {
		select {
		case <-w.updateSignal:
			numUpdates++
		case <-time.After(w.timeout):
			require.Fail(w.t, "Timeout exceeding waiting for updates.")
		}
		if numUpdates == expectedNumUpdates {
			return
		}
	}
}
