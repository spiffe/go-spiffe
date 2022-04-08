//go:build windows
// +build windows

package workloadapi

import (
	"github.com/Microsoft/go-winio"
	"google.golang.org/grpc"
)

// appendDialOptionsOS appends OS specific dial options
func (c *Client) appendDialOptionsOS() {
	c.config.dialOptions = append(c.config.dialOptions, grpc.WithContextDialer(winio.DialPipeContext))
}
