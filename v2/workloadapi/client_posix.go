//go:build !windows
// +build !windows

package workloadapi

// appendDialOptionsOS appends OS specific dial options
func (c *Client) appendDialOptionsOS() {
	// No options to add in this platform
}
