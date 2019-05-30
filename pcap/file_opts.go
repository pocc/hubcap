// Package pcap file operations
package pcap

import (
	"bytes"
	"fmt"
	"os/exec"
)

// IsPcap returns whether Wireshark recognizes the file as a capture
func IsPcap(filepath string) error {
	cmd := exec.Command("captype", filepath)
	stdout := new(bytes.Buffer)
	cmd.Stdout = stdout
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("\033[91mERROR\033[0m captype failed: %s when parsing filepath %s", err, filepath)
	}
	// capinfos output like `/path/to/file.pcap: pcap\n`
	stdout.ReadBytes(' ')
	fileType := string(stdout.Bytes())
	// get rid of trailing newline
	fileType = fileType[:len(fileType)-1]
	// *shark can read .gz, but not most compression/archive formats
	if fileType == "unknown" {
		return fmt.Errorf("\033[91mERROR\033[0m captype: %s is not a recognized capture", filepath)
	}
	return nil
}
