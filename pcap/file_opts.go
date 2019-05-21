// Package pcap file operations
package pcap

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
)

// IsPcap returns whether Wireshark recognizes the file as a capture
func IsPcap(filepath string) error {
	cmd := exec.Command("captype", filepath)
	stdout := new(bytes.Buffer)
	cmd.Stdout = stdout
	err := cmd.Run()
	if err != nil {
		log.Fatal("captype failed: ", err, " when parsing filepath ", filepath)
	}
	// capinfos output like `/path/to/file.pcap: pcap\n`
	stdout.ReadBytes(' ')
	fileType := string(stdout.Bytes())
	fileType = fileType[:len(fileType)-1] // get rid of trailing newline
	if fileType == "unknown" {
		return fmt.Errorf("\033[93mWARN\033[0m captype: %s is not a recognized capture", filepath)
	}
	return nil
}
