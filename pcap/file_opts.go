// Package pcap file operations
package pcap

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
)

// IsPcap returns whether Wireshark recognizes the file as a capture
// Capinfos' StrictTimeOrder (-o) being detected is most predictive of being pcap
func IsPcap(filepath string) error {
	cmd := exec.Command("capinfos", "-c", "-o", filepath)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err != nil && !strings.Contains(string(stderr.Bytes()), "cut short in the middle of a packet") {
		return fmt.Errorf("\033[91mERROR\033[0m captype failed: %s when parsing filepath %s.\n%s", err, filepath, string(stderr.Bytes()))
	}
	outputStr := string(stdout.Bytes())
	isPcap := strings.Contains(outputStr, "Strict time order:   False") || strings.Contains(outputStr, "Strict time order:   True")
	hasZeroPackets := strings.Contains(outputStr, "Number of packets:   0") // K12 files can be packet captures but also have no packets
	if !isPcap || hasZeroPackets {
		return fmt.Errorf(outputStr)
	}
	return nil
}

// fixPcap will remove a common error "appears to have been cut short in the middle of a packet."
// Editcap will report the same error so skip stdout/stderr
func fixPcap(filepath string) {
	cmd := exec.Command("editcap", filepath, filepath)
	stderr := new(bytes.Buffer)
	cmd.Stderr = stderr
	cmd.Run()
	errStr := string(stderr.Bytes())
	// if not expected editcap error, treat as actual
	if !strings.Contains(errStr, "cut short in the middle") && !strings.Contains(errStr, "appears to be damaged") {
		fmt.Printf("\033[93mWARN\033[0m Problem fixing %s with editcap: %s\n", filepath, errStr)
	}
}

// GetSHA256 will get the SHA256 of a file
func GetSHA256(filename string) string {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}
