package pcap

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// getFileDesc gets the file descriptor of a file
func getFileDesc(t *testing.T, target string) *os.File {
	fd, err := os.Open(target)
	if err != nil {
		t.Log("Problem accessing file", target, ". Error:", err)
		t.FailNow()
	}
	return fd
}

var targetFiles = []string{
	"../.cache/ws_iwarp_connect.tar.gz",
	"../.cache/ws_starteam_sample.tgz",
}

// TestUnTgzip tests both tar.gz and tgz files
func TestUnTgzip(t *testing.T) {
	resultFiles := make([][]string, 0)
	expectedFiles := [][]string{
		{
			"iwarp_connect/C00_M00",
			"iwarp_connect/C00_M00_reject",
			"iwarp_connect/C00_M11",
			"iwarp_connect/C11_M00",
			"iwarp_connect/C11_M11",
		},
		{"starteam_sample.cap"},
	}

	for _, filename := range targetFiles {
		fd := getFileDesc(t, filename)
		gotFiles, err := unTgzip(fd)
		if err != nil {
			t.Log("UnGzip failed for file:", filename, "\nError:", err)
			t.FailNow()
		}
		resultFiles = append(resultFiles, gotFiles)
		fd.Close()
	}
	assert.Equal(t, resultFiles, expectedFiles, "Extracted filelists should match expected.")
}

/*func TestUnBzip2(t *testing.T) {
	resultFiles := make([][]string, 0)

	for index, filename := range targetFiles {
		fd := getFileDesc(t, filename)
		newFiles := unBzip2(fd)
		resultFiles[index] = newFiles

	}
}
*/
