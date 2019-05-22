package pcap

import (
	"github.com/google/go-cmp/cmp"
	"os"
	"testing"
)

// getFileDesc gets the file descriptor of a file.
func getFileDesc(t *testing.T, target string) *os.File {
	fd, err := os.Open(target)
	if err != nil {
		t.Log("File not found:", target, ". Error:", err)
		t.FailNow()
	}
	return fd
}

var targetFiles = []string{
	"../.cache/ws_iwarp_connect.tar.gz",
	"../.cache/ws_starteam_sample.tgz",
	"../.cache/ws_rtmpt.pcap.bz2",
	"../.cache/ws_mDNS1.zip",
}

// TestUncompress tests .tar.gz, .tgz, .bz2, .zip files
// Archives are extracted and their files compared to expected values
func TestUncompress(t *testing.T) {
	resultFiles := make([]map[string][]byte, 0)
	destDir := os.TempDir()
	var expectedFiles = []map[string][]byte{
		{
			"iwarp_connect/C00_M00":        []byte("\xc4\xe6\x6f\x8a\xba\xc7\xb0\xe3\x6e\x89\x72\xa1\x9e\x0a\xf9\xec\x89\x27\x4b\x3b\xa3\xae\x78\x05\x81\xc0\xc0\x42\x0f\xcd\x01\x1f"),
			"iwarp_connect/C00_M00_reject": []byte("\xca\xa0\x83\x92\x4e\xc5\x5b\x7c\x6e\xcc\x3d\x73\x07\x98\x6b\x38\x23\x21\xa4\x3c\x5f\x98\x9e\x94\x17\x3e\x93\x10\x77\x0d\xf9\x29"),
			"iwarp_connect/C00_M11":        []byte("\x69\x39\xa4\x59\x8e\x31\xc9\xf4\x95\x98\xdf\x42\x56\x0a\xac\xe1\xf1\xe5\xf3\xe4\x19\xa8\xe5\xe9\xbd\x63\xee\x99\x5a\x70\x82\xfa"),
			"iwarp_connect/C11_M00":        []byte("\x3c\xcd\x15\x56\x90\xd4\x54\xd0\x1f\xa5\xc1\x6a\x29\xae\x17\x3d\x40\x91\x45\x09\x73\x8f\x97\xd9\xbc\xd8\x6c\xe1\x6c\x8a\xc1\x11"),
			"iwarp_connect/C11_M11":        []byte("\x07\xbf\xc3\x9f\xc4\x80\xd6\xb5\x75\x74\x0e\xfd\x01\x58\x80\xa5\xe5\xcd\x1e\xe2\x07\x51\xd6\x7a\x41\x5d\x69\x48\xef\xae\xa6\x94"),
		},
		{"starteam_sample.cap": []byte("\x6f\x9c\x26\x3c\xd2\x0c\x0f\xeb\x93\xe1\xba\xaa\xc7\xd2\xbc\x68\x0d\x62\xb5\x26\xbc\x03\xcc\xce\xc4\xc0\xff\xf6\xf3\x6d\x98\x39")},
		{"ws_rtmpt.pcap": nil},
		{
			"DAAP-mDNS.CAP": nil,
			"More-mDNS.cap": nil,
			"mDNS3.cap":     nil,
		},
	}
	for _, filename := range targetFiles {
		gotFiles, err := UnCompress(filename, destDir)
		if err != nil {
			t.Log("Uncompress failed for file:", filename, "\nError:", err)
			t.Fail()
		}
		resultFiles = append(resultFiles, gotFiles)
	}
	if len(resultFiles) < len(expectedFiles) {
		t.Log("Fewer results than expected. Actual:", len(resultFiles),
			"Expected:", len(expectedFiles))
		t.Fail()
	}
	for i := range expectedFiles {
		testSuccess := cmp.Equal(expectedFiles[i], resultFiles[i])
		if !testSuccess {
			for filename := range expectedFiles[i] {
				t.Logf("\nArchive's hashes differ for file %s:"+
					"\nExpected: %x\nActual: %x", filename,
					expectedFiles[i][filename],
					resultFiles[i][filename])
				t.Fail()
			}
		}
	}
}
