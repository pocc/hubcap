// +build slow

// Package dl downloads all files to a temporary filesystem
package dl

import (
	"os"
	"testing"
)

// Test downloading a file that should succeed and test downloading a file from a url that does not exist
func Test_downloadFile(t *testing.T) {
	wiresharkFile := "https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=a.pcap"
	type args struct {
		url      string
		filepath string
		retrySec int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// Download file is tested by FetchFile lacking the file in cache
		{"Non existant file", args{wiresharkFile, "a.pcap", 0}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := downloadFile(tt.args.url, tt.args.filepath, tt.args.retrySec); (err != nil) != tt.wantErr {
				t.Errorf("downloadFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	err := os.Remove(testFile)
	if err != nil {
		t.Errorf("Problem deleting test file %s", testFile)
	}
}
