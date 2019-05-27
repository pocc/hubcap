// Package dl downloads all files to a temporary filesystem
package dl

import (
	"os"
	"testing"
)

var wiresharkBase = "https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target="
var testFile = "homeplug_request_parameters_and_statistics.pcap"

func TestFetchFile(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Not able to determine current directory")
	}
	target := dir[:len(dir)-3] + "/.cache/ws_" + testFile
	type args struct {
		url string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// Test actual download is handled by df_file_test.go
		{"Test fetch from cache", args{wiresharkBase + testFile}, target, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FetchFile(tt.args.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("FetchFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("FetchFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getFilepathFromURL(t *testing.T) {
	thisDir, err := os.Getwd()
	if err != nil {
		t.Error("Cannot get current dir. Error:", err)
	}
	baseFileStr := thisDir[:len(thisDir)-3] + "/.cache/"

	type args struct {
		url string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"Typical pcap", args{wiresharkBase + testFile}, baseFileStr + "ws_" + testFile, false},
		{"Archive", args{wiresharkBase + "iwarp_connect.tar.gz"}, baseFileStr + "ws_iwarp_connect", false},
		{"Bad URL", args{""}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getFilepathFromURL(tt.args.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("getFilepathFromURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getFilepathFromURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
