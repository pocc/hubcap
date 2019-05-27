// Package dl downloads all files to a temporary filesystem
package dl

import (
	"os"
	"testing"
)

var wiresharkBase = "https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target="
var testFile = "homeplug_request_parameters_and_statistics.pcap"

func TestFetchFile(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
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
	baseFileStr := thisDir + "/.cache/ws_"

	type args struct {
		url string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"Typical pcap", args{wiresharkBase + testFile}, baseFileStr + testFile},
		{"Archive", args{wiresharkBase + "iwarp_connect.tar.gz"}, baseFileStr + "iwarp_connect"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getFilepathFromURL(tt.args.url); got != tt.want {
				t.Errorf("getFilepathFromURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
