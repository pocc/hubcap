// +build all

package dl

import (
	"os"
	"reflect"
	"testing"

	"github.com/mholt/archiver"
)

func TestUnarchivePcaps(t *testing.T) {
	type args struct {
		f string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{"Non-archive should fail", args{".gitignore"}, nil, true},
		{"Actual archive should return with filenames", args{"../test/files/empty.tar.gz"}, []string{"empty", "empty2"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnarchivePcaps(tt.args.f)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnarchivePcaps() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnarchivePcaps() = %v, want %v", got, tt.want)
			}
		})
	}
	// Recreate archive for tests. Note that empty.tar.gz is just 2 touched empty files
	archiver.Archive([]string{"../test/files/empty/empty", "../test/files/empty/empty2"}, "../test/files/empty.tar.gz")
	err := os.RemoveAll("../test/files/empty")
	if err != nil {
		t.Error("Error deleting test directory ../test/files/empty\n")
	}
}

func TestStripArchiveExt(t *testing.T) {
	type args struct {
		fPath string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{".tar", args{"ws_w-I.bz2"}, "ws_w-I"},
		{".bz2", args{"ws_w-I.pcap.tgz"}, "ws_w-I"},
		{".ntar.gz", args{"ws_w-I.ntar.gz"}, "ws_w-I"},
		{".tar.gz", args{"ws_w-I.tar.gz"}, "ws_w-I"},
		{".tgz", args{"ws_w-I.pcap.tgz"}, "ws_w-I"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripArchiveExt(tt.args.fPath); got != tt.want {
				t.Errorf("StripArchiveExt() = %v, want %v", got, tt.want)
			}
		})
	}
}
