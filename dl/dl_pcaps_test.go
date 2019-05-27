// Package dl downloads all files to a temporary filesystem
package dl

import "testing"

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
	type args struct {
		url string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getFilepathFromURL(tt.args.url); got != tt.want {
				t.Errorf("getFilepathFromURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_downloadFile(t *testing.T) {
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
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := downloadFile(tt.args.url, tt.args.filepath, tt.args.retrySec); (err != nil) != tt.wantErr {
				t.Errorf("downloadFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
