// Package dl downloads all files to a temporary filesystem
package dl

import (
	"log"
	"os"
	"regexp"
	"strings"
)

// FetchFile will get the filename from cache or download it
func FetchFile(url string) (string, error) {
	fPath := getFilepathFromURL(url)
	fileFd, _ := os.Stat(fPath)
	pcapExists := fileFd != nil
	if !pcapExists {
		if fetchErr := downloadFile(url, fPath, 0); fetchErr != nil {
			return fPath, fetchErr
		}
	}
	return fPath, nil
}

// GetFilepathFromURL returns the expected full path of a downloaded file based on a url.
// If it is an archive, it returns the full unarchived folder path.
func getFilepathFromURL(url string) string {
	fileRe := regexp.MustCompile(`[^=\\\/\|\?\*:'"<>]+$`) // exclude symbols we don't care about
	filename := fileRe.FindString(url)
	sanitizedFilename := StripArchiveExt(strings.Replace(filename, " ", "_", -1))
	var source string
	if strings.Contains(url, "wireshark.org") {
		source = "ws"
	} else if strings.Contains(url, "packetlife.net") {
		source = "pl"
	}
	thisDir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	filepath := thisDir + "/.cache/" + source + "_" + sanitizedFilename
	return filepath
}
