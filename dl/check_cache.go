// Package dl downloads all files to a temporary filesystem
package dl

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// FetchFile will get the filename from cache or download it
func FetchFile(urlStr string) (string, error) {
	fPath, err := getFilepathFromURL(urlStr)
	if err != nil {
		return "", fmt.Errorf("Invalid url %s passed in", urlStr)
	}
	fileFd, _ := os.Stat(fPath)
	pcapExists := fileFd != nil
	if !pcapExists {
		fmt.Println("\n\033[92mINFO\033[0m", fPath, "not found in cache. Downloading", urlStr)
		if fetchErr := downloadFile(urlStr, fPath, 0); fetchErr != nil {
			return fPath, fetchErr
		}
	}
	return fPath, nil
}

// GetFilepathFromURL returns the expected full path of a downloaded file based on a url.
// If it is an archive, it returns the full unarchived folder path (e.g. minus ``.tgz`).
func getFilepathFromURL(urlStr string) (string, error) {
	if _, err := url.ParseRequestURI(urlStr); err != nil {
		return "", err
	}
	thisDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// hubcap is required to be parent (also required for testing)
	for strings.HasSuffix(filepath.Dir(thisDir), "hubcap") {
		thisDir = filepath.Dir(thisDir)
	}
	fileRe := regexp.MustCompile(`[^=\\\/\|\?\*:'"<>]+$`) // exclude symbols we don't care about
	filename := fileRe.FindString(urlStr)
	sanitizedFilename := StripArchiveExt(strings.Replace(filename, " ", "_", -1))
	var source string
	if strings.Contains(urlStr, "wireshark.org") {
		source = "ws"
	} else if strings.Contains(urlStr, "packetlife.net") {
		source = "pl"
	}
	filepath := thisDir + "/.cache/" + source + "_" + sanitizedFilename
	return filepath, nil
}
