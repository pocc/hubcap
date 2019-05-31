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

// FetchFile will get the filename from cache or download it.
func FetchFile(urlStr string) (string, error) {
	fPath, err := getFilepathFromURL(urlStr)
	if err != nil {
		return "", fmt.Errorf("Invalid url %s passed in", urlStr)
	}
	// Using a blacklist because users are sloppy with how they name valid pcaps
	notPcapRe := regexp.MustCompile(`\.(?:doc|ext|log|json|mib|mp3|p10|pdf|pppd|trc|txt|txt.gz|xls|xlsx|xml)$`)
	if notPcapRe.FindString(fPath) != "" {
		return fPath, fmt.Errorf("\033[92mINFO\033[0m Skipping download of non-pcap file %s from %s", fPath, urlStr)
	}
	// If file path does not exist
	_, fileErr := os.Stat(fPath)
	if os.IsNotExist(fileErr) {
		fmt.Println("\033[92mINFO\033[0m", fPath, "not found in cache. Downloading", urlStr)
		fetchErr := downloadFile(urlStr, fPath, 0)
		if fetchErr != nil {
			return fPath, fetchErr
		}
	}
	return fPath, nil
}

// GetFilepathFromURL returns the expected full path of a downloaded file based on a url.
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
	// Unarchived pcaps are expected to be in to extracted folder, not in the archive
	sanitizedFilename := strings.Replace(strings.Replace(filename, " ", "_", -1), "ntar", "tar", -1)
	htmlEntitiesRe := regexp.MustCompile(`%[0-9A-F]{2}`)
	sanitizedFilename = string(htmlEntitiesRe.ReplaceAll([]byte(sanitizedFilename), []byte("_")))
	relativeDir := "/.cache/"
	var sourceSite string
	if strings.Contains(urlStr, "wireshark.org") {
		sourceSite = "ws"
	} else if strings.Contains(urlStr, "packetlife.net") {
		sourceSite = "pl"
	}
	fullFilename := thisDir + relativeDir + sourceSite + "_" + sanitizedFilename
	return fullFilename, nil
}
