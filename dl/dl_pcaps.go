// Package dl downloads all files to a temporary filesystem
package dl

import (
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
)

// FetchFile will get the filename from cache or download it
func FetchFile(url string) string {
	filepath := getFilepathFromURL(url)
	_, fileDNE := os.Stat(filepath)
	if fileDNE != nil {
		downloadFile(url, filepath)
	}
	return filepath
}

// getFilepathFromURL does just that
func getFilepathFromURL(url string) string {
	fileRe := regexp.MustCompile(`[^=\\\/\|\?\*:'"<>]+$`)
	filename := fileRe.FindString(url)
	thisDir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	return thisDir + "/.cache/" + filename
}

// downloadFile : Download the file given the link
func downloadFile(url string, filepath string) {
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.Fatal(err)
	}
}
