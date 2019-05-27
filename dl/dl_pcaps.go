// Package dl downloads all files to a temporary filesystem
package dl

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
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

// GetFilepathFromURL does just that
func getFilepathFromURL(url string) string {
	fileRe := regexp.MustCompile(`[^=\\\/\|\?\*:'"<>]+$`) // exclude symbols we don't care about
	filename := fileRe.FindString(url)
	sanitizedFilename := strings.Replace(filename, " ", "_", -1)
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

// downloadFile : Download the file given the link
func downloadFile(url string, filepath string, retrySec int) error {
	// Create the file
	time.Sleep(time.Duration(retrySec) * time.Second)
	var contextStr string

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n\033[92mINFO\033[0m", filepath, "not found. Downloading", url)
	switch resp.StatusCode {
	case 302:
		contextStr = "Redirection not implemented"
	case 303:
		contextStr = "Redirection not implemented"
	case 404:
		contextStr = "Resource not found"
	case 500: // Server error / file doesn't exist
		contextStr = "Server error"
	case 525: // 525 is cloudflare saying slow down
		if retrySec < 32 {
			retrySec := 2*retrySec + 1 // ~ f(n) = 2^(n+1)-1
			fmt.Println("Download from", url, "failed with code", resp.StatusCode,
				"\nRetrying after", retrySec, "seconds...")
			downloadFile(url, filepath, retrySec)
		} else {
			contextStr = "Have retried 5 times and will not retry."
		}
	case 200:
		// Write the body to file
		fmt.Println("\033[92mINFO\033[0m Saving to", filepath)
		out, err := os.Create(filepath)
		if err != nil {
			log.Fatal(err)
		}
		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		resp.Body.Close()
		return nil
	default:
		log.Fatal("Received unexpected code", resp.StatusCode,
			"from", url, ". Please create an issue!")
	}
	return fmt.Errorf("\033[93mWARN\033[0m "+
		"Download of %s failed with code %d: %s. Skipping...",
		url, resp.StatusCode, contextStr)
}
