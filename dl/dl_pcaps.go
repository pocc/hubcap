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
func FetchFile(url string) string {
	filepath := getFilepathFromURL(url)
	_, fileDNE := os.Stat(filepath)
	if fileDNE != nil {
		downloadFile(url, filepath, 0)
	}
	return filepath
}

// getFilepathFromURL does just that
func getFilepathFromURL(url string) string {
	fileRe := regexp.MustCompile(`[^=\\\/\|\?\*:'"<>]+$`)
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
func downloadFile(url string, filepath string, retrySec int) {
	// Create the file
	time.Sleep(time.Duration(retrySec) * time.Second)

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Downloading", url)
	switch resp.StatusCode {
	case 302:
		log.Fatal("Received 302 code. Redirection not implemented")
	case 303:
		log.Fatal("Received 303 code. Redirection not implemented")
	case 404:
		fmt.Println("ERROR: Download failed to", url, "with 404 resource not found")
	case 500: // Server error / file doesn't exist
		fmt.Println("ERROR: Download failed to", url, "with server error 500")
	case 525: // 525 is cloudflare saying slow down
		if retrySec < 32 {
			retrySec := 2*retrySec + 1 // ~ f(n) = 2^(n+1)-1
			fmt.Println("Download from", url, "failed with code", resp.StatusCode,
				"\nRetrying after", retrySec, "seconds...")
			downloadFile(url, filepath, retrySec)
		} else {
			fmt.Println("Download from", url, "failed with code", resp.StatusCode,
				"\nHave retried 5 times and will not retry.")
		}
	case 200:
		// Write the body to file
		fmt.Println("Saving to", filepath)
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
	default:
		log.Fatal("Received unexpected code", resp.StatusCode,
			"from", url, ". Please create an issue!")
	}
}
