// Package dl downloads all files to a temporary filesystem
package dl

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func downloadFile(url string, filepath string, retrySec int) error {
	// Create the file
	time.Sleep(time.Duration(retrySec) * time.Second)
	var contextStr string

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
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
		if retrySec < 64 {
			retrySec = 2*retrySec + 1 // ~ f(n) = 2^(n+1)-1
			fmt.Println("\033[93mWARN\033[0m Download from", url, "failed with code", resp.StatusCode,
				"\nRetrying after", retrySec, "seconds...")
			return downloadFile(url, filepath, retrySec)
		}
		contextStr = "Have retried 5 times and will not retry."
	case 200:
		// Write the body to file
		fmt.Println("\033[92mINFO\033[0m Saving to", filepath)
		out, err := os.Create(filepath)
		if err != nil {
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	default:
		return fmt.Errorf("Received unexpected code %d from %s. "+
			"Please create an issue", resp.StatusCode, url)
	}
	return fmt.Errorf("\033[91mERROR\033[0m "+
		"Download of %s failed with code %d: %s. Skipping...",
		url, resp.StatusCode, contextStr)
}
