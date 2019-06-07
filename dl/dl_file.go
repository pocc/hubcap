// Package dl downloads all files to a temporary filesystem
package dl

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"
)

func downloadFile(url string, filepath string, retryMillisec int) error {
	// Create the file
	time.Sleep(time.Duration(retryMillisec) * time.Second)
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
		if retryMillisec < 60000 {
			rand.New(rand.NewSource(time.Now().UnixNano()))
			randNum := rand.Int() % 5000
			retryMillisec = retryMillisec + randNum
			time.Sleep(time.Duration(retryMillisec) * time.Millisecond)
			fmt.Println("\033[93mWARN\033[0m Download from", url, "failed with code", resp.StatusCode,
				"\nRetrying after", retryMillisec, "milliseconds...")
			return downloadFile(url, filepath, retryMillisec)
		}
		contextStr = "Backoff timer is at " + strconv.Itoa(retryMillisec) + " milliseconds and will not retry."
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
