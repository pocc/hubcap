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

	"github.com/mholt/archiver"
)

// FetchFile will get the filename from cache or download it
func FetchFile(url string) (string, error) {
	fPath := getFilepathFromURL(url)
	fileFd, _ := os.Stat(fPath)
	pcapExists := fileFd != nil
	/*
		if isArchive {
			extractedArchiveFd, _ := os.Stat(archiveName)
			extractedArchiveExists := (extractedArchiveFd != nil)
			if !extractedArchiveExists {
				_, archiveErr := UnarchivePcaps(fPath)
				if archiveErr != nil {
					return fPath, false, archiveErr
				}
			}
			fPath = stripArchiveExt(fPath)
	} else */
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

// UnarchivePcaps will unarchive pcaps from archive f to a folder of the same name before removing f
func UnarchivePcaps(f string) ([]string, error) {
	fmt.Printf("\033[92mINFO\033[0m Unarchiving %s\n", f)
	folderName := StripArchiveExt(f)
	osErr := os.Mkdir(folderName, 0644)
	fmt.Printf("\033[92mINFO\033[0m Creating folder %s\n", folderName)
	if osErr != nil {
		return nil, fmt.Errorf("\033[91mERROR\033[0m Problem creating folder `%s` for archive contents.\nError: %s", folderName, osErr)
	}
	archiveErr := archiver.Unarchive(f, folderName)
	if archiveErr != nil {
		return nil, fmt.Errorf("\033[93mWARN\033[0m Unrecognized archive %s.\nError:%s", f, archiveErr)
	}
	delErr := os.Remove(f)
	if delErr != nil {
		return nil, fmt.Errorf("\033[91mERROR\033[0m Problem deleting archive `%s` (Do you have permissions?).\nERROR: %s", f, delErr)
	}
	return []string{""}, nil
}

// StripArchiveExt removes archive extensions `.tar.gz` and `.bz2` or returns filename otherwise
func StripArchiveExt(fPath string) string {
	archiveRe := regexp.MustCompile(`(.*?)(?:\.p?cap)?(?:\.n?tar\.gz|bz2|zip|xz|lzma|rar|tbz2|tgz|ntar|tar)$`)
	archiveMatches := archiveRe.FindStringSubmatch(fPath)
	if len(archiveMatches) == 2 {
		return archiveMatches[1]
	}
	return fPath
}
