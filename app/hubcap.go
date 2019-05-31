// hubcap.go : Utility to download online pcaps to a temporary folder
/*
 * Assumptions:
 *     - The link for a file will continue to point to the same file.
 *       This is used to cache pcap results so expensive downloads
 *       happen as few times as possible.
 */
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pocc/hubcap/dl"
	"github.com/pocc/hubcap/html"
	"github.com/pocc/hubcap/mutexmap"
	"github.com/pocc/hubcap/pcap"
)

// PcapInfo stores info about an individual pcap
type PcapInfo struct {
	Filename    string
	Source      string
	Description string
	Capinfos    map[string]interface{}
	Protocols   []string
	Ports       map[string][]int
	Error       error
}

func main() {
	var wg sync.WaitGroup
	resultJSON := mutexmap.NewDS()

	links := html.GetAllLinks()
	wg.Add(len(links))
	for link, desc := range links {
		// Limit to 100 goroutines at a time
		for runtime.NumGoroutine() > 100 {
			time.Sleep(time.Duration(10) * time.Millisecond)
		}
		go getPcapJSON(link, desc, resultJSON, &wg)
	}
	fmt.Println("Waiting for all goroutines to finish...")
	wg.Wait() // All goroutines MUST complete before writing results
	writeJSON(resultJSON.Cache)
}

func getPcapJSON(link string, desc string, result *mutexmap.DataStore, wg *sync.WaitGroup) {
	pi := PcapInfo{Source: link, Description: desc}
	pi.Filename, pi.Error = dl.FetchFile(link)
	if pi.Error == nil {
		archiveFolder := dl.StripArchiveExt(pi.Filename)
		isArchive := archiveFolder != pi.Filename
		if isArchive {
			getArchiveInfo(archiveFolder, &pi, result, wg)
		} else {
			getPcapInfo(&pi, result, wg) // No reason to be concurrent here
		}
	} else {
		fmt.Println(twoLines(pi.Error))
		wg.Done()
	}
}

func getArchiveInfo(archiveFolder string, pi *PcapInfo, result *mutexmap.DataStore, wg *sync.WaitGroup) {
	var files []string
	_, fileErr := os.Stat(archiveFolder)
	isArchiveExtracted := !os.IsNotExist(fileErr)
	if isArchiveExtracted {
		files, pi.Error = dl.WalkArchive(archiveFolder)
	} else {
		files, pi.Error = dl.UnarchivePcaps(pi.Filename)
	}
	if pi.Error != nil {
		fmt.Println(twoLines(pi.Error))
	} else {
		for _, extractedName := range files {
			pi.Filename = extractedName
			wg.Add(1)
			// Each pcap should have separate PcapInfo
			newPi := pi
			go getPcapInfo(newPi, result, wg)
		}
	}
	wg.Done()
}

func getPcapInfo(pi *PcapInfo, result *mutexmap.DataStore, wg *sync.WaitGroup) {
	pi.Error = pcap.IsPcap(pi.Filename)
	if pi.Error == nil {
		// TODO fix should be a command line option and available as an option.
		pi.Capinfos, pi.Error = pcap.GetCapinfos(pi.Filename, false)
		if pi.Error == nil {
			pi.Protocols, pi.Ports, pi.Error = pcap.GetTsharkJSON(pi.Filename)
			// Remove folder heirarchy
			pi.Filename = ".cache/" + strings.SplitN(pi.Filename, ".cache/", 2)[1]
			// Capinfos filename is redundant so remove it
			delete(pi.Capinfos, "FileName")
			// Primary key of JSON should be SHA256 of pcap if possible
			fileHash := fmt.Sprintf("%s", pi.Capinfos["SHA256"])
			result.Set(fileHash, pi)
		}
	}
	if pi.Error != nil {
		fmt.Println(twoLines(pi.Error))
	}
	wg.Done()
}

// Gets the first 1000 chars or two lines of error
func twoLines(err error) error {
	errBuf := bytes.NewBufferString(err.Error())
	line, _ := errBuf.ReadBytes('\n')
	if errBuf.Len() > 0 {
		line2, _ := errBuf.ReadBytes('\n')
		line = append(line, line2...)
	}
	if line[len(line)-1] == '\n' { // remove newline at end
		line = line[:len(line)-1]
	}
	if len(line) > 1000 {
		line = line[:1000]
	}
	return fmt.Errorf("%s", line)
}

// Warn and end the current goroutine
func endGC(url string, result *mutexmap.DataStore, wg *sync.WaitGroup, values interface{}) {
	result.Set(url, values)
	wg.Done()
}

func writeJSON(resultJSON map[string]interface{}) {
	jsonBytes, err := json.MarshalIndent(resultJSON, "", "  ")
	if err != nil {
		fmt.Println("Error in converting JSON:", err)
		fmt.Println("JSON:", resultJSON)
	}
	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("Could not read current directory", err)
		os.Exit(1)
	}
	jsonPath := dir + "/.cache/captures.json"
	err = ioutil.WriteFile(jsonPath, jsonBytes, 0644)
	if err != nil {
		fmt.Println("Error in writing JSON to file:", err)
		fmt.Println("Filepath:", jsonPath)
	}
}
