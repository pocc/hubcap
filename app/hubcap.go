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
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pocc/hubcap/dl"
	"github.com/pocc/hubcap/html"
	ds "github.com/pocc/hubcap/mutexmap"
	"github.com/pocc/hubcap/pcap"
)

func main() {
	var wg sync.WaitGroup
	goroutineLimit := 500
	resultJSON := ds.NewDS()
	cacheJSON := ds.NewDS()

	links := html.GetAllLinks()
	_, err := os.Stat(".cache")
	if os.IsNotExist(err) {
		fmt.Println("Creating cache folders...")
		os.MkdirAll(".cache/packetlife", 0744)
		os.MkdirAll(".cache/wireshark", 0744)
	} else { // If .cache/ folder doesn't exist, then .cache/captures.json won't either.
		loadCache(links, cacheJSON)
		for k, v := range cacheJSON.Cache {
			resultJSON.Set(k, &v)
		}
	}
	wg.Add(len(links))
	for link, desc := range links {
		if goroutineLimit != 0 {
			for runtime.NumGoroutine() > goroutineLimit {
				time.Sleep(time.Duration(10) * time.Millisecond)
			}
		}
		go getPcapJSON(link, desc, resultJSON, &wg)
	}
	fmt.Printf("Almost done. Waiting for %d goroutines to finish...\n", runtime.NumGoroutine())
	wg.Wait() // All goroutines MUST complete before writing results
	resultAndCacheDiffer := false
	for k, v := range resultJSON.Cache {
		if !reflect.DeepEqual(cacheJSON.Cache[k], v) {
			resultAndCacheDiffer = true
			break
		}
	}
	if resultAndCacheDiffer {
		addedPcapCount := len(resultJSON.Cache) - len(cacheJSON.Cache)
		fmt.Printf("\n\033[92mINFO\033[0m Writing information about %d new files (%d total) to .cache/captures.json\n", addedPcapCount, len(resultJSON.Cache))
		writeJSON(resultJSON.Cache)
	} else {
		fmt.Println("\n\033[92mINFO\033[0m Skipping write: There are no new pcaps to add to captures.json")
	}
}

// Use the cache to skip analyzing pcaps that we have data on
func loadCache(allLinks map[string]string, cacheJSON *ds.DataStore) {
	initalCount := len(allLinks)
	fmt.Println("\033[92mINFO\033[0m Using cached data from .cache/captures.json")
	capturesFD, err := os.Open(".cache/captures.json")
	if err != nil {
		fmt.Println("Problem opening captures.json. Not using data cache will take longer.")
		return
	}

	var captureStruct map[string]ds.PcapInfo
	captureText, ioErr := ioutil.ReadAll(capturesFD)
	if ioErr != nil {
		fmt.Println("Problem reading captures cache. Error:", ioErr)
		os.Exit(1)
	}
	json.Unmarshal(captureText, &captureStruct)
	for filehash, capture := range captureStruct {
		cacheJSON.Set(filehash, &capture)
		for _, link := range capture.Sources {
			delete(allLinks, link)
		}
	}
	fmt.Printf("\033[92mINFO\033[0m Loading %d files from cache\n", len(cacheJSON.Cache))
	fmt.Printf("\033[92mINFO\033[0m Skipping %d files due to cache\n", initalCount-len(allLinks))
}

func getPcapJSON(link string, desc string, result *ds.DataStore, wg *sync.WaitGroup) {
	pi := ds.PcapInfo{Sources: []string{link}, Description: desc}
	var dlErr error
	pi.Filename, dlErr = dl.FetchFile(link)
	if dlErr == nil {
		archiveFolder := dl.StripArchiveExt(pi.Filename)
		isArchive := archiveFolder != pi.Filename
		if isArchive {
			getArchiveInfo(archiveFolder, &pi, result, wg)
		} else {
			getPcapInfo(&pi, result, wg) // No reason to be concurrent here
		}
	} else {
		fmt.Println(twoLines(dlErr))
		if strings.Contains(dlErr.Error(), "non-pcap") {
			newPi := ds.PcapInfo{Sources: []string{link}, Description: "Files whose URL has a non-pcap file extension or that captype reports as \"unknown\" filetype."}
			result.Set("->Error:NotAPcap", &newPi)
		}
	}
	wg.Done()
}

func getArchiveInfo(archiveFolder string, pi *ds.PcapInfo, result *ds.DataStore, wg *sync.WaitGroup) {
	var files []string
	var err error
	_, fileErr := os.Stat(archiveFolder)
	isArchiveExtracted := !os.IsNotExist(fileErr)
	if isArchiveExtracted {
		files, err = dl.WalkArchive(archiveFolder)
	} else {
		files, err = dl.UnarchivePcaps(pi.Filename)
	}
	if err != nil {
		pi.ErrorStr = twoLines(err).Error()
		fmt.Println(twoLines(err))
	} else {
		for _, extractedName := range files {
			pi.Filename = extractedName
			wg.Add(1)
			// Each pcap should have separate PcapInfo
			newPi := pi
			go getPcapInfo(newPi, result, wg)
			wg.Done()
		}
	}
}

func getPcapInfo(pi *ds.PcapInfo, result *ds.DataStore, wg *sync.WaitGroup) {
	relFileName := ".cache/" + strings.SplitN(pi.Filename, ".cache/", 2)[1]
	var err error
	err = pcap.IsPcap(pi.Filename)
	if err == nil {
		// TODO fix should be a command line option and available as an option
		pi.Capinfos, err = pcap.GetCapinfos(pi.Filename, false)
		if err == nil {
			pi.Protocols, pi.Ports, err = pcap.GetTsharkJSON(pi.Filename)
			// Remove folder heirarchy
			pi.Filename = relFileName
			// Capinfos filename is redundant so remove it
			delete(pi.Capinfos, "FileName")
			// Primary key of JSON should be SHA256 of pcap if possible
			fileHash := fmt.Sprintf("%s", pi.Capinfos["SHA256"])
			result.Set(fileHash, pi)
		}
		if err != nil {
			pi.ErrorStr = twoLines(err).Error()
			fmt.Println(twoLines(err))
			pi.Filename = relFileName
			fileHash := pcap.GetSHA256(pi.Filename)
			result.Set(fileHash, pi)
		}
	} else {
		// If file is not a pcap, make a note of the link, but no more
		result.Set("->Error:NotAPcap", &ds.PcapInfo{Sources: pi.Sources})
	}
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

func writeJSON(resultJSON map[string]ds.PcapInfo) {
	// UTF escape codes require extra attention per https://stackoverflow.com/questions/24656624
	jsonBuf := new(bytes.Buffer)
	enc := json.NewEncoder(jsonBuf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(resultJSON)
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
	err = ioutil.WriteFile(jsonPath, jsonBuf.Bytes(), 0644)
	if err != nil {
		fmt.Println("Error in writing JSON to file:", err)
		fmt.Println("Filepath:", jsonPath)
	}
}
