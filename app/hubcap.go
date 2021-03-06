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

	//flags "github.com/jessevdk/go-flags"
	"github.com/pocc/hubcap/dl"
	"github.com/pocc/hubcap/html"
	ds "github.com/pocc/hubcap/mutexmap"
	"github.com/pocc/hubcap/pcap"
)

/*
var opts struct {
	Iface         string         `value-name:"<source>" short:"i" description:"Interface to read."`
	Pcap          flags.Filename `value-name:"<file>" short:"r" description:"Pcap file to read."`
	DecodeAs      []string       `short:"d" description:"Specify dissection of layer type." value-name:"<layer type>==<selector>,<decode-as protocol>"`
	PrintIfaces   bool           `short:"D" optional:"true" optional-value:"true" description:"Print a list of the interfaces on which termshark can capture."`
	DisplayFilter string         `short:"Y" description:"Apply display filter." value-name:"<displaY filter>"`
	CaptureFilter string         `short:"f" description:"Apply capture filter." value-name:"<capture filter>"`
	PassThru      string         `long:"pass-thru" default:"auto" optional:"true" optional-value:"true" choice:"yes" choice:"no" choice:"auto" choice:"true" choice:"false" description:"Run tshark instead (auto => if stdout is not a tty)."`
	LogTty        string         `long:"log-tty" default:"false" optional:"true" optional-value:"true" choice:"yes" choice:"no" choice:"true" choice:"false" description:"Log to the terminal.."`
	Help          bool           `long:"help" short:"h" optional:"true" optional-value:"true" description:"Show this help message."`
	Version       bool           `long:"version" short:"v" optional:"true" optional-value:"true" description:"Show version information."`

	Args struct {
		FilterOrFile string `value-name:"<filter-or-file>" description:"Filter (capture for iface, display for pcap), or pcap file to read."`
	} `positional-args:"yes"`
}*/

var goroutineLimit = 1000

func main() {
	var wg sync.WaitGroup
	links := make(map[string]string)
	cacheLinks := make([]string, 0)
	resultJSON := ds.NewDS()
	cacheJSON := ds.NewDS()

	// Each fn adds gathered links to existing map
	// These calls are cheap, so always check if there are new PL/WS pcaps
	html.AddPacketlifeLinks(links)
	html.AddWiresharkSampleLinks(links)

	os.MkdirAll(".cache/packetlife", 0744)
	os.MkdirAll(".cache/wireshark_bugs", 0744)
	os.MkdirAll(".cache/wireshark_wiki", 0744)
	_, err := os.Stat(".cache/captures.json")
	if !os.IsNotExist(err) {
		loadCache(links, cacheJSON)
		for k, v := range cacheJSON.Cache {
			resultJSON.Set(k, &v)
			cacheLinks = append(cacheLinks, v.Sources...)
		}
	}
	html.GetWsBugzillaLinks(cacheLinks, links)

	for link, desc := range links {
		for runtime.NumGoroutine() > goroutineLimit {
			time.Sleep(time.Duration(10) * time.Millisecond)
		}
		wg.Add(1)
		go getPcapJSON(link, desc, resultJSON, &wg)
	}
	fmt.Printf("Waiting for %d goroutines to finish...\n", runtime.NumGoroutine())
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
		addedLinkCount := getLinkCount(resultJSON) - getLinkCount(cacheJSON)
		fmt.Printf("\n\033[92mINFO\033[0m Writing information about %d/%d new links & %d/%d new files to .cache/captures.json\n",
			addedLinkCount, getLinkCount(resultJSON), addedPcapCount, len(resultJSON.Cache))
		writeJSON(resultJSON.Cache)
	} else {
		fmt.Println("\n\033[92mINFO\033[0m Skipping write: There are no new pcaps to add to captures.json")
	}
}

func getLinkCount(cache *ds.DataStore) int {
	count := 0
	for _, v := range cache.Cache {
		count += len(v.Sources)
	}
	return count
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
	fmt.Printf("\033[92mINFO\033[0m Loading %d links and %d unique files from cache\n", initalCount-len(allLinks), len(cacheJSON.Cache))
}

func getPcapJSON(link string, desc string, result *ds.DataStore, wg *sync.WaitGroup) {
	if desc == "Authorization Required" {
		newPi := ds.PcapInfo{Sources: []string{link}, Description: "Bugzilla does not permit access for this file."}
		result.Set("->Error:AuthorizationRequired", &newPi)
		wg.Done()
		return
	}

	pi := ds.PcapInfo{Sources: []string{link}, Description: desc}
	var dlErr error
	pi.Filename, dlErr = dl.FetchFile(link)
	if dlErr == nil {
		archiveFolder := dl.StripArchiveExt(pi.Filename)
		isArchive := archiveFolder != pi.Filename
		if isArchive {
			getArchiveInfo(archiveFolder, &pi, result)
		} else {
			getPcapInfo(&pi, result) // No reason to be concurrent here
		}
	} else {
		fmt.Println(twoLines(dlErr))
		switch {
		case strings.Contains(dlErr.Error(), "non-pcap"):
			newPi := ds.PcapInfo{Sources: []string{link}, Description: "Files whose URL have a non-pcap file extension."}
			result.Set("->Error:NotAPcap", &newPi)
		case strings.Contains(dlErr.Error(), "Invalid Attachment ID"):
			newPi := ds.PcapInfo{Sources: []string{link}, Description: "This link is to a non-existant attachment in the wireshark bug database."}
			result.Set("->Error:InvalidAttachment", &newPi)
		}
	}
	wg.Done()
}

func getArchiveInfo(archiveFolder string, pi *ds.PcapInfo, result *ds.DataStore) {
	var files []string
	var err error
	var wg sync.WaitGroup
	archiveHasPcaps := false
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
			// Each pcap should have separate PcapInfo
			newPi := pi
			for runtime.NumGoroutine() > goroutineLimit {
				time.Sleep(time.Duration(10) * time.Millisecond)
			}
			wg.Add(1)
			go func(pi *ds.PcapInfo, result *ds.DataStore) {
				getPcapInfo(pi, result)
				fd, _ := os.Stat(pi.Filename)
				if fd != nil { // If it still exists, it will have been a pcap
					archiveHasPcaps = true
				}
				wg.Done()
			}(newPi, result)
		}
	}
	wg.Wait()
	if !archiveHasPcaps {
		fmt.Println("\033[92mINFO\033[0m Deleting archive folder without pcaps:", archiveFolder)
		delErr := os.RemoveAll(archiveFolder)
		if delErr != nil {
			fmt.Println("Problem with deleting archive without pcaps:", delErr)
		}
		newPi := ds.PcapInfo{Sources: pi.Sources, Description: "Captype reports this file as having a filetype of \"unknown\"."}
		result.Set("->Error:CaptypeUnknown", &newPi)
	}
}

func getPcapInfo(pi *ds.PcapInfo, result *ds.DataStore) {
	relFileName := ".cache/" + strings.SplitN(pi.Filename, ".cache/", 2)[1]
	var err error
	err = pcap.IsPcap(pi.Filename)
	if err == nil {
		// TODO fix should be a command line option and available as an option
		pi.Capinfos, err = pcap.GetCapinfos(pi.Filename, false)
		pi.Protocols, pi.Ports, err = pcap.GetTsharkJSON(pi.Filename)
		if err != nil {
			fmt.Println(err.Error())
			pi.ErrorStr = err.Error()
		}
		// Remove folder heirarchy
		pi.Filename = relFileName
		// Capinfos filename is redundant so remove it
		// Primary key of JSON should be SHA256 of pcap if possible
		fileHash := fmt.Sprintf("%s", pi.Capinfos["SHA256"])
		result.Set(fileHash, pi)
		result.DeleteFilename(fileHash, pi)
	} else {
		fmt.Println(twoLines(err))
		fmt.Println("\033[92mINFO\033[0m Deleting unused", pi.Filename)
		// If file is not a pcap, make a note of the link and delete it
		os.Remove(pi.Filename)
		newPi := ds.PcapInfo{Sources: pi.Sources, Description: "Captype reports this file as having a filetype of \"unknown\"."}
		result.Set("->Error:CaptypeUnknown", &newPi)
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
	if len(line) == 0 {
		return fmt.Errorf("")
	}
	if line[len(line)-1] == '\n' { // remove newline at end
		line = line[:len(line)-1]
	}
	if len(line) > 1000 {
		line = line[:1000]
	}
	return fmt.Errorf("%s", line)
}

// writeJSON writes all data to a `captures.json` file.
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

// writeHTML takes an HTML template and writes to a `captures.html` file.
func writeHTML() {}
