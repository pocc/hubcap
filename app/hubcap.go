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

var goroutineLimit = 100

func main() {
	var wg sync.WaitGroup
	resultJSON := ds.NewDS()
	cacheJSON := ds.NewDS()

	links := html.GetAllLinks()
	os.MkdirAll(".cache/packetlife", 0744)
	os.MkdirAll(".cache/wireshark_bugs", 0744)
	os.MkdirAll(".cache/wireshark_wiki", 0744)
	_, err := os.Stat(".cache/captures.json")
	if !os.IsNotExist(err) {
		loadCache(links, cacheJSON)
		for k, v := range cacheJSON.Cache {
			resultJSON.Set(k, &v)
		}
	}
	for link, desc := range links {
		for runtime.NumGoroutine() > goroutineLimit {
			time.Sleep(time.Duration(10) * time.Millisecond)
		}
		wg.Add(1)
		go getPcapJSON(link, desc, resultJSON, &wg)
	}
	for runtime.NumGoroutine() > 10 {
		fmt.Printf("Waiting for %d goroutines to finish...\n", runtime.NumGoroutine())
		time.Sleep(5 * time.Second)
	}
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
	fmt.Printf("\033[92mINFO\033[0m Loading %d links and %d unique files from cache\n", initalCount-len(allLinks), len(cacheJSON.Cache))
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
			// Each pcap should have separate PcapInfo
			newPi := pi
			for runtime.NumGoroutine() > goroutineLimit {
				time.Sleep(time.Duration(10) * time.Millisecond)
			}
			wg.Add(1)
			go func(pi *ds.PcapInfo, result *ds.DataStore) {
				getPcapInfo(pi, result)
				wg.Done()
			}(newPi, result)
		}
	}
}

func getPcapInfo(pi *ds.PcapInfo, result *ds.DataStore) {
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
		// If file is not a pcap, make a note of the link and delete it
		os.RemoveAll(pi.Filename)
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
