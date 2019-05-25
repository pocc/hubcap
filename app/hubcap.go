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
	"log"
	"os"
	"runtime"
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
	Link        string
	Description string
	Capinfos    map[string]interface{}
	Protocols   []string
	Ports       map[string][]int
	Error       error
}

// PI = PcapInfo shortened
type PI PcapInfo

func main() {
	var wg sync.WaitGroup
	var filename string

	resultJSON := mutexmap.NewDS()
	filenameCh := make(chan PI)
	archiveCh := make(chan PI)
	pcapCh := make(chan PI)
	jsonWriteCh := make(chan PI)

	links := html.GetAllLinks()
	for _, link := range links {
		// Limit to 100 goroutines at a time
		for runtime.NumGoroutine() > 100 {
			time.Sleep(time.Duration(10) * time.Millisecond)
		}
		wg.Add(1)
		/* Pipelining all data with channels
		 *
		 * Link -> Filename ------> IsPcap? -> Capinfos -> Write JSON
		 *              ⤷ Unarchive ⤴  ⤷-> tshark info -⤴
		 *
		 *     Skip to Write JSON if error as it should include partial data
		 */
		go getFilename(link, filenameCh, archiveCh, jsonWriteCh)
		select {
		case archive := <-archiveCh: // Unarchive and get info on each file inside
			go unArchive(archive, filenameCh, jsonWriteCh)
		case filename := <-filenameCh:
			go isPcap(filename, pcapCh, jsonWriteCh)
		case pcap := <-pcapCh:
			go getPcapInfo(pcap, jsonWriteCh)
		case jsonObj := <-jsonWriteCh:
			go resultJSON.Set(filename, jsonObj)
		}
		wg.Done()
	}
	wg.Wait() // All goroutines MUST complete before writing results
	close(pcapCh)
	writeJSON(resultJSON.Cache)
}

func getFilename(link html.LinkData, filenameCh chan PI, archiveCh chan PI, jsonWrite chan PI) {
	var pi = PI{Description: link.Description}
	var err error
	pi.Filename, err = dl.FetchFile(link.Link)
	archiveName := dl.StripArchiveExt(pi.Filename)
	switch {
	case err != nil:
		jsonWrite <- pi
	case archiveName != pi.Filename:
		pi.Filename = archiveName
		archiveCh <- pi
	default:
		filenameCh <- pi
	}
}

func unArchive(pi PI, filenameCh chan PI, jsonWrite chan PI) {
	files, err := dl.UnarchivePcaps(pi.Filename)
	if err != nil {
		pi.Error = err
		jsonWrite <- pi
	} else {
		for _, f := range files {
			pi.Filename = f
			filenameCh <- pi
		}
	}
}

func isPcap(pi PI, pcapCh chan PI, jsonWrite chan PI) {
	err := pcap.IsPcap(pi.Filename)
	if err != nil {
		pi.Error = err
		jsonWrite <- pi
	} else {
		pcapCh <- pi
	}
}

func getPcapInfo(pi PI, jsonWrite chan PI) {
	var err error
	pi.Capinfos, err = pcap.GetCapinfos(pi.Filename)
	if err != nil {
		pi.Error = err
	} else {
		pi.Protocols, pi.Ports, err = pcap.GetTsharkJSON(pi.Filename)
		if err != nil {
			pi.Error = err
		}
	}
	jsonWrite <- pi
}

// firstLine truncates an error to the first 160 chars
func firstLine(err error) error {
	errText := err.Error()
	errBuf := bytes.NewBufferString(errText)
	line, _ := errBuf.ReadBytes('\n')
	if line[len(line)-1] == '\n' { // remove newline at end
		line = line[:len(line)-1]
	}
	two80CharLines := 160
	truncateLength := two80CharLines
	if len(line) < truncateLength {
		truncateLength = len(line)
	} else {
		line = append(line, '.', '.') // If truncating, add an ellipsis
	}
	errLines := fmt.Errorf("%s", line[:truncateLength])
	fmt.Println(errLines)
	return errLines
}

func writeJSON(resultJSON map[string]interface{}) {
	jsonBytes, err := json.MarshalIndent(resultJSON, "", "  ")
	if err != nil {
		fmt.Println("Error in converting JSON:", err)
		fmt.Println("JSON:", resultJSON)
	}
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	jsonPath := dir + "/.cache/captures.json"
	err = ioutil.WriteFile(jsonPath, jsonBytes, 0644)
	if err != nil {
		fmt.Println("Error in writing JSON to file:", err)
		fmt.Println("Filepath:", jsonPath)
	}
}
