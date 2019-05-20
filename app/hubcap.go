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
	mm "github.com/pocc/hubcap/mutexmap"
	"github.com/pocc/hubcap/pcap"
)

// PcapData stores info about an individual pcap
type PcapData struct {
	Description string
	Capinfos    map[string]interface{}
	Protocols   []string
	Ports       map[string][]int
}

func main() {
	var wg sync.WaitGroup
	resultJSON := mm.NewDS()

	links := html.GetAllLinks()
	wg.Add(len(links))
	for _, link := range links {
		// Limit to 100 goroutines at a time
		for runtime.NumGoroutine() > 100 {
			time.Sleep(time.Duration(10) * time.Millisecond)
		}
		go getPcapJSON(link, resultJSON, &wg)
	}
	wg.Wait() // All goroutines MUST complete before writing results
	writeJSON(resultJSON.Cache)
}

func getPcapJSON(link html.LinkData, result *mm.DataStore, wg *sync.WaitGroup) {
	pcapPath, dlErr := dl.FetchFile(link.Link)
	description := link.Description
	if dlErr != nil { // Skip local processing if file does not exist
		truncatedErr := firstLine(dlErr.Error())
		var pcapInfo = map[string]string{
			"Description":   description,
			"DownloadError": truncatedErr,
		}
		endGC(link.Link, result, wg, pcapInfo)
		return
	}
	capinfos, capErr := pcap.GetCapinfos(pcapPath)
	if capErr != nil {
		truncatedErr := firstLine(capErr.Error())
		var pcapInfo = map[string]string{
			"Description":   description,
			"CapinfosError": truncatedErr,
		}
		endGC(link.Link, result, wg, pcapInfo)
		return
	}
	protocols, ports, tsErr := pcap.GetProtoAndPortsJSON(pcapPath)
	if tsErr != nil {
		truncatedErr := firstLine(tsErr.Error())
		var pcapInfo = map[string]interface{}{
			"Description": description,
			"Capinfos":    capinfos,
			"TsharkError": truncatedErr,
		}
		endGC(link.Link, result, wg, pcapInfo)
		return
	}
	var pcapInfo = PcapData{
		description,
		capinfos,
		protocols,
		ports,
	}

	endGC(link.Link, result, wg, pcapInfo)
}

func firstLine(errText string) string {
	errBuf := bytes.NewBufferString(errText)
	line, _ := errBuf.ReadBytes('\n')
	if line[len(line)-1] == '\n' { // remove newline at end
		line = line[:len(line)-1]
	}
	line = append(line, '.', '.')
	two80CharLines := 160
	truncateLength := two80CharLines
	if len(line) < truncateLength {
		truncateLength = len(line)
	}
	lineStr := string(line[:truncateLength])
	fmt.Println(lineStr)
	return lineStr
}

// Warn and end the current goroutine
func endGC(url string, result *mm.DataStore, wg *sync.WaitGroup, values interface{}) {
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
		log.Fatal(err)
	}
	jsonPath := dir + "/.cache/captures.json"
	err = ioutil.WriteFile(jsonPath, jsonBytes, 0644)
	if err != nil {
		fmt.Println("Error in writing JSON to file:", err)
		fmt.Println("Filepath:", jsonPath)
	}
}
