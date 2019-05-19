// hubcap.go : Utility to download online pcaps to a temporary folder
/*
 * Assumptions:
 *     - The link for a file will continue to point to the same file.
 *       This is used to cache pcap results so expensive downloads
 *       happen as few times as possible.
 */
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"

	"github.com/pocc/hubcap/dl"
	"github.com/pocc/hubcap/html"
	mm "github.com/pocc/hubcap/mutexmap"
	"github.com/pocc/hubcap/pcap"
)

// PcapData stores info about an individual pcap
type PcapData struct {
	description string
	//capinfos    pcap.CapinfosData
	protocols []string
	ports     map[string][]int
}

func main() {
	var wg sync.WaitGroup
	resultJSON := mm.NewDS()

	links := html.GetAllLinks()
	wg.Add(len(links))
	for _, link := range links {
		go getPcapJSON(link, resultJSON, &wg)
	}
	wg.Wait() // All goroutines MUST complete before writing results
	writeJSON(resultJSON.Cache)
}

func getPcapJSON(link html.LinkData, result *mm.DataStore, wg *sync.WaitGroup) {
	pcapPath := dl.FetchFile(link.Link)
	/*var pcapData  = PcapData(
		link.Description,
		pcap.GetPcapInfo(pcapPath)

	)*/
	pcapInfo := []string{link.Description}
	var a struct{}
	result.Set(link.Link, a)
	wg.Done()
}

func writeJSON(resultJSON map[string]struct{}) {
	jsonStr, err := json.MarshalIndent(resultJSON, "", "  ")
	if err != nil {
		fmt.Println("Error in converting JSON:", err)
		fmt.Println("JSON:", resultJSON)
	}
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	jsonPath := dir + "/.cache/captures.json"
	err = ioutil.WriteFile(jsonPath, jsonStr, 0644)
	if err != nil {
		fmt.Println("Error in writing JSON to file:", err)
		fmt.Println("Filepath:", jsonPath)
	}
}
