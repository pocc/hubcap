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
	"github.com/pocc/hubcap/pcap"
)

func main() {
	var wg sync.WaitGroup
	resultJSON := make(map[string][]string)

	links := html.GetAllLinks()
	wg.Add(len(links))
	for _, link := range links {
		go getPcapJSON(&link, resultJSON)
	}
	wg.Wait() // All goroutines MUST complete before writing results
	writeJSON(resultJSON)
}

func getPcapJSON(link *html.LinkData, result map[string][]string) {
	filepath := dl.DownloadFile(link.Link)
	pcapInfo := pcap.GetPcapInfo(filepath)
	pcapName := "Temporary pcap name"
	result[pcapName] = pcapInfo
}

func writeJSON(resultJSON map[string][]string) {
	file, err := json.MarshalIndent(resultJSON, "", "  ")
	if err != nil {
		fmt.Println("Error in converting JSON:", err)
		fmt.Println("JSON:", resultJSON)
	}
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	jsonPath := dir + "/.cache/captures.json"
	err = ioutil.WriteFile(jsonPath, file, 0644)
	if err != nil {
		fmt.Println("Error in writing JSON to file:", err)
		fmt.Println("Filepath:", jsonPath)
	}
}
