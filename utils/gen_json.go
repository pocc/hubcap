// Generate JSON for tshark.dev Downloads page
// Philosophy is to render everything so less javascript is run browser-side
// Run from project root (i.e. call `go run utils/gen_json.go`)
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"strconv"
)

// PcapInfo stores info about an individual pcap
type PcapInfo struct {
	Filename    string
	Sources     []string
	Description string
	Capinfos    map[string]interface{}
	Protocols   []string
	Ports       map[string][]int
	ErrorStr    string
}

// Data item as part of an abrdiged captures json
type AbridgedPcapInfo struct {
	Filename string
	Source string
	Description string
	Protocols string
	FileSize string
	CaptureDuration float64
	NumberOfPackets int
	NumberOfInterfacesInFile int
}

// given a filesize, return the same value in KB/MB/GB, etc
func convertSize(filesize interface{}) string {
	size := filesize.(float64)
	unit := []string{"B", "KB", "MB", "GB", "TB"}
	power := 0
	for size > 1024 {
		size /= 1024
		power++
	}
	return fmt.Sprintf("%.0f %s", size, unit[power])
}

// Copied from app/hubcap.go. At some point should reference that funciton instead.
func writeJSON(Pcaps []AbridgedPcapInfo) {
	jsonBuf := new(bytes.Buffer)
	enc := json.NewEncoder(jsonBuf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(Pcaps)
	if err != nil {
		fmt.Println("Error in converting JSON:", err)
		fmt.Println("JSON:", Pcaps)
	}
	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("Could not read current directory", err)
		os.Exit(1)
	}
	jsonPath := dir + "/build/abridged_captures.json"
	err = ioutil.WriteFile(jsonPath, jsonBuf.Bytes(), 0644)
	if err != nil {
		fmt.Println("Error in writing JSON to file:", err)
		fmt.Println("Filepath:", jsonPath)
	}
}

func main() {
	cacheFD, err := ioutil.ReadFile(".cache/captures.json")
	if err != nil {
		fmt.Println("Error reading file " + err.Error())
	}
	cache := make(map[string]PcapInfo)
	Pcaps := make([]AbridgedPcapInfo, 0)
	jsonErr := json.Unmarshal([]byte(cacheFD), &cache)
	if jsonErr != nil {
		fmt.Println("Error unmarshalling json " + err.Error())
	}
	var numberOfInterfaces int
	var numberOfInterfacesF64 float64
	var ok3 bool
	for hash, pi := range cache {
		protos := make([]string, 0)
		if hash[0] != '-' { // - means it's not a sha256 hash
			for _, proto := range pi.Protocols {
				protos = append(protos, "[" + proto + "]") 
			}
			// Looks like there's a bug with Capinfos where -0.3 is shown as 0.-3
			duration := fmt.Sprintf("%v", pi.Capinfos["CaptureDuration"])
			if strings.Contains(duration, "-") {
				duration = "-" + strings.ReplaceAll(duration, "-", "")
			}
			if strings.Contains(duration, " ") {
				duration = strings.Split(duration, " ")[0]
			}
			captureDuration, err1 := strconv.ParseFloat(duration, 64)
			numberOfPacketsF64, ok2 := pi.Capinfos["NumberOfPackets"].(float64)
			numberOfPackets := int(numberOfPacketsF64)
			if pi.Capinfos["NumberOfInterfacesInFile"] != nil {
				numberOfInterfacesF64, ok3 = pi.Capinfos["NumberOfInterfacesInFile"].(float64)
				numberOfInterfaces = int(numberOfInterfacesF64)
			} else {
				numberOfInterfaces = 0
				ok3 = true
			}
			if err1 != nil || !ok2 || !ok3 {
				fmt.Println("Error parsing captures JSON at", pi.Filename,
				"CaptureDuration: ", pi.Capinfos["CaptureDuration"], err1.Error(), reflect.TypeOf(pi.Capinfos["CaptureDuration"]), 
				"NumberOfPackets", pi.Capinfos["NumberOfPackets"], ok2, reflect.TypeOf(pi.Capinfos["NumberOfPackets"]), 
				"NumberOfInterfaces",  pi.Capinfos["NumberOfInterfacesInFile"], ok3, reflect.TypeOf(pi.Capinfos["NumberOfInterfacesInFile"]))
			}
			numberOfPackets = int(numberOfPackets)

			new_pcapinfo := AbridgedPcapInfo{
				filepath.Base(pi.Filename),
				pi.Sources[0],
				pi.Description,
				strings.Join(protos, " "),
				convertSize(pi.Capinfos["FileSize"]),
				captureDuration,
				numberOfPackets,
				numberOfInterfaces,
			}
			Pcaps = append(Pcaps, new_pcapinfo)
		}
	}
	writeJSON(Pcaps)
}
