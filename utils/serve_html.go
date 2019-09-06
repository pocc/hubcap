// Generate HTML for Downloads page
// Philosophy is to render everything so less javascript is run browser-side
package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"path/filepath"
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

func main() {
	tmpl := template.Must(template.ParseFiles("/Users/rj/code/hubcap/assets/source.html"))
	cacheFD, err := ioutil.ReadFile("/Users/rj/code/hubcap/.cache/captures.json")
	if err != nil {
		fmt.Println("Error reading file " + err.Error())
	}
	cache := make(map[string]PcapInfo)
	Pcaps := make([]PcapInfo, 0)
	jsonErr := json.Unmarshal([]byte(cacheFD), &cache)
	if jsonErr != nil {
		fmt.Println("Error unmarshalling json " + err.Error())
	}
	for hash, pi := range cache {
		protos := make([]string, 0)
		if hash[0] != '-' { // - means it's not a sha256 hash
			pi.Filename = filepath.Base(pi.Filename)
			pi.Capinfos["FileSize"] = convertSize(pi.Capinfos["FileSize"])
			for _, proto := range pi.Protocols {
				protos = append(protos, "[" + proto + "]") 
			}
			pi.Protocols = protos
			Pcaps = append(Pcaps, pi)
		}
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		err := tmpl.Execute(w, Pcaps)
		if err != nil {
			fmt.Println(err)
		}
	})

	http.ListenAndServe(":80", nil)
}
