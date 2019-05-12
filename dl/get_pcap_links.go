// Get links of pcaps to download
package dl


import (
    "fmt"
    "net/http"
    "io/ioutil"
    "strconv"
	"regexp"
)

type linkStruct struct {
	// Include any data in here that could be relevant to a pcap link
	link string
	description string
}

func getHtml(url string) (string, error) {
    // Get the ASCII html from a URL
    resp, err := http.Get(url) 
    if err != nil { fmt.Println("ERROR: Failed to crawl `" + url + "`") }
    defer resp.Body.Close()
    html, err := ioutil.ReadAll(resp.Body)
    if err != nil { fmt.Println("ERROR: Failed to read html from `" + url + "`") }
    return string(html), err
}

func getPlCaptureQty(base_url string) int {
	// Get the number of pages of captures at packetlife.net
	capture_html, _ := get_html(base_url + "/captures") 
	re := regexp.MustCompile(`\?page=(\d+)`)
	page_paths := re.FindAllStringSubmatch(capture_html, -1)
	highest_page := 0
	for _, match := range page_paths {
		page_num, err := strconv.Atoi(match[1])
		if err != nil { fmt.Print("Error found:", err) }
		if highest_page < page_num {
			highest_page = page_num
		}
	} 
	return highest_page
}

func getPlCaptures(base_url string) ([]string, []string) {
	// Get the download URLs of all available pcaps from PacketLife.net
	re := regexp.MustCompile(`<h3>(?P<name>.*?)<small>[\s\S]*?<p>(?P<desc>[\s\S]*?)</p>`)
	num_pages := getPlCaptureQty(base_url)
    var packetLifeLinks []linkStruct
		
	for i := 1; i <= num_pages; i++ {
        html, _ := get_html(base_url + "/captures/?page=" + strconv.Itoa(i))
		link_matches := re.FindAllStringSubmatch(html, -1)
		// Get capture group match (partial link) and add it to link list
		for _, match := range link_matches {
			packetLifeLinks = append(plLinks, linkStruct{match[1:2]})		}
    }
	return packetLifeLinks
}

func GetAllLinks() {
    base_url := "http://packetlife.net"
	num_pages := getPlCaptureQty(base_url)
	packetLifeLinks := getCapturePaths(base_url, num_pages)
}