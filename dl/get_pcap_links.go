// Package dl gets links of pcaps to download
package dl

import (
	"fmt"
	"html"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Include any data in here that could be relevant to a pcap link
type linkData struct {
	link        string
	description string
}

// Get the ASCII html from a URL
func getHTML(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("ERROR: Failed to reach `" + url + "`")
	}
	defer resp.Body.Close()
	siteHTML, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("ERROR: Failed to read html from `" + url + "`")
	}
	retHTML := html.UnescapeString(string(siteHTML))
	return retHTML, err
}

// Get the number of pages of captures at packetlife.net
func getPlCapPages() []string {
	baseURL := "http://packetlife.net"
	captureHTML, _ := getHTML(baseURL + "/captures")
	re := regexp.MustCompile(`\?page=(\d+)`)
	pagePaths := re.FindAllStringSubmatch(captureHTML, -1)
	highestPage := 0
	for _, match := range pagePaths {
		pageNum, err := strconv.Atoi(match[1])
		if err != nil {
			fmt.Print("Error found:", err)
		}
		if highestPage < pageNum {
			highestPage = pageNum
		}
	}

	pageUrls := make([]string, highestPage)
	// Packet life pages start at 1
	for i := 0; i < highestPage; i++ {
		pageUrls[i] = baseURL + "/captures/?page=" + strconv.Itoa(i+1)
	}

	return pageUrls
}

func getCaptureLinks(urls []string, linkReStr string) []linkData {
	// Get the download links of all available pcaps from URLs given regex
	re := regexp.MustCompile(linkReStr)
	var allLinks []linkData

	for _, url := range urls {
		siteHTML, _ := getHTML(url)
		linkMatches := re.FindAllStringSubmatch(siteHTML, -1)
		// Get capture group match (partial link) and add it to link list
		htmlRe := regexp.MustCompile(`(https?:\/\/[a-zA-Z0-9.-]*)`)
		emptyRe := regexp.MustCompile(`(^[\s.]*$|<span class)`)
		for _, match := range linkMatches {
			// If it is a relative path, add the base url before it
			if strings.HasPrefix(match[1], "/") {
				baseURLWithEntities := htmlRe.FindStringSubmatch(url)[1]
				baseURL := html.UnescapeString(baseURLWithEntities)
				match[1] = baseURL + match[1]
			}
			if emptyRe.MatchString(match[2]) {
				match[2] = "No Description"
			}
			// Sanitize description
			noDescRe := regexp.MustCompile(`(<br>\s*<\/strong>Description:? ?<strong>|^\s*[-;:]?\s*)`)
			match[2] = noDescRe.ReplaceAllString(match[2], "")
			allLinks = append(allLinks, linkData{match[1], match[2]})
		}
	}
	return allLinks
}

// GetAllLinks gets all of the pcap download links from various websites
func GetAllLinks() {
	var links []linkData
	var newLinks []linkData

	// From Packet Life (http://packetlife.net/captures/)
	plPageUrls := getPlCapPages()
	plRe := `<h3>(?P<name>.*?)<small>[\s\S]*?<p>(?P<desc>[\s\S]*?)</p>\s*`
	newLinks = getCaptureLinks(plPageUrls, plRe)
	links = append(links, newLinks...)

	// From Wireshark Sample Captures, provided by the community
	wsSampleUrls := []string{"https://wiki.wireshark.org/SampleCaptures"}
	// It looks like this HTML was written by hand (i.e. harder to use regex)
	wsSampleRe := `<a class="attachment" href="(\/SampleCaptures[^"]+?)"[\s\S]+?(?:<\/s[\s\S]*?867">|<\/a> ??)([\s\S]+?)\s*(?:<span class|File:<strong> )`
	newLinks = getCaptureLinks(wsSampleUrls, wsSampleRe)
	links = append(links, newLinks...)

	for _, link := range links {
		fmt.Print(link.link, "\n\t", link.description, "\n")
	}
}
