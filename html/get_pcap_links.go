// Package html gets links of pcaps to download
package html

import (
	"fmt"
	"html"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LinkData : All meta data for a pcap
type LinkData struct {
	Link        string
	Description string
}

// Get the ASCII html from a URL
func getHTML(pageURL string, htmlChan chan<- string, wg *sync.WaitGroup) {
	fmt.Println("\033[92mINFO\033[0m Fetching HTML for page", pageURL)
	resp, err := http.Get(pageURL)
	if err != nil {
		fmt.Println("ERROR: Failed to reach `"+pageURL+"`", err)
	}
	defer resp.Body.Close()
	siteHTML, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("ERROR: Failed to read html from `"+pageURL+"`", err)
	}
	htmlChan <- html.UnescapeString(string(siteHTML))
	wg.Done()
}

// Get the number of pages of captures at packetlife.net by looking at HTML
func getPlCapPages(wg *sync.WaitGroup) []string {
	baseURL := "http://packetlife.net"
	htmlChan := make(chan string)
	wg.Add(1)
	go getHTML(baseURL+"/captures", htmlChan, wg)
	captureHTML := <-htmlChan
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

// Wireshark bugzilla attachments are sequential, but not all are pcaps
func getWsBugzillaPcaps() {
	// https://bugs.wireshark.org/bugzilla/attachment.cgi?id=6400
	// <div class="details">M1_header_crc.pcapng (application/x-pcapng),432 bytes, created by
	// `<div class=\"details\">[\s\S]*?\(application/([\s\S]*)`
	fmt.Println("This function is not implemented!")
	os.Exit(1)
}

func getCaptureLinks(baseURL string, pageURLs []string, linkReStr string, wg *sync.WaitGroup) []LinkData {
	// Get the download links of all available pcaps from URLs given regex
	var allLinks []LinkData
	htmlChan := make(chan string)

	// Get capture group match (partial link) and add it to link list
	emptyRe := regexp.MustCompile(`(^[\s.]*$|<span class)`)
	linkRe := regexp.MustCompile(linkReStr)
	noDescRe := regexp.MustCompile(`(<br>\s*<\/strong>Description:? ?<strong>|^\s*[-;:]?\s*)`)
	for _, pageURL := range pageURLs {
		wg.Add(1)
		go getHTML(pageURL, htmlChan, wg)
		siteHTML := <-htmlChan
		linkMatches := linkRe.FindAllStringSubmatch(siteHTML, -1)
		for _, match := range linkMatches {
			// If it is a relative path, add the base url before it
			link, desc := match[1], match[2]
			if !strings.HasPrefix(link, "http") {
				link = baseURL + link
			}
			if emptyRe.MatchString(match[2]) {
				desc = "No Description"
			}
			// Sanitize link and description
			link = strings.Replace(link, ",", "%2C", -1)
			link = strings.Replace(link, " ", "%20", -1)
			desc = noDescRe.ReplaceAllString(desc, "")
			allLinks = append(allLinks, LinkData{link, desc})
		}
	}
	return allLinks
}

// GetAllLinks gets all of the pcap download links from various websites
func GetAllLinks() []LinkData {
	var links []LinkData
	var newLinks []LinkData
	var wg sync.WaitGroup
	start := time.Now()

	// From Packet Life
	plCapURL := "http://packetlife.net/captures/"
	plPageUrls := getPlCapPages(&wg)
	plRe := `<h3>(?P<name>.*?\S)\s*<small>[\s\S]*?<p>(?P<desc>[\s\S]*?\S)\s*</p>\s*`
	newLinks = getCaptureLinks(plCapURL, plPageUrls, plRe, &wg)
	links = append(links, newLinks...)

	// From Wireshark Sample Captures, provided by the community
	wsCapURL := "https://wiki.wireshark.org"
	wsSampleUrls := []string{wsCapURL + "/SampleCaptures"}
	// It looks like this HTML was written by hand (i.e. harder to use regex)
	wsSampleRe := `<a class="attachment" href="(\/SampleCaptures[^"]+?)"[\s\S]+?(?:<\/s[\s\S]*?867">|<\/a> ??)([\s\S]+?)\s*(?:<span class|File:<strong> )`
	newLinks = getCaptureLinks(wsCapURL, wsSampleUrls, wsSampleRe, &wg)
	links = append(links, newLinks...)

	wg.Wait()
	numPages := len(plPageUrls) + len(wsSampleUrls)
	fmt.Printf("-> Fetched %d pages containing %d links in %s\n", numPages, len(links), time.Since(start))
	return links
}
