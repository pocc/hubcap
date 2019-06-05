// Package html gets links of pcaps to download
package html

import (
	"fmt"
	"html"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type downloadLink struct {
	link        string
	description string
	filename    string
}

// Get the ASCII html string from a URL
func getHTML(pageURL string) string {
	fmt.Println("\033[92mINFO\033[0m Fetching HTML for page", pageURL)
	resp, httpErr := http.Get(pageURL)
	if httpErr != nil {
		fmt.Println("ERROR: Failed to reach `"+pageURL+"`", httpErr)
		time.Sleep(5 * time.Second)
		return getHTML(pageURL)
	}
	defer resp.Body.Close()
	siteHTML, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("ERROR: Failed to read html from `"+pageURL+"`", err)
	}
	return html.UnescapeString(string(siteHTML))
}

// Return all links from packetlife.net
func getPlCapPages(wg *sync.WaitGroup) []string {
	baseURL := "http://packetlife.net"
	captureHTML := getHTML(baseURL + "/captures")
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
func getWsBugzillaLinks(allLinks map[string]string) {
	var wg sync.WaitGroup
	done := make(chan bool)
	backoff := make(chan bool)
	index := 1
	for {
		select {
		case <-done:
			wg.Wait() // Wait for all Bugzilla crawlers
			return
		case <-backoff:
			time.Sleep(1000 * time.Millisecond)
		default:
			wg.Add(1)
			go getBugzillaHTML(index, 200, allLinks, &wg, backoff, done)
			time.Sleep(500 * time.Millisecond)
			index++
		}
	}
}

func getBugzillaHTML(index int, delay int, allLinks map[string]string, wg *sync.WaitGroup, backoff chan<- bool, done chan<- bool) {
	defer wg.Done()
	var description, filename string
	baseURL := "https://bugs.wireshark.org/bugzilla/attachment.cgi?id="
	descRe := regexp.MustCompile(`<title>([\s\S]*?)<\/title>(?:[\s\S]*?<div class=\"details\">(.*?) \()?`)
	indexStr := strconv.Itoa(index)
	pageHTML := getHTML(baseURL + indexStr + "&action=edit")
	attachmentDetails := descRe.FindAllStringSubmatch(pageHTML, -1)
	if len(attachmentDetails) == 0 {
		fmt.Println("ERROR: Regex failed in unexpected way for", pageHTML, "on index", index)
	}
	if len(attachmentDetails[0]) == 0 {
		fmt.Println("ERROR: Failed to parse HTML for", pageHTML, "on index", index)
	} else {
		description = attachmentDetails[0][1]
		description = strings.Replace(description, "\n ", "", -1)
		switch description {
		case "Invalid Attachment ID": // Quit once attachment number is invalid
			done <- true
			return
		case "Authorization Required": // Skip pulling files that don't exist
			return
		case "bugs.wireshark.org | 525: SSL handshake failed": // Wait and retry
			rand.New(rand.NewSource(time.Now().UnixNano()))
			randNum := rand.Int() % 2000
			newDelay := delay*4 + randNum
			time.Sleep(time.Duration(newDelay) * time.Millisecond)
			wg.Add(1)
			fmt.Println("\033[93mWARN\033[0m ", indexStr+": SSL handshake failed. Retrying in", newDelay, "ms")
			getBugzillaHTML(index, newDelay, allLinks, wg, backoff, done)
		default:
			filename = attachmentDetails[0][2]
			filename = strings.Replace(filename, " ", "_", -1)
			// filename is not needed in request, but provides filename for parser down the line
			allLinks[baseURL+indexStr+"&name="+filename] = description
		}
	}
}

// addCaptureLinks gets links/descs provided an html string and regex to find them
func addCaptureLinks(baseURL string, siteHTML string, linkReStr string, allLinks map[string]string) {
	// Get capture group match (partial link) and add it to link list
	emptyRe := regexp.MustCompile(`(^[\s.]*$|<span class)`)
	linkRe := regexp.MustCompile(linkReStr)
	noDescTitleRe := regexp.MustCompile(`(<br>\s*<\/strong>Description:? ?<strong>|^\s*[-;:]?\s*)`)
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
		// Some links are to view the download instead of getting it
		link = strings.Replace(link, "&do=view", "&do=get", -1)
		desc = noDescTitleRe.ReplaceAllString(desc, "")
		allLinks[link] = desc
	}
}

// GetAllLinks gets all of the pcap download links from various websites
func GetAllLinks() map[string]string {
	links := make(map[string]string)
	var wg sync.WaitGroup
	start := time.Now()

	// From Packet Life
	plCapURL := "http://packetlife.net/captures/"
	plPageUrls := getPlCapPages(&wg)
	plRe := `<h3>(?P<name>.*?\S)\s*<small>[\s\S]*?<p>(?P<desc>[\s\S]*?\S)\s*</p>\s*`
	for _, pageURL := range plPageUrls {
		wg.Add(1)
		go func(webpageURL string) {
			captureHTML := getHTML(webpageURL)
			addCaptureLinks(plCapURL, captureHTML, plRe, links)
			wg.Done()
		}(pageURL)
	}

	// From Wireshark Sample Captures, provided by the community
	wsCapURL := "https://wiki.wireshark.org"
	wsSampleURL := wsCapURL + "/SampleCaptures"
	wsSampleHTML := getHTML(wsSampleURL)
	wsAppendixLinksRe := `Appendix\" title=\"[^"]*\" href=\"([^"]*)\"()`
	addCaptureLinks(wsCapURL, wsSampleHTML, wsAppendixLinksRe, links)
	// It looks like this HTML was written by hand (i.e. harder to use regex)
	// If a link is found both in appendix and in pagetext, overwrite with link that has description
	wsLinkWithDescRe := `<a class="attachment" href="(\/SampleCaptures[^"]+?)"[\s\S]+?(?:<\/s[\s\S]*?867">|<\/a> ??)([\s\S]+?)\s*(?:<span class|File:<strong> )`
	addCaptureLinks(wsCapURL, wsSampleHTML, wsLinkWithDescRe, links)

	// From Wireshark Bugzilla, add all links found
	// getWsBugzillaLinks(links)

	wg.Wait()
	numPages := len(plPageUrls) + 1
	fmt.Printf("-> Fetched %d pages containing %d links in %s\n", numPages, len(links), time.Since(start))
	return links
}
