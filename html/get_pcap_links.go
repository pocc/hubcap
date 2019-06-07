// Package html gets links of pcaps to download
package html

import (
	"fmt"
	"html"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LinkCache is concurrent safe way to store links
type LinkCache struct {
	sync.Mutex
	Cache map[string]string
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
	siteHTML, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("ERROR: Failed to read html from `"+pageURL+"`", err)
	}
	resp.Body.Close()
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

// GetWsBugzillaLinks gets wireshark bugzilla attachments, which are sequential, but not all are pcaps
func GetWsBugzillaLinks(cachedLinks []string, allLinks map[string]string) {
	linkCache := LinkCache{Cache: make(map[string]string)}
	idRe := regexp.MustCompile(`id=(.*?)(?:&|$)`)
	index := 1
	numCached := 0
	haveCachedAttachment := make([]bool, 20000)
	for _, link := range cachedLinks {
		results := idRe.FindStringSubmatch(link)
		if len(results) > 0 {
			num, err := strconv.Atoi(results[1])
			if err != nil {
				fmt.Println("Unable to convert string to int", err)
			}
			haveCachedAttachment[num] = true
			numCached++
		}
	}
	done := make(chan bool)
	backoff := make(chan bool)
	backoffSwitch := false
	for index < 20000 {
		if haveCachedAttachment[index] {
			index++
			continue
		}
		if backoffSwitch {
			fmt.Printf("Backing off for 2 seconds.\n")
			time.Sleep(time.Duration(2) * time.Second)
			backoffSwitch = false
		}
		select {
		case <-done:
			fmt.Printf("Waiting for %d goroutines to finish\n", runtime.NumGoroutine())
			index = 20000 // Just hardcode to max for the time being
		case <-backoff:
			time.Sleep(time.Duration(1000) * time.Millisecond)
			backoffSwitch = true
		default:
			go getBugzillaHTML(index, 200, &linkCache, backoff, done)
			time.Sleep(500 * time.Millisecond)
			index++
		}
	}
	for link, desc := range linkCache.Cache {
		allLinks[link] = desc
	}
}

func getBugzillaHTML(index int, delay int, linkCache *LinkCache, backoff chan<- bool, done chan<- bool) {
	var description, filename string
	baseURL := "https://bugs.wireshark.org/bugzilla/attachment.cgi?id="
	descRe := regexp.MustCompile(`<title>([\s\S]*?)<\/title>(?:[\s\S]*?<div class=\"details\">(.*?) \()?`)
	indexStr := strconv.Itoa(index)
	pageHTML := getHTML(baseURL + indexStr + "&action=edit")
	attachmentDetails := descRe.FindAllStringSubmatch(pageHTML, -1)
	if len(attachmentDetails) == 0 || len(attachmentDetails[0]) == 0 {
		fmt.Println("ERROR: Regex failed in unexpected way for", pageHTML, "on index", index, ". Skipping...")
		return
	}
	description = attachmentDetails[0][1]
	description = strings.Replace(description, "\n ", "", -1)
	description = strings.TrimSpace(description)
	switch description {
	case "Invalid Attachment ID": // Quit once attachment number is invalid
		fmt.Printf("\033[93mWARN\033[0m Invalid Attachment ID found for %s. Skipping...\n", baseURL+indexStr)
		if index != 15252 && index != 15253 { // Weird invalid attachments in middle of list, not at end
			done <- true
		}
	case "Authorization Required": // Skip pulling files that don't exist
		fmt.Printf("\033[93mWARN\033[0m Authorization Required for viewing %s. Skipping...\n", baseURL+indexStr)
		linkCache.Lock()
		linkCache.Cache[baseURL+indexStr] = "Authorization Required"
		linkCache.Unlock()
	case "bugs.wireshark.org | 525: SSL handshake failed": // Wait and retry
		rand.New(rand.NewSource(time.Now().UnixNano()))
		newDelay := delay*4 + rand.Int()%2000
		fmt.Println("\033[93mWARN\033[0m ", indexStr+": SSL handshake failed. Retrying in", newDelay, "ms")
		backoff <- true
	default:
		filename = attachmentDetails[0][2]
		filename = strings.Replace(filename, " ", "_", -1)
		// filename is not needed in request, but provides filename for parser down the line
		linkCache.Lock()
		linkCache.Cache[baseURL+indexStr+"&name="+filename] = description
		linkCache.Unlock()
	}
}

// addCaptureLinks gets links/descs provided an html string and regex to find them
func addCaptureLinks(baseURL string, siteHTML string, linkReStr string, allLinks map[string]string) {
	// Get capture group match (partial link) and add it to link list
	linkCache := LinkCache{Cache: make(map[string]string)}
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
		linkCache.Lock()
		linkCache.Cache[link] = desc
		linkCache.Unlock()
	}
	for link, desc := range linkCache.Cache {
		allLinks[link] = desc
	}
}

// AddWiresharkSampleLinks gets all of the pcap download links from the Wireshark Sample Captures
func AddWiresharkSampleLinks(links map[string]string) {
	var wg sync.WaitGroup
	numInitialLinks := len(links)
	start := time.Now()

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

	wg.Wait()
	fmt.Printf("-> Fetched 1 page containing %d links in %s\n", len(links)-numInitialLinks, time.Since(start))
}

// AddPacketlifeLinks gets all of the pcap download links from PacketLife
func AddPacketlifeLinks(links map[string]string) {
	var wg sync.WaitGroup
	numInitialLinks := len(links)
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

	wg.Wait()
	numPages := len(plPageUrls) + 1
	fmt.Printf("-> Fetched %d page containing %d links in %s\n", numPages, len(links)-numInitialLinks, time.Since(start))
}
