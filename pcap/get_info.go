// Package pcap : Get info about a pcap using capinfos and tshark
package pcap

import (
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"regexp"
	"time"
)

type pcapInfo struct {
	filename      string
	filetype      string
	encapsulation string
	tsPrecision   string
	pktSizeLimit  string
	numPkts       int
	numFileBytes  int
	numDataBytes  int
	capLengthInS  float32
	firstPktTime  time.Time
	lastPktTime   time.Time
	bytesPerSec   float32
	bitsPerSec    float32
	avePktBytes   float32
	avePktsPerSec float32
	SHA256        string
	RIPEMD160     string
	SHA1          string
	isOrdered     bool
	numInterfaces int32
	interfaces    []netIface
}

type netIface struct {
	name            string
	description     string
	encapsulation   string
	captureLength   int
	timePrecision   int32
	timeTicksPerSec int32
	osName          string
	numStatEntries  int32
	numPkts         int
}

func getCapinfos(fileInfo string, capRe *regexp.Regexp) {
	return
}

func getTsharkInfo(fileInfo string, tsharkRe *regexp.Regexp) {
	return
}

// GetPcapInfo : Get metadata about a pcap
func getPcapInfo() map[string][]string {
	files, err := ioutil.ReadDir("./")
	if err != nil {
		log.Fatal(err)
	}
	capinfosRe := regexp.MustCompile(``)
	tsharkRe := regexp.MustCompile(``)
	result := make(map[string][]string)
	for _, fileObj := range files {
		filename := string(fileObj.Name())
		capText, err := exec.Command("capinfos", filename).CombinedOutput()
		if err != nil {
			log.Fatal(err)
		}
		getCapinfos(string(capText), capinfosRe)

		tsharkText, err := exec.Command("tshark", "-r", "-T", "fields",
			"-e", "frame.types").CombinedOutput()
		if err != nil {
			log.Fatal(err)
		}
		getTsharkInfo(string(tsharkText), tsharkRe)
	}
	fmt.Println(result)
	return result
}
