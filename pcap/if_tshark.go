package pcap

import (
	"log"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type tsharkInfo struct {
	protocols   []string
	tcpSrcPorts []int
	tcpDstPorts []int
	udpSrcPorts []int
	udpDstPorts []int
}

/*
func GetTsharkInfo(filename string, filter string, fields ...string) tsharkInfo {
	tsharkText, err := exec.Command("tshark", "-r", "-T", "fields",
		"-e", "frame.types", "-e", "tcp.ports", "-e", "udp.ports", filename).CombinedOutput()
	if err != nil {
		fmt.Println("ERROR: tshark could not read", filename, "\n", err)
	}
	var result tsharkInfo
	return result
}*/

func getTsharkInfo(text []byte) tsharkInfo {
	/* This buffer parser is faster than and equivalent to these python regexes:
	 */
	var result tsharkInfo
	protoRe := regexp.MustCompile(`(?:^|\n)(\S*?)\|(\d*?),?(\d*?)\|(\d*?),?(\d*?)`)
	protoData := protoRe.FindAllStringSubmatch(string(text), -1)
	result.protocols = uniqueProtocols(protoData[0])
	result.tcpSrcPorts = uniquePorts(protoData[1])
	result.tcpDstPorts = uniquePorts(protoData[2])
	result.udpSrcPorts = uniquePorts(protoData[3])
	result.udpDstPorts = uniquePorts(protoData[4])

	return result
}

func uniqueProtocols(protocols []string) []string {
	var result []string
	mapUniques := make(map[string]bool)
	for _, protocolLine := range protocols {
		protocols := strings.Split(protocolLine, ":")
		for _, protocol := range protocols {
			if !mapUniques[protocol] {
				result = append(result, protocol)
			}
			mapUniques[protocol] = true
		}
	}
	return result
}

func uniquePorts(ports []string) []int {
	uniques := make([]int, 0)
	mapUniques := make(map[string]bool)
	for _, port := range ports {
		if !mapUniques[port] {
			uniqueInt, err := strconv.Atoi(port)
			if err != nil {
				log.Fatal(err)
			}
			uniques = append(uniques, uniqueInt)
		}
		mapUniques[port] = true
	}

	return uniques
}

// TestGetTsharkInfo tests GetTsharkInfo
func TestGetTsharkInfo(t *testing.T) {
	/*testInput := []byte(
			`eth:ethertype:ip:udp:data|42559,26895|
	eth:ethertype:ip:tcp:ssl||443,56561
	eth:ethertype:ip:tcp||56562,443
	eth:ethertype:ip:tcp:data||443,56562
	eth:ethertype:ip:tcp||56561,443
	eth:ethertype:ip:tcp:ssl||443,56563
	eth:ethertype:ip:udp:data|26895,42559|
	eth:ethertype:ip:tcp||56562,443
	eth:ethertype:ip:tcp:ssl||443,56562
	eth:ethertype:ip:tcp||56563,443`)*/
	expected := []byte(
		`{"protocols":["eth","ethertype","ip","tcp","ssl","udp","data"],` +
			`"tcp":{"srcport":[443,56561,56562,56563],"dstport":[443,56561,56562,56563]}` +
			`"udp":{"srcport":[26895,42559],"dstport":[26895,42559]}`)
	actual := []byte("") //getCapinfos(testInput)
	assert.Equal(t, expected, actual, "These should be the same.")
}
