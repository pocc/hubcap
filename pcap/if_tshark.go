package pcap

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
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

// GetTsharkInfo filters with the given filter and then applies fields
func GetTsharkInfo(filename string, filter string, fields ...string) ([]byte, error) {
	cmdList := []string{"-T", "fields", "-Y", filter, "-E", "separator=|"}
	for _, field := range fields {
		cmdList = append(cmdList, "-e", field)
	}
	cmdList = append(cmdList, "-r", filename)
	cmd := exec.Command("tshark", cmdList...)

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err != nil {
		tsharkErr := fmt.Errorf("\033[93mWARN\033[0m %s", err.Error())
		return []byte(err.Error()), tsharkErr
	}
	if len(stderr.Bytes()) > 0 {
		// This is not a fatal error because it's ok if some files are not read
		errorText := string(stderr.Bytes())
		if errorText[0] == '\n' {
			errorText = errorText[1:]
		}
		tsharkErr := fmt.Errorf("\033[93mWARN\033[0m tshark: %s", errorText)
		return stderr.Bytes(), tsharkErr
	}
	return stdout.Bytes(), nil
}

// GetProtoAndPortsJSON gets just frame.protocols, udp.port, tcp.port and returns a JSON
func GetProtoAndPortsJSON(filename string) ([]string, map[string][]int, error) {
	text, err := GetTsharkInfo(filename, "", "frame.protocols", "udp.port", "tcp.port")
	protocols, ports := parseProtoAndPorts(text)
	return protocols, ports, err
}

// parseProtoAndPorts parses just frame.protocols, udp.port, tcp.port
func parseProtoAndPorts(text []byte) ([]string, map[string][]int) {
	ports := make(map[string][]int)
	protoRe := regexp.MustCompile(`(?:^|\n)(\S*?)\|(\d*?),?(\d*?)\|(\d*?),?(\d*?)`)
	protoData := protoRe.FindAllStringSubmatch(string(text), -1)
	rotatedData := make([][]string, 5)
	for i := 0; i < 5; i++ {
		rotatedData[i] = make([]string, len(protoData))
	}
	for j, line := range protoData {
		for i := 0; i < len(line)-1; i++ {
			elem := line[i+1]
			if elem != "" {
				rotatedData[i][j] = elem
			}
		}
	}
	protocols := uniqueProtocols(rotatedData[0])
	ports["tcpSrcPorts"] = uniquePorts(rotatedData[1])
	ports["tcpDstPorts"] = uniquePorts(rotatedData[2])
	ports["udpSrcPorts"] = uniquePorts(rotatedData[3])
	ports["udpDstPorts"] = uniquePorts(rotatedData[4])
	return protocols, ports
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
		if !mapUniques[port] && port != "" {
			uniqueInt, err := strconv.Atoi(port)
			if err != nil {
				log.Fatal("ERROR:", err, "\nProblem converting port to int `"+port+"`")
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
