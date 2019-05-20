package pcap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"log"
	"os/exec"
	"testing"
)

// GetCapinfos creates a json out of capinfos output
func GetCapinfos(filename string) map[string]interface{} {
	cmd := exec.Command("capinfos", "-M", filename)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	if err != nil || !bytes.Equal(stderr.Bytes(), []byte("")) {
		// This is not a fatal error because it's ok if some files are not read
		fmt.Println("capinfos error reading file", filename,
			"Go reported err:", err,
			"\nSTDOUT:`"+string(stdout.Bytes())+"`",
			"\nSTDERR:`"+string(stderr.Bytes())+"`")
		errorResult := make(map[string]interface{})
		errorResult[filename] = "File not found"
		return errorResult
	}
	ciJSON := capinfos2JSON(stdout.Bytes())
	return JSON2Struct(ciJSON)
}

// JSON2Struct converts a capinfos struct to a JSON
func JSON2Struct(text []byte) map[string]interface{} {
	pcapInfo := map[string]interface{}{}
	err := json.Unmarshal(text, &pcapInfo)
	if err != nil {
		fmt.Println("Failed to structify", string(text), "\nERROR:", err)
		log.Fatal(err)
	}
	return pcapInfo
}

// capinfos2JSON parses capinfos output into a JSON
func capinfos2JSON(text []byte) []byte {
	result := []byte("{\"")
	index := 0
	// Treat colon as text if this line's colon delemiter has been read
	readingKey := true
	readingNumericValue := false
	readingEncap := false
	var numberStart int
	// Add a } at the end if there's an interface
	// Structure of capinfos is [pcap section, interface section...]
	readingInterfaces := false
	for index < len(text) {
		switch text[index] {
		case ':':
			switch {
			case text[index+1] == '\n':
				if readingInterfaces {
					chopIndex := len(result) - 1
					for result[chopIndex] != ',' {
						chopIndex--
					}
					result = result[:chopIndex]
					result = append(result, '}', ',', '{', '"')
				} else {
					switch {
					// Interface info
					case string(result[len(result)-4:]) == "Info":
						result = append(result[:len(result)-6], 's')
						result = append(result, '"', ':', '[', '{', '"')
						readingInterfaces = true
					// Encapsulation info
					case string(string(result[len(result)-5:])) == "Pkts)":
						result = append(result[:len(result)-9], '"', ':', '[', '"')
						readingEncap = true
					default:
						log.Fatal("Unknown interface:", string(result))
					}
				}
				index = skipSpaces(index+1, text)
			case readingKey:
				result = append(result, '"', ':')
				// capinfos indents values of keys, so skip that
				index = skipSpaces(index, text)
				isDigit := '9' >= text[index+1] && text[index+1] >= '0'
				if isDigit {
					readingNumericValue = true
					numberStart = len(result)
				}
				result = append(result, '"')
				readingKey = false
			default:
				result = append(result, ':')
			}
		case ' ':
			// For `Interface #n` key value pairs
			switch {
			case text[index+1] == '=' && text[index+2] == ' ':
				result = append(result, '"', ':', '"')
				readingKey = false
				index += 2
				if '9' >= text[index+1] && text[index+1] >= '0' {
					readingNumericValue = true
					numberStart = len(result) - 1
				}
			// keys should not have spaces, should be camelcase
			case readingKey:
				r := text[index+1]
				if 'z' >= r && r >= 'a' {
					camelcaseFirstLetter := text[index+1] - 32
					result = append(result, camelcaseFirstLetter)
					index++
				}
			case readingNumericValue:
				// skip unit for number like "packets", "seconds", or "bytes"
				for index < len(text) && text[index+1] != '\n' {
					index++
				}
			default:
				result = append(result, ' ')
			}
		case '\n':
			// If it's a number, unquote it
			if readingNumericValue {
				// Verbose because golang optimizes append in unexpected ways
				preQuote := result[:numberStart]
				postQuote := string(result[numberStart+1:])
				result = append(preQuote, postQuote...)
			} else {
				result = append(result, '"')
			}
			isLastChar := index == len(text)-1
			if !isLastChar {
				if text[index+1] != ' ' && readingEncap {
					result = append(result, ']')
					readingEncap = false
				}
				result = append(result, ',', '"')
				index = skipSpaces(index, text)
				readingKey = true
				readingNumericValue = false
			}
		case '\\': // escape \ in text per JSON requirements
			result = append(result, '\\', '\\')
		default:
			isDigitChar := (text[index] >= '0' && text[index] <= '9') || text[index] == '.'
			if !isDigitChar {
				readingNumericValue = false
			}
			result = append(result, text[index])
		}
		index++
	}
	if readingInterfaces {
		if !readingNumericValue {
			result = append(result, '"')
		}
		result = append(result, '}', ']')
	}
	result = append(result, '}')
	return result
}

func skipSpaces(index int, text []byte) int {
	for index < (len(text) - 1) {
		if text[index+1] == ' ' || text[index+1] == '\t' {
			index++
		} else {
			return index
		}
	}
	return index
}

// TestGetCapinfos tests GetCapinfos
func TestGetCapinfos(t *testing.T) {
	testInput := []byte(`File name:           /Users/rj/Documents/large.pcapng
File type:           Wireshark/... - pcapng
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: (not set)
Number of packets:   193073
File size:           212040036 bytes
Data size:           205473952 bytes
Capture duration:    33.597593 seconds
First packet time:   2019-03-26 17:18:03.284989
Last packet time:    2019-03-26 17:18:36.882582
Data byte rate:      6115734.33 bytes/sec
Data bit rate:       48925874.67 bits/sec
Average packet size: 1064.23 bytes
Average packet rate: 5746.63 packets/sec
SHA256:              ef36510ba24689e38609c5b85d977f9c88d7decb70c563547af8c0b34db28612
RIPEMD160:           f479beebce2d0ccb537d76e8d4d343eb6218b5b7
SHA1:                6e113443e9d47d4a73c645581296b8ef32072eed
Strict time order:   True
Capture hardware:    Intel(R) Core(TM) i7-4770HQ CPU @ 2.20GHz (with SSE4.2)
Capture oper-sys:    Mac OS X 10.14.3, build 18D109 (Darwin 18.2.0)
Capture application: Dumpcap (Wireshark) 3.0.0 (v3.0.0-0-g937e33de)
Number of interfaces in file: 2
Interface #0 info:
                      Name = en0
                      Description = Wi-Fi
                      Encapsulation = Ethernet (1 - ether)
                      Capture length = 524288
                      Time precision = microseconds (6)
                      Time ticks per second = 1000000
                      Time resolution = 0x06
                      Operating system = Mac OS X 10.14.3, build 18D109 (Darwin 18.2.0)
                      Number of stat entries = 1
                      Number of packets = 193073
Interface #1 info:
                      Encapsulation = Cisco HDLC (28 - chdlc)
                      Capture length = 8192
                      Time precision = microseconds (6)
                      Time ticks per second = 1000000
                      Number of stat entries = 0
					  Number of packets = 38
`)
	expected := []byte(`{"FileName":"/Users/rj/Documents/large.pcapng","FileType":"Wireshark/... - pcapng","FileEncapsulation":"Ethernet","FileTimestampPrecision":"microseconds (6)","PacketSizeLimit":"file hdr: (not set)","NumberOfPackets":193073,"FileSize":212040036,"DataSize":205473952,"CaptureDuration":33.597593,"FirstPacketTime":"2019-03-26 17:18:03.284989","LastPacketTime":"2019-03-26 17:18:36.882582","DataByteRate":6115734.33,"DataBitRate":48925874.67,"AveragePacketSize":1064.23,"AveragePacketRate":5746.63,"SHA256":"ef36510ba24689e38609c5b85d977f9c88d7decb70c563547af8c0b34db28612","RIPEMD160":"f479beebce2d0ccb537d76e8d4d343eb6218b5b7","SHA1":"6e113443e9d47d4a73c645581296b8ef32072eed","StrictTimeOrder":"True","CaptureHardware":"Intel(R) Core(TM) i7-4770HQ CPU @ 2.20GHz (with SSE4.2)","CaptureOper-sys":"Mac OS X 10.14.3, build 18D109 (Darwin 18.2.0)","CaptureApplication":"Dumpcap (Wireshark) 3.0.0 (v3.0.0-0-g937e33de)","NumberOfInterfacesInFile":2,"Interfaces":[{"Name":"en0","Description":"Wi-Fi","Encapsulation":"Ethernet (1 - ether)","CaptureLength":524288,"TimePrecision":"microseconds (6)","TimeTicksPerSecond":1000000,"TimeResolution":"0x06","OperatingSystem":"Mac OS X 10.14.3, build 18D109 (Darwin 18.2.0)","NumberOfStatEntries":1,"NumberOfPackets":19307},{"Encapsulation":"Cisco HDLC (28 - chdlc)","CaptureLength":8192,"TimePrecision":"microseconds (6)","TimeTicksPerSecond":1000000,"NumberOfStatEntries":0,"NumberOfPackets":38}]}`)
	actual := capinfos2JSON(testInput)
	assert.Equal(t, expected, actual, "These should be the same.")
}
