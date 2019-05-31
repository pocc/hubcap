package pcap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// GetCapinfos creates a json out of capinfos output
func GetCapinfos(filename string, shouldFix bool) (map[string]interface{}, error) {
	cmd := exec.Command("capinfos", "-M", filename)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	cmd.Run()
	stderrStr := string(stderr.Bytes())
	willFix := shouldFix && strings.Contains(stderrStr, "cut short in the middle")
	switch {
	case willFix:
		fixPcap(filename)
	case !bytes.Equal([]byte(stderrStr), []byte("")):
		// This is not a fatal error because it's ok if some files are not read
		capinfosErr := fmt.Errorf("\033[93mWARN\033[0m " + stderrStr)
		errorResult := make(map[string]interface{})
		errorResult[filename] = "File not found"
		return errorResult, capinfosErr
	case bytes.Equal(stdout.Bytes(), []byte("")):
		fmt.Println("\033[91mERROR\033[0m FATAL: No output received from capinfos for file", filename,
			"\nThis usually means that there are too many goroutines.",
			"\nCurrent number of goroutines:", runtime.NumGoroutine())
		os.Exit(1)
	}

	ciJSON := capinfos2JSON(stdout.Bytes())
	return JSON2Struct(ciJSON), nil
}

// JSON2Struct converts a capinfos struct to a JSON
func JSON2Struct(text []byte) map[string]interface{} {
	pcapInfo := map[string]interface{}{}
	err := json.Unmarshal(text, &pcapInfo)
	if err != nil {
		fmt.Println("Failed to structify", string(text), "\nERROR:", err)
		os.Exit(1)
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
						fmt.Println("Unknown interface:", string(result))
						os.Exit(1)
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
