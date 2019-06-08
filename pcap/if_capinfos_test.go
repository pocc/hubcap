package pcap

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestGetCapinfos tests GetCapinfos
func TestGetCapinfos(t *testing.T) {
	testInput := []byte(`File type:           Wireshark/... - pcapng
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
	expected := []byte("{\"FileType\":\"Wireshark/... - pcapng\",\"FileEncapsulation\":\"Ethernet\",\"FileTimestampPrecision\":\"microseconds (6)\",\"PacketSizeLimit\":\"file hdr: (not set)\",\"NumberOfPackets\":193073,\"FileSize\":212040036,\"DataSize\":205473952,\"CaptureDuration\":33.597593,\"FirstPacketTime\":\"2019-03-26 17:18:03.284989\",\"LastPacketTime\":\"2019-03-26 17:18:36.882582\",\"DataByteRate\":6115734.33,\"DataBitRate\":48925874.67,\"AveragePacketSize\":1064.23,\"AveragePacketRate\":5746.63,\"SHA256\":\"ef36510ba24689e38609c5b85d977f9c88d7decb70c563547af8c0b34db28612\",\"RIPEMD160\":\"f479beebce2d0ccb537d76e8d4d343eb6218b5b7\",\"SHA1\":\"6e113443e9d47d4a73c645581296b8ef32072eed\",\"StrictTimeOrder\":\"True\",\"CaptureHardware\":\"Intel(R) Core(TM) i7-4770HQ CPU @ 2.20GHz (with SSE4.2)\",\"CaptureOper-sys\":\"Mac OS X 10.14.3, build 18D109 (Darwin 18.2.0)\",\"CaptureApplication\":\"Dumpcap (Wireshark) 3.0.0 (v3.0.0-0-g937e33de)\",\"NumberOfInterfacesInFile\":2,\"Interfaces\":[{\"Name\":\"en0\",\"Description\":\"Wi-Fi\",\"Encapsulation\":\"Ethernet (1 - ether)\",\"CaptureLength\":524288,\"TimePrecision\":\"microseconds (6)\",\"TimeTicksPerSecond\":1000000,\"TimeResolution\":\"0x06\",\"OperatingSystem\":\"Mac OS X 10.14.3, build 18D109 (Darwin 18.2.0)\",\"NumberOfStatEntries\":1,\"NumberOfPackets\":193073},{\"Encapsulation\":\"Cisco HDLC (28 - chdlc)\",\"CaptureLength\":8192,\"TimePrecision\":\"microseconds (6)\",\"TimeTicksPerSecond\":1000000,\"NumberOfStatEntries\":0,\"NumberOfPackets\":38}]}")
	actual := capinfos2JSON(testInput)
	assert.Equal(t, string(expected), string(actual), "These should be the same.")
}
