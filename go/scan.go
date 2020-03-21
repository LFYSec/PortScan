package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type TCPHeader struct {
	SrcPort       uint16
	DstPort       uint16
	SeqNum        uint32
	AckNum        uint32
	Flags         uint16
	Window        uint16
	ChkSum        uint16
	UrgentPointer uint16
}
type scanResult struct {
	Port uint16
}
type scanJob struct {
	Laddr string
	Raddr string
	SPort uint16
	DPort uint16
	Stop  bool
}

var (
	TimeOut    *int
	LAddr      string
	RAddr      string
	ScanWay    *string
	StopChan   = make(chan bool, 1)
	CommonPort = []uint16{20, 21, 22, 23, 25, 37, 47, 53, 67, 68, 69, 80, 106, 109, 110, 111, 135, 137, 138, 139, 143, 144, 161, 389, 443, 445, 458, 545, 548, 554, 631, 875, 1080, 1227, 1433, 1434, 1494, 1521, 1604, 1723, 1755, 1758, 2601, 2604, 3128, 3306, 3389, 4000, 4440, 4848, 5000, 5010, 5190, 5631, 5632, 5666, 5800, 5801, 5900, 5901, 6000, 6379, 6667, 7000, 7001, 7002, 7007, 7070, 8000, 8009, 8383, 8080, 9000, 9043, 9200, 11211, 26000, 27001, 27010, 27015, 27960, 50060}
	// TODO use hashmap to show what service the port is
	vis = make([]bool, 65535)
)

func main() {
	jobs := make(chan *scanJob, 65536)
	results := make(chan *scanResult, 1000)
	for w := 0; w < 50; w++ {
		go consumer(jobs, results)
	}

	targetIP := flag.String("r", "", "remote address")
	portRange := flag.String("p", "common", "port range like -p 1-1024")
	ScanWay = flag.String("w", "SYN", "scanning way, like TCP、SYN、FIN")
	TimeOut = flag.Int("t", 3, "timeout")
	flag.Parse()

	if *targetIP == "" {
		fmt.Println("Must input target")
		os.Exit(0)
	}

	sTime := time.Now().Unix()
	LAddr = getLAddr()
	RAddr = *targetIP

	if *ScanWay == "SYN" {
		go func(num int) {
			for i := 0; i < num; i++ {
				recvSynAck(results)
			}
		}(10)
	}

	if *portRange == "common" {
		go producer(jobs, 0, 0)
	} else {
		SPort, DPort := portSplit(portRange)
		go producer(jobs, SPort, DPort)
	}

	for {
		select {
		case res := <-results:
			fmt.Println("Open: ", res.Port)
		case <-StopChan:
			eTime := time.Now().Unix()
			fmt.Println("Time: ", eTime-sTime, "s")
			os.Exit(0)
		}
	}
}

func producer(jobs chan *scanJob, SPort, DPort uint16) {
	if SPort == 0 && DPort == 0 {
		for _, p := range CommonPort {
			s := scanJob{
				Laddr: LAddr,
				Raddr: RAddr,
				SPort: uint16(random(10000, 65535)),
				DPort: p,
			}
			jobs <- &s
		}
	} else {
		for p := SPort; p <= DPort; p++ {
			s := scanJob{
				Laddr: LAddr,
				Raddr: RAddr,
				SPort: uint16(random(10000, 65535)),
				DPort: p,
			}
			jobs <- &s
		}
	}
	jobs <- &scanJob{Stop: true}
	close(jobs)
}

func consumer(jobs <-chan *scanJob, results chan<- *scanResult) {
	for {
		if j, ok := <-jobs; ok {
			if j.Stop == true {
				time.Sleep(time.Duration(*TimeOut) * time.Second)
				StopChan <- true
			} else if *ScanWay == "SYN" {
				SynScan(j)
				time.Sleep(1e7)
			} else if *ScanWay == "TCP" {
				TcpScan(j, results)
			}
		}
	}
}

func TcpScan(j *scanJob, result chan<- *scanResult) {
	target := fmt.Sprintf("%s:%d", j.Raddr, j.DPort)
	conn, err := net.DialTimeout("tcp", target, time.Duration(*TimeOut)*time.Second)
	if err == nil {
		result <- &scanResult{
			Port: j.DPort,
		}
		defer conn.Close()
	}
}

func SynScan(j *scanJob) {
	conn, err := net.Dial("ip4:tcp", j.Raddr)
	checkError(err)
	defer conn.Close()
	tcpH := TCPHeader{
		SrcPort:       j.SPort,
		DstPort:       j.DPort,
		SeqNum:        rand.Uint32(),
		AckNum:        0,
		Flags:         0x8002,
		Window:        8192,
		ChkSum:        0,
		UrgentPointer: 0,
	}
	buff := new(bytes.Buffer)
	err = binary.Write(buff, binary.BigEndian, tcpH)
	checkError(err)
	err = binary.Write(buff, binary.BigEndian, [12]byte{})
	checkError(err)
	data := buff.Bytes()
	checkSum := CheckSum(data, ip2Bytes(j.Laddr), ip2Bytes(j.Raddr))
	tcpH.ChkSum = checkSum
	buff = new(bytes.Buffer)
	err = binary.Write(buff, binary.BigEndian, tcpH)
	checkError(err)
	err = binary.Write(buff, binary.BigEndian, [12]byte{})
	checkError(err)
	data = buff.Bytes()
	_, err = conn.Write(data)
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		log.Println(err)
	}
}

func CheckSum(data []byte, src, dst [4]byte) uint16 {
	pseudoHeader := []byte{
		src[0], src[1], src[2], src[3],
		dst[0], dst[1], dst[2], dst[3],
		0,
		6,
		0,
		byte(len(data)),
	}
	totalLength := len(pseudoHeader) + len(data)
	if totalLength%2 != 0 {
		totalLength++
	}
	d := make([]byte, 0, totalLength)
	d = append(d, pseudoHeader...)
	d = append(d, data...)
	return ^mySum(d)
}

func mySum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(uint16(data[i])<<8 | uint16(data[i+1]))
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return uint16(sum)
}

func recvSynAck(res chan<- *scanResult) {
	listenAddr, err := net.ResolveIPAddr("ip4", LAddr) // 解析域名为ip
	checkError(err)
	conn, err := net.ListenIP("ip4:tcp", listenAddr)
	defer conn.Close()
	checkError(err)
	for {
		buff := make([]byte, 1024)
		_, addr, err := conn.ReadFrom(buff)
		if err != nil {
			continue
		}

		if addr.String() != RAddr || buff[13] != 0x12 {
			continue
		}
		var port uint16
		err = binary.Read(bytes.NewReader(buff), binary.BigEndian, &port)
		checkError(err)

		if vis[port] {
			continue
		}
		res <- &scanResult{
			Port: port,
		}
		vis[port] = true
	}
}

func ip2Bytes(addr string) [4]byte {
	s := strings.Split(addr, ".")
	b0, _ := strconv.Atoi(s[0])
	b1, _ := strconv.Atoi(s[1])
	b2, _ := strconv.Atoi(s[2])
	b3, _ := strconv.Atoi(s[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}

func random(min, max int) int {
	return rand.Intn(max-min) + min
}

func getLAddr() string {
	var iface *net.Interface
	var err error
	var f int
	if runtime.GOOS == "darwin" {
		f = 1
		iface, err = net.InterfaceByName("en0")
	} else if runtime.GOOS == "linux" {
		f = 0
		iface, err = net.InterfaceByName("eth0")
	} else {
		panic("Unsupported os")
	}
	checkError(err)
	addr, err := iface.Addrs()
	checkError(err)

	addrStr := strings.Split(addr[f].String(), "/")[0]
	return addrStr
}

func portSplit(portRange *string) (uint16, uint16) {
	ports := strings.Split(*portRange, "-")
	minPort, err := strconv.ParseUint(ports[0], 10, 16)
	if err != nil {
		panic(err)
	}
	maxPort, err := strconv.ParseUint(ports[1], 10, 16)
	if err != nil {
		panic(err)
	}
	if minPort > maxPort {
		panic(errors.New("minPort must bigger than maxPort"))
	}
	return uint16(minPort), uint16(maxPort)
}
