package beater

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"time"
	//"unicode"
)

var (
	//device       string = "\\Device\\NPF_{F0C8EAAE-E1FB-45F2-B0A1-6236EEADE5EE}"
	device string = "veth1"
	//device       string = "enp2s0f0"
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	//timeout      time.Duration = 1 * time.Second
	timeout time.Duration = 10 * time.Microsecond
	//timeout      time.Duration = 10 * time.Nanosecond
	handle      *pcap.Handle
	packetCount int = 0
)

const channleNum = 8

var channels [channleNum]chan []byte
var clients [channleNum]beat.Client

func capture(b *beat.Beat, endSignal chan struct{}) {

	for i := 0; i < channleNum; i++ {
		//var err error
		channels[i] = make(chan []byte, 1000)
		clients[i], _ = b.Publisher.Connect()
		go decodeAndPublish(channels[i], clients[i])
	}

	go caponline()

	for {
		select {
		case <-endSignal:
			for i := 0; i < channleNum; i++ {
				close(channels[i])
				clients[i].Close()
			}
		}
	}
}

func caponline() {

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	i := 0
	for {
		//packetData,ci,err := handle.ReadPacketData()
		//packetData,ci,_ := handle.ReadPacketData()
		packetData, ci, _ := handle.ZeroCopyReadPacketData()
		if err != nil {
			continue
		}

		//if ci.CaptureLength <= 0 {
		//	continue
		//}
		//
		//channels[i] <- packetData
		//i=i+1
		//if i==channleNum  {
		//	i=0
		//	//break
		//}

		// 14 eth, 40 IPv6 header, 8 UDP
		//起码要大于：  14+40+8+8+4+40+2+2+12=130字节
		if ci.CaptureLength > 130 {
			pdata := make([]byte, ci.CaptureLength)
			copy(pdata, packetData)
			channels[i] <- pdata
			i++
			if i == channleNum {
				i = 0
			}
		}

		// Only capture 100 and then stop
		//if packetCount > 100 {
		//	break
		//}
	}

}

func packetHandler(packetDataChannel chan []byte) {

	var (
		ethLayer layers.Ethernet
		ipLayer  layers.IPv4
		ip6Layer layers.IPv6
		tcpLayer layers.TCP
		udpLayer layers.UDP
	)
	//Unfortunately, not all layers can be used by DecodingLayerParser... only those implementing the DecodingLayer interface are usable.
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer, &ip6Layer, &tcpLayer, &udpLayer)
	decoded := []gopacket.LayerType{}

	for packetData := range packetDataChannel {
		if err := parser.DecodeLayers(packetData, &decoded); err != nil {
			fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
		}
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				fmt.Println("    IP6 ", len(packetData), ip6Layer.SrcIP, ip6Layer.DstIP)
			case layers.LayerTypeIPv4:
				//fmt.Println("    IP4 ", len(*packetData),  ipLayer.SrcIP, ipLayer.DstIP)
				//fmt.Println("    IP4 ", len(packetData))
				//fmt.Printf("%p\n",&packetData)
				//rawBytes := []byte{10, 20, 30}
				packetData = append(packetData, byte(10))
				fmt.Println("    IP4 ", len(packetData))
				fmt.Printf("%p\n", &packetData)
			}
		}

		packetCount++
		fmt.Println(packetCount)
	}

}

func packetHandler1(packetDataChannel chan []byte) {

	var (
		ethLayer layers.Ethernet
		ipLayer  layers.IPv4
		ip6Layer layers.IPv6
		//tcpLayer layers.TCP
		udpLayer layers.UDP
	)

	dlp := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet)
	dlp.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
	//var eth layers.Ethernet
	dlp.AddDecodingLayer(&ethLayer)
	dlp.AddDecodingLayer(&ipLayer)
	dlp.AddDecodingLayer(&ip6Layer)
	//dlp.AddDecodingLayer(&tcpLayer)
	dlp.AddDecodingLayer(&udpLayer)
	// ... add layers and use DecodingLayerParser as usual...

	//Unfortunately, not all layers can be used by DecodingLayerParser... only those implementing the DecodingLayer interface are usable.
	//parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer, &ip6Layer, &tcpLayer,&udpLayer)
	decoded := []gopacket.LayerType{}

	for packetData := range packetDataChannel {
		if err := dlp.DecodeLayers(packetData, &decoded); err != nil {
			fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
			fmt.Println(len(packetData))
		}
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				fmt.Println("    IP6 ", len(packetData), ip6Layer.SrcIP, ip6Layer.DstIP)
			case layers.LayerTypeUDP:
				//fmt.Println("    IP6 ",len(packetData), ip6Layer.SrcIP, ip6Layer.DstIP)
				fmt.Println("capture UDP")
				fmt.Println("    IP4 ", len(packetData), udpLayer.SrcPort, udpLayer.DstPort)
				packetCount++
				fmt.Println(packetCount)
			}
		}

		//packetCount++
		//fmt.Println(packetCount)
	}

}

func packetHandler2(packetDataChannel chan []byte, client beat.Client) {
	//defer client.Close()

	var (
		ethLayer layers.Ethernet
		ipLayer  layers.IPv4
		ip6Layer layers.IPv6
		//tcpLayer layers.TCP
		udpLayer layers.UDP
	)

	dlp := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet)
	dlp.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
	//var eth layers.Ethernet
	dlp.AddDecodingLayer(&ethLayer)
	dlp.AddDecodingLayer(&ipLayer)
	dlp.AddDecodingLayer(&ip6Layer)
	//dlp.AddDecodingLayer(&tcpLayer)
	dlp.AddDecodingLayer(&udpLayer)
	// ... add layers and use DecodingLayerParser as usual...

	//Unfortunately, not all layers can be used by DecodingLayerParser... only those implementing the DecodingLayer interface are usable.
	//parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer, &ip6Layer, &tcpLayer,&udpLayer)
	decoded := []gopacket.LayerType{}

	for packetData := range packetDataChannel {
		if err := dlp.DecodeLayers(packetData, &decoded); err != nil {
			fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
			fmt.Println(len(packetData))
		}
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				fmt.Println("    IP6 ", len(packetData), ip6Layer.SrcIP, ip6Layer.DstIP)
				//case layers.LayerTypeIPv4:
				//	fmt.Println("    IP4 ", len(packetData),  ipLayer.SrcIP, ipLayer.DstIP)
				//	//fmt.Println("    IP4 ", len(packetData))
				//	//fmt.Printf("%p\n",&packetData)
				//	//rawBytes := []byte{10, 20, 30}
				//	//packetData=append(packetData, byte(10))
				//	//fmt.Println("    IP4 ", len(packetData))
				//	//fmt.Printf("%p\n",&packetData)
				//packetCount++
				//fmt.Println(packetCount)
			case layers.LayerTypeUDP:
				//fmt.Println("    IP6 ",len(packetData), ip6Layer.SrcIP, ip6Layer.DstIP)
				fmt.Println("capture UDP")
				//fmt.Println("    IP4 ", len(packetData),  udpLayer.SrcPort,udpLayer.DstPort)
				//case layers.LayerTypeIPv4:
				//	fmt.Println("    IP4 ", len(packetData),  ipLayer.SrcIP, ipLayer.DstIP)
				//	//fmt.Println("    IP4 ", len(packetData))
				//	//fmt.Printf("%p\n",&packetData)
				//	//rawBytes := []byte{10, 20, 30}
				//	//packetData=append(packetData, byte(10))
				//	//fmt.Println("    IP4 ", len(packetData))
				//	//fmt.Printf("%p\n",&packetData)

				event := beat.Event{
					Timestamp: time.Now(),
					Fields: common.MapStr{
						"counter": packetCount,
					},
				}

				fields := event.Fields
				udpEvent := common.MapStr{}
				fields["udpRelated"] = udpEvent

				udpEvent["dpSrcPort"] = udpLayer.SrcPort
				udpEvent["udpDstPort"] = udpLayer.DstPort

				client.Publish(event)
				packetCount++
				fmt.Println(packetCount)
			}
		}

		//packetCount++
		//fmt.Println(packetCount)
	}

}

func packetHandler3(packetDataChannel chan []byte, client beat.Client) {

	var (
		ethLayer layers.Ethernet
		//ipLayer  layers.IPv4
		ip6Layer layers.IPv6
		//tcpLayer layers.TCP
		udpLayer layers.UDP
	)

	dlp := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet)
	dlp.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
	//var eth layers.Ethernet
	dlp.AddDecodingLayer(&ethLayer)
	//dlp.AddDecodingLayer(&ipLayer)
	dlp.AddDecodingLayer(&ip6Layer)
	//dlp.AddDecodingLayer(&tcpLayer)
	dlp.AddDecodingLayer(&udpLayer)
	// ... add layers and use DecodingLayerParser as usual...

	//Unfortunately, not all layers can be used by DecodingLayerParser... only those implementing the DecodingLayer interface are usable.
	//parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer, &ip6Layer, &tcpLayer,&udpLayer)
	decoded := []gopacket.LayerType{}

	event := beat.Event{
		Timestamp: time.Now(),
		Fields: common.MapStr{
			"counter": packetCount,
		},
	}
	fields := event.Fields

	for packetData := range packetDataChannel {
		//if err := dlp.DecodeLayers(packetData, &decoded); err != nil {
		//	//fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
		//	//fmt.Println(len(packetData))
		////	当前是什么也不做。应该是遇到不能解析的layer的时候会报错。这个应该是很常见吧。
		//}
		//不用去管哪些解析不了的layer.因为我们只提供了3种DecodingLayer。
		dlp.DecodeLayers(packetData, &decoded)

		//开始处理每个数据包的时候，要先清空掉上一个数据包里的数据。
		event.Timestamp = time.Now()
		fields["counter"] = packetCount

		udpEvent := common.MapStr{}
		fields["udpRelated"] = udpEvent

		for _, layerType := range decoded {

			switch layerType {
			case layers.LayerTypeIPv6:
				fmt.Println("    IP6 ", len(packetData), ip6Layer.SrcIP, ip6Layer.DstIP)
			case layers.LayerTypeUDP:
				//fmt.Println("    IP6 ",len(packetData), ip6Layer.SrcIP, ip6Layer.DstIP)
				fmt.Println("capture UDP")
				//这是读取已经解码的结果。
				//udpEvent["udpSrcPort"] =udpLayer.SrcPort
				//udpEvent["udpDstPort"] =udpLayer.DstPort
				//这是直接解码
				udpEvent["udpSrcPort"] = uint16(packetData[55]) | uint16(packetData[54])<<8
				//下面用现成的函数
				//udpEvent["udpSrcPort"],_,_ =unpackUint16(packetData,54)
				udpEvent["udpDstPort"], _, _ = unpackUint16(packetData, 56)
				//udpEvent["udpSrcPort"] = uint32(packetData[54:56])
				//下面的做法是错误的。原本是1234，会变成4,210
				//udpEvent["udpDstPort"] =  packetData[56:58]
			}
		}

		client.Publish(event)

		packetCount++

		//packetCount++
		//fmt.Println(packetCount)
	}

}

func decodeAndPublish(packetDataChannel chan []byte, client beat.Client) {

	event := beat.Event{
		Timestamp: time.Now(),
		Fields: common.MapStr{
			"counter": packetCount,
		},
	}
	fields := event.Fields

	for packetData := range packetDataChannel {

		if !bytes.Equal(packetData[12:14], []byte{0x86, 0xdd}) {
			//说明不是IPv6的数据包。0x86DD是网际协议v6 （IPv6，Internet Protocol version 6）
			continue
		}
		if int(packetData[20]) != 17 {
			//next header=17是UDP包。不是的话，说明不是UDP的数据包
			continue
		}
		if  !bytes.Equal(packetData[54:58],[]byte{0x0d,0x80,0x04,0xd2})  {
			//UDP的源端口是3456且目的端口是1234的包才是INT over IPv6上的包
			continue
		}

		//开始处理每个数据包的时候，要先清空掉上与一个数据包相关的event里的数据。
		event.Timestamp = time.Now()
		fields["counter"] = packetCount

		//telemetry group header的解析
		// 0                   1                   2                   3
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//| Ver   | hw_id     |                           Sequence Number |
		//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//|                         Node ID                               |
		//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		tghEvent := common.MapStr{}
		fields["telemetryGroupHeader"] = tghEvent

		tghEvent["version"] = packetData[62]>>4
		tghEvent["hw_id"] =(packetData[62]<<2 & 0x3C) & (packetData[63]>>6 & 0x03)


		udpEvent := common.MapStr{}
		fields["udpRelated"] = udpEvent

		//这是直接解码
		udpEvent["udpSrcPort"] = uint16(packetData[55]) | uint16(packetData[54])<<8
		//下面用现成的函数
		//udpEvent["udpSrcPort"],_,_ =unpackUint16(packetData,54)
		udpEvent["udpDstPort"], _, _ = unpackUint16(packetData, 56)

		//udpEvent["udpSrcPort"] = uint32(packetData[54:56])
		//下面的做法是错误的。原本是1234，会变成4,210
		//udpEvent["udpDstPort"] =  packetData[56:58]

		client.Publish(event)

		packetCount++

		//packetCount++
		//fmt.Println(packetCount)
	}

}

const (
	headerSize = 12

	// Header.Bits
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
	_Z  = 1 << 6  // Z
	_AD = 1 << 5  // authticated data
	_CD = 1 << 4  // checking disabled
)

// setHdr set the header in the dns using the binary data in dh.
//func (dns *Msg) setHdr(dh Header) {
//	dns.Id = dh.Id
//	dns.Response = dh.Bits&_QR != 0
//	dns.Opcode = int(dh.Bits>>11) & 0xF
//	dns.Authoritative = dh.Bits&_AA != 0
//	dns.Truncated = dh.Bits&_TC != 0
//	dns.RecursionDesired = dh.Bits&_RD != 0
//	dns.RecursionAvailable = dh.Bits&_RA != 0
//	dns.Zero = dh.Bits&_Z != 0 // _Z covers the zero bit, which should be zero; not sure why we set it to the opposite.
//	dns.AuthenticatedData = dh.Bits&_AD != 0
//	dns.CheckingDisabled = dh.Bits&_CD != 0
//	dns.Rcode = int(dh.Bits & 0xF)
//}

// Error represents a DNS error.
type Error struct{ err string }

func (e *Error) Error() string {
	if e == nil {
		return "dns: <nil>"
	}
	return "dns: " + e.err
}

func unpackUint16(msg []byte, off int) (i uint16, off1 int, err error) {
	if off+2 > len(msg) {
		return 0, len(msg), &Error{err: "overflow unpacking uint16"}
	}
	return binary.BigEndian.Uint16(msg[off:]), off + 2, nil
}

//func decodeIntFromByte(pkt []byte){
//
//}
