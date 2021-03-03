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
	"net"
	"os"
	"strconv"
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

				//这是直接解码
				//udpEvent["udpSrcPort"] = uint16(packetData[55]) | uint16(packetData[54])<<8
				//udpEvent["udpSrcPort"] = binary.BigEndian.Uint16(packetData[54:])

				//下面用现成的函数
				//udpEvent["udpSrcPort"],_,_ =unpackUint16(packetData,54)
				//udpEvent["udpDstPort"] = binary.BigEndian.Uint16(packetData[56:])

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

		//下面的这些12，14，20等后面应该改动为offset比较合理，程序能具有更强的通用性。
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
		}else {
			fields["INT port"] = common.MapStr{
				"udpSrcPort" : binary.BigEndian.Uint16(packetData[54:]),
				"udpDstPort" : binary.BigEndian.Uint16(packetData[56:]),
			}
		}

		//开始处理每个数据包的时候，要先清空掉上与一个数据包相关的event里的数据。
		event.Timestamp = time.Now()
		//event.Fields["counter"] = packetCount
		fields["counter"] = packetCount

		//开始对telemetry group header的解析
		// 0                   1                   2                   3
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//| Ver   | hw_id     |                           Sequence Number |
		//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//|                         Node ID                               |
		//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		fields["telemetryGroupHeader"] =common.MapStr{
			"version": packetData[62]>>4,
			"hw_id": (binary.BigEndian.Uint16(packetData[62:])>>6 ) & 0x003F,
			"sequenceNumber": (binary.BigEndian.Uint32(packetData[62:])) & 0x003FFFFF,
			"nodeId": NodeToString(binary.BigEndian.Uint32(packetData[66:])),
		}


		//开始对Individual Report Header进行解释
		//Report Lenght的长度单位是4个字节
		// 0                   1                   2                   3
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//|RepType| InType| Report Length |     MD Length |D|Q|F|I| Rsvd  |
		repType := packetData[70]>>4
		//reportLength和mdLength的长度单位都是4字节，所以要左移2位才能转换为字节
		reportLength := uint16(packetData[71]) <<2
		inType := packetData[70] & 0x0F
		mdLength := uint16(packetData[72]) <<2

		//目前只对Inner Only类型以及IPv6封装的进行处理
		if (repType !=0) || (inType!=5) {
			continue
		}

		//When the RepType value is Inner Only, then the Individual Report Main Contents is empty.
		//MD Length should be set to zero upon transmission, and ignored upon reception.
		if (repType ==0) && (mdLength!=0) {
			continue
		}

		//以太网报头+IPv6报头+UDP报头+TelemetryReportHeader+Individual Report Header +（原始的IPv6报头+… )
		//= 14+40+8+8+4+（40+…）=74+…
		//如果reportLength不对，就不予以处理
		if reportLength+74 != uint16(len(packetData))  {
			continue
		}

		fields["individualReportHeader"] = common.MapStr{
			//"RepType": repType,
			"RepType": RepTypeToString(repType),
			"InType": InnerTypeToString(inType),
			//"ReportLength": reportLength,
			//"MDLength": mdLength,
			"D:Dropped" : packetData[73]&_L7 != 0,
			"Q:Congested Queue Association" : packetData[73]&_L6 != 0,
			"F:Tracked Flow Association" : packetData[73]&_L5 != 0,
			"I:Intermediate Report" : packetData[73]&_L4 != 0,
		}

		//开始处理原始的IPv6头的信息
		//从[74]字节开始
		//TODO：其它的等后面处理。
		offset :=74
		fields["originalIPv6"] = common.MapStr{
			"srcIPv6Addr": net.IP{
				packetData[offset+8],
				packetData[offset+9],
				packetData[offset+10],
				packetData[offset+11],
				packetData[offset+12],
				packetData[offset+13],
				packetData[offset+14],
				packetData[offset+15],
				packetData[offset+16],
				packetData[offset+17],
				packetData[offset+18],
				packetData[offset+19],
				packetData[offset+20],
				packetData[offset+21],
				packetData[offset+22],
				packetData[offset+23],}.String(),
			"dstIPv6Addr": net.IP{
				packetData[offset+24],
				packetData[offset+25],
				packetData[offset+26],
				packetData[offset+27],
				packetData[offset+28],
				packetData[offset+29],
				packetData[offset+30],
				packetData[offset+31],
				packetData[offset+32],
				packetData[offset+33],
				packetData[offset+34],
				packetData[offset+35],
				packetData[offset+36],
				packetData[offset+37],
				packetData[offset+38],
				packetData[offset+39],}.String(),
		}



		client.Publish(event)
		packetCount++
	}
}

const (
	NoneInnertype = iota
	TlvInnertype
	DomainspecificextensiondataInnertype
	EthernetInnertype
	Ipv4Innertype
	Ipv6Innertype
)

var InnerTypeForString = map[uint8]string{
	NoneInnertype:                        "None",
	TlvInnertype:                         "TLV",
	DomainspecificextensiondataInnertype: "DomainSpecificExtensionData",
	EthernetInnertype:                    "Ethernet",
	Ipv4Innertype:                        "IPv4",
	Ipv6Innertype:                        "IPv6",
}

func InnerTypeToString(innerType uint8) string {
	s, exists := InnerTypeForString[innerType]
	if !exists {
		return strconv.FormatUint(uint64(innerType),10)
	}
	return s
}

const (
	InnerOnly_RepType = iota     //InnerOnly_RepType=0
	INT_RepType
	IOAM_RepType
)

var RepTypeForString = map[uint8]string{
	InnerOnly_RepType: "Inner Only",
	INT_RepType: "INT",
	IOAM_RepType: "IOAM",
}

func RepTypeToString(repType uint8) string {
	s, exists := RepTypeForString[repType]
	if !exists {
		return strconv.FormatUint(uint64(repType),10)
	}
	return s
}

var NodeForString = map[uint32]string{
	25174435: "R1",
	25174436: "R2",
	25174437: "R3",
	25174438: "R4",
	25174439: "R5",
	25174440: "R6",
}

func NodeToString(opCode uint32) string {
	s, exists := NodeForString[opCode]
	if !exists {
		return strconv.FormatUint(uint64(opCode),10)
	}
	return s
}


const (
	_L7 = 1 << 7
	_L6 = 1 << 6
	_L5 = 1 << 5
	_L4 = 1 << 4
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

//func unpackUint32(msg []byte, off int) (i uint32, off1 int, err error) {
//	if off+4 > len(msg) {
//		return 0, len(msg), &Error{err: "overflow unpacking uint32"}
//	}
//	return binary.BigEndian.Uint32(msg[off:]), off + 4, nil
//}

//func decodeIntFromByte(pkt []byte){
//
//}
