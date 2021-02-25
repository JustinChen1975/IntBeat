package beater

import (
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
	device       string = "veth1"
	//device       string = "enp2s0f0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	//timeout      time.Duration = 1 * time.Second
	timeout      time.Duration = 10 * time.Microsecond
	//timeout      time.Duration = 10 * time.Nanosecond
	handle       *pcap.Handle
	packetCount int = 0
)

const channleNum  = 8

var  channels [channleNum] chan []byte
var  clients [channleNum] beat.Client

func capture(b *beat.Beat, endSignal  chan  struct{}) {

	for i := 0; i < channleNum; i++ {
		//var err error
		channels[i] = make(chan []byte,1000)
		clients[i], _ = b.Publisher.Connect()
		//go packetHandler(channels[i])
		//go packetHandler1(channels[i])
		go packetHandler2(channels[i],clients[i])
	}

	go  caponline()

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


func caponline()  {

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	i :=0
	for  {
		//packetData,ci,err := handle.ReadPacketData()
		//packetData,ci,_ := handle.ReadPacketData()
		packetData,ci,_ := handle.ZeroCopyReadPacketData()
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

		//fmt.Println(ci)
		//fmt.Println(&packetData)
		//fmt.Printf("ID=%s,  %p\n",cc,&(& packetData))
		// 14 eth, 40 IPv6 header, 8 UDP
		if ci.CaptureLength >62   {
			pdata := make([]byte, ci.CaptureLength)
			copy(pdata,packetData)
			channels[i] <- pdata
			i++
			if i==channleNum  {
				i=0
			}
		}

		// Only capture 100 and then stop
		//if packetCount > 100 {
		//	break
		//}
	}

}

func packetHandler(packetDataChannel chan []byte){

	var (
		ethLayer layers.Ethernet
		ipLayer  layers.IPv4
		ip6Layer  layers.IPv6
		tcpLayer layers.TCP
		udpLayer layers.UDP
	)
	//Unfortunately, not all layers can be used by DecodingLayerParser... only those implementing the DecodingLayer interface are usable.
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer, &ip6Layer, &tcpLayer,&udpLayer)
	decoded := []gopacket.LayerType{}

	for packetData :=range packetDataChannel {
		if err := parser.DecodeLayers(packetData, &decoded); err != nil {
			fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
		}
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				fmt.Println("    IP6 ",len(packetData), ip6Layer.SrcIP, ip6Layer.DstIP)
			case layers.LayerTypeIPv4:
				//fmt.Println("    IP4 ", len(*packetData),  ipLayer.SrcIP, ipLayer.DstIP)
				//fmt.Println("    IP4 ", len(packetData))
				//fmt.Printf("%p\n",&packetData)
				//rawBytes := []byte{10, 20, 30}
				packetData=append(packetData, byte(10))
				fmt.Println("    IP4 ", len(packetData))
				fmt.Printf("%p\n",&packetData)
			}
		}

		packetCount++
		fmt.Println(packetCount)
	}

}

func packetHandler1(packetDataChannel chan []byte){

	var (
		ethLayer layers.Ethernet
		ipLayer  layers.IPv4
		ip6Layer  layers.IPv6
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

	for packetData :=range packetDataChannel {
		if err := dlp.DecodeLayers(packetData, &decoded); err != nil {
			fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
			fmt.Println(len(packetData))
		}
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				fmt.Println("    IP6 ",len(packetData), ip6Layer.SrcIP, ip6Layer.DstIP)
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
				fmt.Println("    IP4 ", len(packetData),  udpLayer.SrcPort,udpLayer.DstPort)
				//case layers.LayerTypeIPv4:
				//	fmt.Println("    IP4 ", len(packetData),  ipLayer.SrcIP, ipLayer.DstIP)
				//	//fmt.Println("    IP4 ", len(packetData))
				//	//fmt.Printf("%p\n",&packetData)
				//	//rawBytes := []byte{10, 20, 30}
				//	//packetData=append(packetData, byte(10))
				//	//fmt.Println("    IP4 ", len(packetData))
				//	//fmt.Printf("%p\n",&packetData)
				packetCount++
				fmt.Println(packetCount)
			}
		}

		//packetCount++
		//fmt.Println(packetCount)
	}

}


func packetHandler2(packetDataChannel chan []byte,client beat.Client){
	//defer client.Close()

	var (
		ethLayer layers.Ethernet
		ipLayer  layers.IPv4
		ip6Layer  layers.IPv6
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

	for packetData :=range packetDataChannel {
		if err := dlp.DecodeLayers(packetData, &decoded); err != nil {
			fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
			fmt.Println(len(packetData))
		}
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				fmt.Println("    IP6 ",len(packetData), ip6Layer.SrcIP, ip6Layer.DstIP)
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
						"udpSrcPort":    udpLayer.SrcPort,
						"udpDstPort":    udpLayer.DstPort,
						"counter": packetCount,
					},
				}
				client.Publish(event)
				packetCount++
				fmt.Println(packetCount)
			}
		}

		//packetCount++
		//fmt.Println(packetCount)
	}

}

func decodeIntFromByte(pkt []byte){

}





