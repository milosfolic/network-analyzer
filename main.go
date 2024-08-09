package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var (
	iface        string
	protocol     string
	saveToFile   string
	displayDNS   bool
	displayHTTP  bool
	packetTable  table.Writer
	packetRows   [][]interface{}
	packetLimit  int
	updatePeriod time.Duration
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "netanalyzer",
		Short: "Network Analyzer Tool",
		Run: func(cmd *cobra.Command, args []string) {
			setupTable()
			analyze(iface, protocol, saveToFile, displayDNS, displayHTTP)
		},
	}

	rootCmd.Flags().StringVarP(&iface, "interface", "i", "en0", "Network interface to listen on")
	rootCmd.Flags().StringVarP(&protocol, "protocol", "p", "all", "Protocol to filter (all, tcp, udp)")
	rootCmd.Flags().StringVarP(&saveToFile, "save", "s", "", "File to save captured packets (PCAP format)")
	rootCmd.Flags().BoolVarP(&displayDNS, "dns", "d", false, "Display DNS queries")
	rootCmd.Flags().BoolVarP(&displayHTTP, "http", "t", false, "Display HTTP requests")
	rootCmd.Flags().IntVarP(&packetLimit, "limit", "l", 20, "Limit the number of displayed rows in the table")
	rootCmd.Flags().DurationVarP(&updatePeriod, "update-period", "u", 5*time.Second, "Time period for updating the table")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

func setupTable() {
	packetTable = table.NewWriter()
	packetTable.SetOutputMirror(os.Stdout)
	packetTable.AppendHeader(table.Row{
		"Protocol", "Src IP", "Dst IP", "Src Port", "Dst Port", "DNS Query", "DNS Response", "HTTP Method", "HTTP URL", "HTTP Host",
	})
	packetTable.SetStyle(table.StyleRounded)
	packetTable.Style().Options.SeparateRows = true
}

func analyze(iface, protocol, _ string, displayDNS, displayHTTP bool) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	ticker := time.NewTicker(updatePeriod)
	defer ticker.Stop()

	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			if protocol != "all" && !filterByProtocol(packet, protocol) {
				continue
			}
			analyzePacket(packet, displayDNS, displayHTTP)

			if len(packetRows) > packetLimit {
				packetRows = packetRows[1:]
			}

		case <-ticker.C:
			updateTable()
		}
	}
}

func filterByProtocol(packet gopacket.Packet, protocol string) bool {
	switch protocol {
	case "tcp":
		return packet.Layer(layers.LayerTypeTCP) != nil
	case "udp":
		return packet.Layer(layers.LayerTypeUDP) != nil
	default:
		return true
	}
}

func analyzePacket(packet gopacket.Packet, displayDNS, displayHTTP bool) {
	var srcIP, dstIP, srcPort, dstPort, protocol, dnsQuery, dnsResponse, httpMethod, httpURL, httpHost string

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		protocol = "TCP"
		srcPort = fmt.Sprintf("%d", tcp.SrcPort)
		dstPort = fmt.Sprintf("%d", tcp.DstPort)
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		protocol = "UDP"
		srcPort = fmt.Sprintf("%d", udp.SrcPort)
		dstPort = fmt.Sprintf("%d", udp.DstPort)
	}

	if displayDNS {
		dnsQuery, dnsResponse = checkForDNS(packet)
	}

	if displayHTTP {
		httpMethod, httpURL, httpHost = checkForHTTP(packet)
	}

	packetRows = append(packetRows, []interface{}{
		protocol, srcIP, dstIP, srcPort, dstPort, dnsQuery, dnsResponse, httpMethod, httpURL, httpHost,
	})
}

func checkForDNS(packet gopacket.Packet) (string, string) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return "", ""
	}
	udp, _ := udpLayer.(*layers.UDP)

	if udp.SrcPort != 53 && udp.DstPort != 53 {
		return "", ""
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return "", ""
	}
	dns, _ := dnsLayer.(*layers.DNS)

	var dnsQuery, dnsResponse string
	for _, query := range dns.Questions {
		dnsQuery = string(query.Name)
	}

	if dns.QR {
		for _, answer := range dns.Answers {
			dnsResponse = answer.IP.String()
		}
	}

	return dnsQuery, dnsResponse
}

func checkForHTTP(packet gopacket.Packet) (string, string, string) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return "", "", ""
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	if tcp.DstPort != 80 && tcp.DstPort != 8080 && tcp.SrcPort != 80 && tcp.SrcPort != 8080 {
		return "", "", ""
	}

	payload := string(tcp.Payload)
	if strings.Contains(payload, "HTTP") {
		lines := strings.Split(payload, "\r\n")
		if len(lines) > 0 {
			requestLine := strings.Fields(lines[0])
			if len(requestLine) >= 3 {
				method := requestLine[0]
				url := requestLine[1]
				var host string
				for _, line := range lines {
					if strings.HasPrefix(line, "Host:") {
						host = strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
						break
					}
				}
				return method, url, host
			}
		}
	}

	return "", "", ""
}

func updateTable() {
	packetTable.ResetRows()

	for _, row := range packetRows {
		packetTable.AppendRow(row)
	}

	packetTable.Render()
}
