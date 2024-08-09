package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"
)

var (
	protocol         string
	saveToFile       string
	displayDNS       bool
	displayHTTP      bool
	packetLimit      int
	updatePeriod     time.Duration
	ifaces           []string
	showSummaryStats bool
	packetTable      *tview.Table
	packetRows       [][]interface{}
	totalPacketCount int
	tcpCount         int
	udpCount         int
	icmpCount        int
	arpCount         int
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "netanalyzer",
		Short: "Network Analyzer Tool",
		Run: func(cmd *cobra.Command, args []string) {
			setupTable()

			var interfaces []pcap.Interface
			var err error

			if len(ifaces) == 0 {
				interfaces, err = pcap.FindAllDevs()
				if err != nil {
					log.Fatal(err)
				}
			} else {
				interfaces, err = getSpecifiedInterfaces(ifaces)
				if err != nil {
					log.Fatal(err)
				}
			}

			for _, iface := range interfaces {
				go analyze(iface.Name, protocol, displayDNS, displayHTTP)
			}

			go updateTablePeriodically()

			// Start the TUI application
			app := tview.NewApplication()
			if err := app.SetRoot(packetTable, true).Run(); err != nil {
				log.Fatal(err)
			}
		},
	}

	rootCmd.Flags().StringVarP(&protocol, "protocol", "p", "all", "Protocol to filter (all, tcp, udp)")
	rootCmd.Flags().StringVarP(&saveToFile, "save", "s", "", "File to save captured packets (PCAP format)")
	rootCmd.Flags().BoolVarP(&displayDNS, "dns", "d", false, "Display DNS queries and responses")
	rootCmd.Flags().BoolVarP(&displayHTTP, "http", "t", false, "Display HTTP requests")
	rootCmd.Flags().IntVarP(&packetLimit, "limit", "l", 20, "Limit the number of displayed rows in the table")
	rootCmd.Flags().DurationVarP(&updatePeriod, "update-period", "u", 2*time.Second, "Time period for updating the table")
	rootCmd.Flags().StringSliceVarP(&ifaces, "interfaces", "i", nil, "List of network interfaces to capture from (comma-separated). It listens on all by default")
	rootCmd.Flags().BoolVarP(&showSummaryStats, "summary", "m", false, "Show summary statistics")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

func setupTable() {
	packetTable = tview.NewTable()
	packetTable.SetFixed(1, 0).SetSelectable(true, false).SetBorder(true).SetTitle("Network Analyzer").SetTitleAlign(tview.AlignCenter)

	// Set header cells with a basic color code (e.g., 11 for yellow)
	packetTable.SetCell(0, 0, tview.NewTableCell("Interface").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 1, tview.NewTableCell("Protocol").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 2, tview.NewTableCell("Src IP").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 3, tview.NewTableCell("Dst IP").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 4, tview.NewTableCell("Src Port").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 5, tview.NewTableCell("Dst Port").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 6, tview.NewTableCell("DNS Query").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 7, tview.NewTableCell("DNS Response").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 8, tview.NewTableCell("HTTP Method").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 9, tview.NewTableCell("HTTP URL").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 10, tview.NewTableCell("HTTP Host").SetAlign(tview.AlignCenter).SetTextColor(11))
}

func getSpecifiedInterfaces(ifaceNames []string) ([]pcap.Interface, error) {
	var interfaces []pcap.Interface
	allInterfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	for _, iface := range allInterfaces {
		for _, name := range ifaceNames {
			if iface.Name == name {
				interfaces = append(interfaces, iface)
			}
		}
	}

	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no matching interfaces found")
	}

	return interfaces, nil
}

func analyze(iface, protocol string, displayDNS, displayHTTP bool) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		if packet == nil {
			continue
		}
		if protocol != "all" && !filterByProtocol(packet, protocol) {
			continue
		}
		analyzePacket(packet, iface, displayDNS, displayHTTP)

		// Limit the number of displayed rows
		if len(packetRows) > packetLimit {
			packetRows = packetRows[1:]
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

func analyzePacket(packet gopacket.Packet, iface string, displayDNS, displayHTTP bool) {
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

		if displayHTTP {
			httpMethod, httpURL, httpHost = checkForHTTP(packet)
		}
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		protocol = "UDP"
		srcPort = fmt.Sprintf("%d", udp.SrcPort)
		dstPort = fmt.Sprintf("%d", udp.DstPort)

		if displayDNS {
			dnsQuery, dnsResponse = checkForDNS(packet)
		}
	}

	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer != nil {
		protocol = "ICMP"
		icmpCount++
	}

	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		protocol = "ARP"
		arpCount++
	}

	packetRows = append(packetRows, []interface{}{
		iface, protocol, srcIP, dstIP, srcPort, dstPort, dnsQuery, dnsResponse, httpMethod, httpURL, httpHost,
	})

	totalPacketCount++
	if protocol == "TCP" {
		tcpCount++
	} else if protocol == "UDP" {
		udpCount++
	}
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
	if dns.QDCount > 0 {
		dnsQuery = string(dns.Questions[0].Name) // Convert []byte to string
	}
	if dns.ANCount > 0 {
		dnsResponse = dns.Answers[0].IP.String()
	}

	return dnsQuery, dnsResponse
}

func checkForHTTP(packet gopacket.Packet) (string, string, string) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return "", "", ""
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	payload := string(tcp.Payload)
	if len(payload) > 0 && tcp.DstPort == 80 {
		if strings.HasPrefix(payload, "GET ") || strings.HasPrefix(payload, "POST ") || strings.HasPrefix(payload, "PUT ") || strings.HasPrefix(payload, "DELETE ") {
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
	}

	return "", "", ""
}

func updateTablePeriodically() {
	ticker := time.NewTicker(updatePeriod)
	defer ticker.Stop()

	for range ticker.C {
		updateTable()
	}
}

func updateTable() {
	packetTable.Clear()

	// Set header cells with a basic color code (e.g., 11 for yellow)
	packetTable.SetCell(0, 0, tview.NewTableCell("Interface").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 1, tview.NewTableCell("Protocol").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 2, tview.NewTableCell("Src IP").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 3, tview.NewTableCell("Dst IP").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 4, tview.NewTableCell("Src Port").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 5, tview.NewTableCell("Dst Port").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 6, tview.NewTableCell("DNS Query").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 7, tview.NewTableCell("DNS Response").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 8, tview.NewTableCell("HTTP Method").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 9, tview.NewTableCell("HTTP URL").SetAlign(tview.AlignCenter).SetTextColor(11))
	packetTable.SetCell(0, 10, tview.NewTableCell("HTTP Host").SetAlign(tview.AlignCenter).SetTextColor(11))

	// Populate table with packet data
	for i, row := range packetRows {
		for j, cell := range row {
			packetTable.SetCell(i+1, j, tview.NewTableCell(fmt.Sprintf("%v", cell)).SetAlign(tview.AlignCenter))
		}
	}

	// Show summary statistics if enabled
	if showSummaryStats {
		packetTable.SetCell(len(packetRows)+1, 0, tview.NewTableCell(fmt.Sprintf("Total Packets: %d", totalPacketCount)).SetAlign(tview.AlignLeft))
		packetTable.SetCell(len(packetRows)+2, 0, tview.NewTableCell(fmt.Sprintf("TCP Packets: %d", tcpCount)).SetAlign(tview.AlignLeft))
		packetTable.SetCell(len(packetRows)+3, 0, tview.NewTableCell(fmt.Sprintf("UDP Packets: %d", udpCount)).SetAlign(tview.AlignLeft))
		packetTable.SetCell(len(packetRows)+4, 0, tview.NewTableCell(fmt.Sprintf("ICMP Packets: %d", icmpCount)).SetAlign(tview.AlignLeft))
		packetTable.SetCell(len(packetRows)+5, 0, tview.NewTableCell(fmt.Sprintf("ARP Packets: %d", arpCount)).SetAlign(tview.AlignLeft))
	}

	packetTable.ScrollToEnd()
}
