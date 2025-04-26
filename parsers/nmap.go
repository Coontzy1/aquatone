package parsers

import (
	"io"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/shelld3v/aquatone/core"
	"github.com/lair-framework/go-nmap"
)

type NmapParser struct {
	allowedPorts map[int]bool
}

func NewNmapParser(ports string) *NmapParser {
	parser := &NmapParser{
		allowedPorts: make(map[int]bool),
	}

	// Parse the ports string (example: "80,443,8080") into a map[int]bool
	if ports != "" {
		portsSlice := strings.Split(ports, ",")
		for _, portStr := range portsSlice {
			port, err := strconv.Atoi(strings.TrimSpace(portStr))
			if err == nil {
				parser.allowedPorts[port] = true
			}
		}
	} else {
		parser.allowedPorts = nil // No filtering if no ports provided
	}

	return parser
}

func (p *NmapParser) Parse(r io.Reader) ([]string, error) {
	var targets []string
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		return targets, err
	}
	scan, err := nmap.Parse(bytes)
	if err != nil {
		return targets, err
	}

	for _, host := range scan.Hosts {
		urls := p.hostToURLs(host)
		for _, url := range urls {
			targets = append(targets, url)
		}
	}

	return targets, nil
}

func (p *NmapParser) hostToURLs(host nmap.Host) []string {
	var urls []string
	for _, port := range host.Ports {
		if port.State.State != "open" {
			continue
		}

		// Check allowed ports if filtering is active
		if p.allowedPorts != nil {
			if !p.allowedPorts[port.PortId] {
				continue // Port not allowed
			}
		}

		var protocol string
		if port.Protocol == "tcp" {
			if port.Service.Tunnel == "ssl" || port.Service.Name == "https" {
				protocol = "https"
			} else {
				protocol = "http"
			}
		} else {
			continue
		}

		if len(host.Hostnames) > 0 {
			for _, hostname := range host.Hostnames {
				urls = append(urls, core.HostAndPortToURL(hostname.Name, port.PortId, protocol))
			}
		}
		for _, address := range host.Addresses {
			if address.AddrType == "mac" {
				continue
			}
			urls = append(urls, core.HostAndPortToURL(address.Addr, port.PortId, protocol))
		}
	}

	return urls
}

