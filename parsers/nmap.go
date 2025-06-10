package parsers

import (
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/lair-framework/go-nmap"
)

type NmapParser struct {
	allowedPorts     map[int]bool
	showDefaultPorts bool
}

func NewNmapParser(ports string, showDefaultPorts bool) *NmapParser {
	parser := &NmapParser{
		allowedPorts:     make(map[int]bool),
		showDefaultPorts: showDefaultPorts,
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
				urls = append(urls, p.buildURL(protocol, hostname.Name, port.PortId))
			}
		}
		for _, address := range host.Addresses {
			if address.AddrType == "mac" {
				continue
			}
			urls = append(urls, p.buildURL(protocol, address.Addr, port.PortId))
		}
	}
	return urls
}

func (p *NmapParser) buildURL(protocol, host string, port int) string {
	if (!p.showDefaultPorts) && 
	   ((protocol == "http" && port == 80) || (protocol == "https" && port == 443)) {
		return fmt.Sprintf("%s://%s/", protocol, host)
	}
	return fmt.Sprintf("%s://%s:%d/", protocol, host, port)
}
