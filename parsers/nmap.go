package parsers

import (
	"fmt"
	"io"
	"io/ioutil"

	nmap "github.com/lair-framework/go-nmap"
)

// NmapParser parses an Nmap XML and returns one URL per host+port.
type NmapParser struct {
	showDefaultPorts bool
}

// NewNmapParser drops any port‐filtering string and only honors
// the showDefaultPorts boolean.
func NewNmapParser(_ string, showDefaultPorts bool) *NmapParser {
	return &NmapParser{showDefaultPorts: showDefaultPorts}
}

// Parse reads all <port> entries from the XML and returns
// URLs for each IPv4+port tuple.
func (p *NmapParser) Parse(r io.Reader) ([]string, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	scan, err := nmap.Parse(data)
	if err != nil {
		return nil, err
	}

	var targets []string
	for _, host := range scan.Hosts {
		for _, u := range p.hostToURLs(host) {
			targets = append(targets, u)
		}
	}
	return targets, nil
}

// hostToURLs builds a URL for every TCP port on a host,
// using both hostnames and IPv4 addresses.
func (p *NmapParser) hostToURLs(host nmap.Host) []string {
	var urls []string
	for _, port := range host.Ports {
		// Only TCP
		if port.Protocol != "tcp" {
			continue
		}
		// Decide http vs https
		scheme := "http"
		if port.Service.Tunnel == "ssl" || port.Service.Name == "https" {
			scheme = "https"
		}
		// Hostnames first
		for _, h := range host.Hostnames {
			urls = append(urls, p.buildURL(scheme, h.Name, port.PortId))
		}
		// Then IPv4 addresses
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				urls = append(urls, p.buildURL(scheme, addr.Addr, port.PortId))
			}
		}
	}
	return urls
}

// buildURL formats the URL and omits the default port
// if showDefaultPorts is false.
func (p *NmapParser) buildURL(scheme, host string, port int) string {
	// drop :80 for http or :443 for https if flag is false
	if !p.showDefaultPorts &&
		((scheme == "http" && port == 80) ||
			(scheme == "https" && port == 443)) {
		return fmt.Sprintf("%s://%s/", scheme, host)
	}
	return fmt.Sprintf("%s://%s:%d/", scheme, host, port)
}

