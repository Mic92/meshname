package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gologme/log"

	"github.com/zhoreeq/meshname/pkg/meshname"
)

func ipv6ToArpaDomain(ipNet net.IPNet) (string, error) {
	// Ensure the IP is an IPv6 address
	if ipNet.IP.To4() != nil {
		return "", fmt.Errorf("not an IPv6 address")
	}

	// Convert IP to a slice of bytes
	ipBytes := ipNet.IP.To16()

	// Determine the number of full bytes to include based on the subnet mask
	maskSize, _ := ipNet.Mask.Size()
	bytesToInclude := maskSize / 8

	// Reverse the order of nibbles for the included bytes and format as a string
	var arpaDomain strings.Builder
	for i := bytesToInclude*2 - 1; i >= 0; i-- {
		byteIndex := i / 2
		nibble := ipBytes[byteIndex]

		if i%2 == 0 {
			nibble >>= 4
		} else {
			nibble &= 0x0F
		}

		arpaDomain.WriteString(fmt.Sprintf("%x.", nibble))
	}

	// Add the standard suffix for IPv6 reverse DNS
	arpaDomain.WriteString("ip6.arpa")

	return arpaDomain.String(), nil
}

func parseNetworks(networksconf string) (map[string]*net.IPNet, map[string]string, error) {
	networks := make(map[string]*net.IPNet)
	reverseIps := make(map[string]string)
	for _, item := range strings.Split(networksconf, ",") {
		if tokens := strings.SplitN(item, "=", 2); len(tokens) == 2 {
			if _, validSubnet, err := net.ParseCIDR(tokens[1]); err == nil {
				networks[tokens[0]] = validSubnet
				domain, err := ipv6ToArpaDomain(*validSubnet)
				if err != nil {
					return nil, nil, fmt.Errorf("invalid subnet: %s: %s", tokens[1], err)
				}
				reverseIps[domain] = tokens[0]
			} else {
				return nil, nil, err
			}
		}
	}
	return networks, reverseIps, nil
}

var (
	listenAddr, networksconf string
	getName, getIP           string
	debug                    bool
)

func init() {
	flag.StringVar(&listenAddr, "listenaddr", "[::1]:53535", "address to listen on")
	flag.StringVar(&networksconf, "networks", "ygg=200::/7,cjd=fc00::/8,meshname=::/0,popura=::/0", "TLD=subnet list separated by comma")
	flag.StringVar(&getName, "getname", "", "convert IPv6 address to a name")
	flag.StringVar(&getIP, "getip", "", "convert a name to IPv6 address")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
}

func main() {
	flag.Parse()

	logger := log.New(os.Stdout, "", log.Flags())

	logger.EnableLevel("error")
	logger.EnableLevel("warn")
	logger.EnableLevel("info")
	if debug {
		logger.EnableLevel("debug")
	}

	if getName != "" {
		ip := net.ParseIP(getName)
		if ip == nil {
			logger.Fatal("Invalid IP address")
		}
		subDomain := meshname.DomainFromIP(&ip)
		fmt.Println(subDomain)
		return
	} else if getIP != "" {
		ip, err := meshname.IPFromDomain(&getIP)
		if err != nil {
			logger.Fatal(err)
		}
		fmt.Println(ip)
		return
	}

	networks, reverseIps, err := parseNetworks(networksconf)
	if err != nil {
		logger.Fatalln(err)
	}

	s := meshname.New(logger, listenAddr, networks, reverseIps)

	if err := s.Start(); err != nil {
		logger.Fatal(err)
	}
	logger.Infoln("Listening on:", listenAddr)

	c := make(chan os.Signal, 1)
	r := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	signal.Notify(r, os.Interrupt, syscall.SIGHUP)
	defer s.Stop()
	for {
		select {
		case <-c:
			return
		}
	}
}
