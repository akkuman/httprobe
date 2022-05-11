package iprange

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

var (
	ErrTargetFormat = errors.New("error target format")
)

func GetAllIP(target string) ([]net.IP, error) {
	var ips []net.IP
	var subTargets []string
	if strings.Contains(target, ",") {
		for _, sub := range strings.Split(target, ",") {
			subTargets = append(subTargets, strings.TrimSpace(sub))
		}
	} else {
		subTargets = append(subTargets, strings.TrimSpace(target))
	}
	for _, sub := range subTargets {
		ips_, err := parseIPTarget(sub)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ips_...)
	}
	return ips, nil
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

// https://gist.github.com/kotakanbe/d3059af990252ba89a82
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// https://gist.github.com/kotakanbe/d3059af990252ba89a82
func GetAllIPFromCIDR(cidr string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for ip_ := ip.Mask(ipnet.Mask); ipnet.Contains(ip_); inc(ip_) {
		ipString := ip_.String()
		newIP := net.ParseIP(ipString)
		ips = append(ips, newIP.To4())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

func parseIPTarget(target string) ([]net.IP, error) {
	var subTargets []string
	var ips []net.IP
	var err error
	target = strings.TrimSpace(target)
	if strings.Contains(target, "-") {
		subTargets = strings.Split(target, "-")
		if len(subTargets) != 2 {
			return nil, ErrTargetFormat
		}
		startIP := strings.TrimSpace(subTargets[0])
		endIP := strings.TrimSpace(subTargets[1])
		startIP_ := net.ParseIP(startIP)
		if startIP_ == nil {
			return nil, ErrTargetFormat
		}
		startIPSplit := strings.Split(startIP, ".")
		endIPSplit := strings.Split(endIP, ".")
		var endIPResult = make([]string, 4)
		copy(endIPResult, startIPSplit[:len(startIPSplit)-len(endIPSplit)])
		copy(endIPResult[len(startIPSplit)-len(endIPSplit):], endIPSplit)
		// endIPResult = append(endIPResult, endIPSplit...)
		endIP = strings.Join(endIPResult, ".")
		endIP_ := net.ParseIP(endIP)
		if endIP_ == nil {
			return nil, ErrTargetFormat
		}
		startIPInt := ip2int(startIP_)
		endIPInt := ip2int(endIP_)
		if startIPInt > endIPInt {
			return nil, ErrTargetFormat
		}
		for i := startIPInt; i <= endIPInt; i++ {
			ips = append(ips, int2ip(i))
		}
		return ips, nil
	} else if strings.Contains(target, "/") {
		ips, err = GetAllIPFromCIDR(target)
		if err != nil {
			return nil, ErrTargetFormat
		}
		return ips, nil
	} else {
		ip := net.ParseIP(target)
		if ip == nil {
			return nil, ErrTargetFormat
		}
		ips = append(ips, ip)
		return ips, nil
	}
}