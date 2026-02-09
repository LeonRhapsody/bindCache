package main

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// 读取 IP 地址段文件，返回 IP 范围列表
func readIPRanges(filename string) ([]net.IPNet, map[string][]net.IPNet, error) {
	var ipRanges []net.IPNet
	map1 := make(map[string][]net.IPNet)

	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		s1 := strings.Split(line, " ")
		client := s1[len(s1)-1]
		ip1 := s1[0]

		_, ipNet, err := net.ParseCIDR(ip1)
		if err != nil {
			ips := strings.Split(ip1, "-")
			if len(ips) != 2 {
				continue
			}
			startIP := net.ParseIP(strings.TrimSpace(ips[0]))
			endIP := net.ParseIP(strings.TrimSpace(ips[1]))

			// 将起始 IP 地址和结束 IP 地址之间的每个 IP 地址都添加到 IP 范围列表中
			for ip := startIP; compareIP(ip, endIP) <= 0; ip = incrementIP(ip) {
				map1[client] = append(map1[client], net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
				ipRanges = append(ipRanges, net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
			}
		} else {
			map1[client] = append(map1[client], *ipNet)
			ipRanges = append(ipRanges, *ipNet)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	return ipRanges, map1, nil
}

// 增加 IP 地址
func incrementIP(ip net.IP) net.IP {
	nextIP := make(net.IP, len(ip))
	copy(nextIP, ip)

	for i := len(nextIP) - 1; i >= 0; i-- {
		nextIP[i]++
		if nextIP[i] > 0 {
			break
		}
	}

	return nextIP
}

// 比较两个 IP 地址
func compareIP(ip1, ip2 net.IP) int {
	for i := 0; i < len(ip1) && i < len(ip2); i++ {
		if ip1[i] != ip2[i] {
			return int(ip1[i]) - int(ip2[i])
		}
	}
	return len(ip1) - len(ip2)
}

// 判断 IP 是否在 IP 范围内
func isInIPRanges(ip string, map1 *map[string][]net.IPNet) (bool, string) {
	ipAddr := net.ParseIP(ip)
	for client, value := range *map1 {
		for _, ipNet := range value {
			if ipNet.Contains(ipAddr) {
				return true, client
			}
		}
	}
	return false, ""
}
