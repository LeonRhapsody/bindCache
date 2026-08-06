package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestIncrementIP(t *testing.T) {
	// 测试正常的 IP 递增
	ip1 := net.ParseIP("192.168.1.1").To4()
	next1 := incrementIP(ip1)
	if next1.String() != "192.168.1.2" {
		t.Errorf("incrementIP(192.168.1.1) 预期 192.168.1.2, 实际得到 %s", next1.String())
	}

	// 测试跨网段的 IP 递增 (例如 192.168.1.255 到 192.168.2.0)
	ip2 := net.ParseIP("192.168.1.255").To4()
	next2 := incrementIP(ip2)
	if next2.String() != "192.168.2.0" {
		t.Errorf("incrementIP(192.168.1.255) 预期 192.168.2.0, 实际得到 %s", next2.String())
	}
}

func TestCompareIP(t *testing.T) {
	ip1 := net.ParseIP("192.168.1.1").To4()
	ip2 := net.ParseIP("192.168.1.2").To4()
	ip3 := net.ParseIP("192.168.1.1").To4()

	if compareIP(ip1, ip2) >= 0 {
		t.Errorf("compareIP(192.168.1.1, 192.168.1.2) 预期返回负数")
	}
	if compareIP(ip2, ip1) <= 0 {
		t.Errorf("compareIP(192.168.1.2, 192.168.1.1) 预期返回正数")
	}
	if compareIP(ip1, ip3) != 0 {
		t.Errorf("compareIP(192.168.1.1, 192.168.1.1) 预期返回 0")
	}
}

func TestReadAndIsInIPRanges(t *testing.T) {
	// 创建临时网段映射文件
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test_vip.txt")

	content := "192.168.1.0/24 ClassA\n10.0.0.1-10.0.0.3 ClassB\n"
	err := os.WriteFile(tempFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("写临时测试文件失败: %v", err)
	}

	ipRanges, clientMap, err := readIPRanges(tempFile)
	if err != nil {
		t.Fatalf("readIPRanges 失败: %v", err)
	}

	// 验证解析的 IP 范围数量
	// 192.168.1.0/24 是一个 CIDR
	// 10.0.0.1-10.0.0.3 是 3 个 IP 地址
	if len(ipRanges) != 4 {
		t.Errorf("预期解析到 4 个 IP 范围/地址, 实际得到 %d", len(ipRanges))
	}

	// 验证包含关系测试
	tests := []struct {
		ip           string
		expectFound  bool
		expectClient string
	}{
		{"192.168.1.50", true, "ClassA"},
		{"192.168.2.1", false, ""},
		{"10.0.0.2", true, "ClassB"},
		{"10.0.0.4", false, ""},
	}

	for _, tt := range tests {
		found, client := isInIPRanges(tt.ip, &clientMap)
		if found != tt.expectFound || client != tt.expectClient {
			t.Errorf("isInIPRanges(%s) 预期 (found: %v, client: %s), 实际得到 (found: %v, client: %s)",
				tt.ip, tt.expectFound, tt.expectClient, found, client)
		}
	}
}
