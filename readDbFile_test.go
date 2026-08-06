package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLine_Normal(t *testing.T) {
	p := NewParser()
	p.inCache = true

	// 测试元数据 view 设置
	p.parseLine("Cache dump of view 'external'")
	if p.view != "external" {
		t.Errorf("预期 view 为 'external', 实际得到: %s", p.view)
	}

	// 测试 $DATE 导入
	p.parseLine("$DATE 20260623100000")
	if p.date != "20260623100000" {
		t.Errorf("预期 date 为 '20260623100000', 实际得到: %s", p.date)
	}

	// 设置属性注释
	p.parseLine("; authanswer")
	if p.currentAttribute != "authanswer" {
		t.Errorf("预期 currentAttribute 为 'authanswer', 实际得到: %s", p.currentAttribute)
	}

	// 测试正常的 A 记录解析
	p.parseLine("example.com. 3600 A 192.168.1.100")
	record, exists := p.records["example.com."]
	if !exists {
		t.Fatalf("未找到域 example.com. 的解析记录")
	}
	if len(record.As) != 1 || record.As[0].IP != "192.168.1.100" || record.As[0].TTL != 3600 {
		t.Errorf("A 记录解析不正确: %+v", record.As)
	}

	// 测试缩进格式记录解析
	p.parseLine("\t3600 AAAA 2001:db8::1")
	record = p.records["example.com."]
	if len(record.AAAAs) != 1 || record.AAAAs[0].IP != "2001:db8::1" || record.AAAAs[0].TTL != 3600 {
		t.Errorf("缩进格式 AAAA 记录解析不正确: %+v", record.AAAAs)
	}

	// 测试 TXT 记录解析（多单词 TXT 包含空格）
	p.parseLine("\t600 TXT \"v=spf1 include:_spf.google.com ~all\"")
	record = p.records["example.com."]
	if len(record.TXTs) != 1 || record.TXTs[0].Content != "\"v=spf1 include:_spf.google.com ~all\"" {
		t.Errorf("TXT 记录解析不正确: %+v", record.TXTs)
	}
}

func TestParseLine_NegativeCache(t *testing.T) {
	p := NewParser()
	p.inCache = true
	p.currentAttribute = "authauthority"

	// 测试否定缓存 (NXDOMAIN)
	p.parseLine("nonexistent.com. 300 -A ;-$nxdomain")
	record, exists := p.records["nonexistent.com."]
	if !exists {
		t.Fatalf("未找到 nonexistent.com. 的解析记录")
	}
	if len(record.As) != 1 || record.As[0].Rcode != "nxdomain" {
		t.Errorf("否定缓存 A 记录解析不正确: %+v", record.As)
	}
	if _, existsInNx := p.nxdomainRecords["nonexistent.com."]; !existsInNx {
		t.Errorf("未在 nxdomainRecords 列表中找到对应记录")
	}

	// 测试否定缓存 (NXRRSET)
	p.parseLine("example.com. 300 -AAAA ;-$nxrrset")
	record, exists = p.records["example.com."]
	if !exists {
		t.Fatalf("未找到 example.com. 的解析记录")
	}
	if len(record.AAAAs) != 1 || record.AAAAs[0].Rcode != "nxrrset" {
		t.Errorf("否定缓存 AAAA 记录解析不正确: %+v", record.AAAAs)
	}
	if _, existsInNxrr := p.nxrrsetRecords["example.com."]; !existsInNxrr {
		t.Errorf("未在 nxrrsetRecords 列表中找到对应记录")
	}
}

func TestParseLine_MultiLine(t *testing.T) {
	p := NewParser()
	p.inCache = true

	// 模拟多行 RRSIG 或者 TYPE65 记录
	p.parseLine("example.com. 3600 RRSIG A 8 2 3600 20260723100000 (")
	if !p.inMultiLine {
		t.Errorf("预期进入多行状态模式")
	}
	p.parseLine("\t\t20260623100000 12345 example.com.")
	p.parseLine("\t\tbase64signaturesignature= )")

	if p.inMultiLine {
		t.Errorf("预期退出多行状态模式")
	}

	record, exists := p.records["example.com."]
	if !exists {
		t.Fatalf("未找到 example.com. 的解析记录")
	}
	if len(record.RRSIGs) != 1 {
		t.Fatalf("多行 RRSIG 记录数不匹配")
	}
	sig := record.RRSIGs[0]
	if sig.SignerName != "example.com." {
		t.Errorf("RRSIG 签名者名称解析错误: %s", sig.SignerName)
	}
}

func TestParseDNSCacheFile(t *testing.T) {
	// 创建临时的 BIND 快照文本文件
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "cache_dump_test.db")

	mockContent := `
; Cache dump of view 'external'
$DATE 20260623120000
; authanswer
testdomain.com. 1800 NS ns1.testdomain.com.
; answer
ns1.testdomain.com. 1800 A 1.2.3.4
; glue
sub.testdomain.com. 1800 -A ;-$nxrrset
`
	err := os.WriteFile(tempFile, []byte(mockContent), 0644)
	if err != nil {
		t.Fatalf("写入临时测试快照文件失败: %v", err)
	}

	bindCache, err := ParseDNSCacheFile(tempFile)
	if err != nil {
		t.Fatalf("ParseDNSCacheFile 失败: %v", err)
	}

	if bindCache.View != "external" || bindCache.Date != "20260623120000" {
		t.Errorf("元数据解析错误: view=%s, date=%s", bindCache.View, bindCache.Date)
	}

	if len(bindCache.records) != 3 {
		t.Errorf("解析域名数不正确, 预期 3, 实际: %d", len(bindCache.records))
	}

	// 校验 nxrrset
	if len(bindCache.nxrrsetRecords) != 1 {
		t.Errorf("否定缓存 (NXRRSET) 记录数不匹配, 预期 1, 实际: %d", len(bindCache.nxrrsetRecords))
	}
}

func TestParseADBLineSupportsFiveFieldEDNSCounters(t *testing.T) {
	parser := NewParser()
	parser.parseLine("; Address database dump")
	parser.parseLine("; ns1.example. [v4 TTL 120] [v4 success]")
	parser.parseLine(";\t192.0.2.53 [srtt 181080] [flags 00004000] [edns 9/4/3/2/1] [plain 5/6] [udpsize 1232] [ttl 120]")
	if len(parser.adbRecords) != 1 {
		t.Fatalf("ADB records = %d, want 1", len(parser.adbRecords))
	}
	record := parser.adbRecords[0]
	if record.Name != "ns1.example." || record.IP != "192.0.2.53" || record.SRTT != 181080 {
		t.Fatalf("ADB 基础字段解析错误: %#v", record)
	}
	if record.EDNSSuccess != 9 || record.EDNSTimeout != 10 || record.EDNSTimeout4096 != 4 || record.EDNSTimeout1432 != 3 || record.EDNSTimeout1232 != 2 || record.EDNSTimeout512 != 1 {
		t.Fatalf("ADB EDNS 五段计数解析错误: %#v", record)
	}
	if record.PlainSuccess != 5 || record.PlainTimeout != 6 || record.UDPSize != 1232 {
		t.Fatalf("ADB plain/UDP 字段解析错误: %#v", record)
	}
}

func TestParseADBLineSupportsTwoFieldEDNSCounters(t *testing.T) {
	parser := NewParser()
	parser.parseLine("; Address database dump")
	parser.parseLine("; ns2.example. [v4 TTL 120] [v4 success]")
	parser.parseLine(";\t198.51.100.53 [srtt 9000] [flags 00000000] [edns 7/2] [plain 0/0] [ttl 120]")
	record := parser.adbRecords[0]
	if record.EDNSSuccess != 7 || record.EDNSTimeout != 2 || record.EDNSTimeout4096 != 2 {
		t.Fatalf("ADB EDNS 两段计数解析错误: %#v", record)
	}
}

func TestParserDefaultsToFirstBusinessView(t *testing.T) {
	parser := NewParser()
	parser.parseLine("; Cache dump of view 'any' (cache any)")
	parser.parseLine("$DATE 20260727040001")
	parser.parseLine("; Cache dump of view '_bind' (cache _bind)")
	parser.parseLine("$DATE 20260727040002")

	if parser.view != "any" || parser.selectedView != "any" {
		t.Fatalf("default view = %q/%q, want any/any", parser.view, parser.selectedView)
	}
	if parser.inCache {
		t.Fatal("_bind view must not be parsed by the default single-view parser")
	}
	if parser.date != "20260727040001" {
		t.Fatalf("date = %q, want date from selected view", parser.date)
	}
}
