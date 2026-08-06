package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// MX 记录结构体
type MX struct {
	TTL        int
	Priority   int
	MailServer string
	Attribute  string
	Rcode      string
}

// PTR 记录结构体
type PTR struct {
	TTL       int
	Target    string
	Attribute string
	Rcode     string
}

// TXT 记录结构体
type TXT struct {
	TTL       int
	Content   string
	Attribute string
	Rcode     string
}

// SRV 记录结构体
type SRV struct {
	TTL       int
	Priority  int
	Weight    int
	Port      int
	Target    string
	Attribute string
	Rcode     string
}

// CAA 记录结构体
type CAA struct {
	TTL       int
	Flag      int
	Tag       string
	Value     string
	Attribute string
	Rcode     string
}

// TLSA 记录结构体
type TLSA struct {
	TTL                  int
	Usage                int
	Selector             int
	MatchingType         int
	CertificateAssocData string
	Attribute            string
	Rcode                string
}

// NAPTR 记录结构体
type NAPTR struct {
	TTL         int
	Order       int
	Preference  int
	Flags       string
	Services    string
	Regexp      string
	Replacement string
	Attribute   string
	Rcode       string
}

// SOA 记录结构体
type SOA struct {
	TTL       int
	MName     string
	RName     string
	Serial    uint32
	Refresh   int
	Retry     int
	Expire    int
	Minimum   int
	Attribute string
	Rcode     string
}

// RRSIG 记录结构体
type RRSIG struct {
	TTL         int
	TypeCovered string
	Algorithm   int
	Labels      int
	OriginalTTL int
	Expiration  string
	Inception   string
	KeyTag      int
	SignerName  string
	Signature   string
	Attribute   string
	Rcode       string
}

// DNSKEY 记录结构体
type DNSKEY struct {
	TTL       int
	Flags     int
	Protocol  int
	Algorithm int
	PublicKey string
	Attribute string
	Rcode     string
}

// DS 记录结构体
type DS struct {
	TTL        int
	KeyTag     int
	Algorithm  int
	DigestType int
	Digest     string
	Attribute  string
	Rcode      string
}

// NSEC 记录结构体
type NSEC struct {
	TTL        int
	NextDomain string
	Types      []string
	Attribute  string
	Rcode      string
}

// NSEC3 记录结构体
type NSEC3 struct {
	TTL        int
	HashAlg    int
	Flags      int
	Iterations int
	Salt       string
	NextDomain string
	Types      []string
	Attribute  string
	Rcode      string
}

type NS struct {
	NsDomain  string
	TTL       int
	IP        string
	Attribute string
}

type A struct {
	TTL       int
	IP        string
	Attribute string
	Rcode     string
}

type AAAA struct {
	TTL       int
	IP        string
	Attribute string
	Rcode     string
}

type ANY struct {
	TTL       int
	IP        string
	Attribute string
	Rcode     string
}

type TYPE65 struct {
	TTL       int
	IP        string
	Attribute string
	Rcode     string
}

type TYPE64 struct {
	TTL       int
	IP        string
	Attribute string
	Rcode     string
}

type CNAME struct {
	TTL       int
	IP        string
	Attribute string
	Rcode     string
}

// DNAME 记录结构体
type DNAME struct {
	TTL       int
	Target    string
	Attribute string
	Rcode     string
}

// ADBRecord 代表一条 Address Database 记录（权威服务器网络遥测）
type ADBRecord struct {
	Name        string
	IP          string
	SRTT        int
	Flags       string
	EDNSSuccess int
	// BIND 9.10-9.18 的 ADB dump 分别记录 4096/1432/1232/512 四档
	// EDNS 超时；较新格式可能只输出一个汇总超时。EDNSTimeout 始终保存
	// 各档之和，便于旧调用方继续使用。
	EDNSTimeout     int
	EDNSTimeout4096 int
	EDNSTimeout1432 int
	EDNSTimeout1232 int
	EDNSTimeout512  int
	PlainSuccess    int
	PlainTimeout    int
	UDPSize         int
	Cookie          string
	TTL             int
}

// Record 表示一条域名的所有 DNS 记录集合
type Record struct {
	NSs     []NS
	As      []A
	AAAAs   []AAAA
	ANYs    []ANY
	TYPE65  []TYPE65
	TYPE64  []TYPE64
	CNAMEs  []CNAME
	DNAMEs  []DNAME
	MXs     []MX
	PTRs    []PTR
	TXTs    []TXT
	SRVs    []SRV
	CAAs    []CAA
	TLSAs   []TLSA
	NAPTRs  []NAPTR
	SOAs    []SOA
	RRSIGs  []RRSIG
	DNSKEYs []DNSKEY
	DSs     []DS
	NSECs   []NSEC
	NSEC3s  []NSEC3
}

// Parser 定义解析器状态和方法
type Parser struct {
	records           map[string]Record
	nxdomainRecords   map[string]Record
	nxrrsetRecords    map[string]Record
	currentDomain     string
	currentAttribute  string
	currentTTL        int
	inCache           bool
	domainPattern     *regexp.Regexp
	cleanValuePattern *regexp.Regexp
	// 多行记录处理
	inMultiLine     bool
	multiLineBuffer string
	multiLineType   string
	// 元数据
	date         string
	view         string
	targetView   string
	selectedView string
	// ADB 遥测数据解析
	inADB          bool
	currentADBName string
	adbRecords     []ADBRecord
}

// NewParser 创建一个解析器
func NewParser() *Parser {
	return NewParserForView("")
}

// NewParserForView 创建一个仅解析指定 View 的解析器。空值表示第一个非 _bind 的业务 View。
func NewParserForView(targetView string) *Parser {
	const initialCapacity = 1000
	return &Parser{
		records:           make(map[string]Record, initialCapacity),
		nxdomainRecords:   make(map[string]Record, initialCapacity/10),
		nxrrsetRecords:    make(map[string]Record, initialCapacity/10),
		domainPattern:     regexp.MustCompile(`^.*\.$`),
		cleanValuePattern: regexp.MustCompile(`[^0-9a-fA-F]`),
		adbRecords:        make([]ADBRecord, 0, 100),
		targetView:        strings.TrimSpace(targetView),
	}
}

// ParseDNSCacheFile 从文件中提取所有的缓存与证明记录
func ParseDNSCacheFile(filename string) (*BindCache, error) {
	return parseDNSCacheFile(filename, "")
}

// ParseDNSCacheFileForView 仅解析 BIND dump 中指定的业务 View。
func ParseDNSCacheFileForView(filename, view string) (*BindCache, error) {
	return parseDNSCacheFile(filename, view)
}

func parseDNSCacheFile(filename, view string) (*BindCache, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	parser := NewParserForView(view)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parser.parseLine(line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	return &BindCache{
		records:         parser.records,
		nxdomainRecords: parser.nxdomainRecords,
		nxrrsetRecords:  parser.nxrrsetRecords,
		Date:            parser.date,
		View:            parser.view,
		ADBRecords:      parser.adbRecords,
	}, nil
}

// isNumeric 检查字符串是否全由数字组成
func isNumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// parseLine 状态机行解析器
func (p *Parser) parseLine(line string) {
	// 退出 ADB 的前置条件：非空、非注释、且非 $DATE 指令的行，则退出 ADB 状态
	if line != "" && !strings.HasPrefix(line, ";") && !strings.HasPrefix(line, "$") {
		p.inADB = false
	}

	// 1. 元数据指令读取
	if strings.Contains(line, "Cache dump of view") {
		p.inADB = false
		startIdx := strings.Index(line, "view '")
		if startIdx != -1 {
			rem := line[startIdx+6:]
			endIdx := strings.Index(rem, "'")
			if endIdx != -1 {
				p.inCache = p.selectCacheView(rem[:endIdx])
				return
			}
		}
		p.inCache = false
		return
	}
	if strings.Contains(line, "Address database dump") || strings.Contains(line, "Start view") {
		p.inCache = false
		if strings.Contains(line, "Address database dump") {
			p.inADB = true
		} else {
			p.inADB = false
		}
		return
	}
	if strings.HasPrefix(line, "$DATE") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && (p.date == "" || p.inCache) {
			p.date = fields[1]
		}
		return
	}

	if p.inADB && strings.HasPrefix(line, ";") {
		p.parseADBLine(line)
		return
	}

	if !p.inCache {
		return
	}

	// 2. 检测注释与特殊证明记录
	if strings.HasPrefix(line, ";") {
		cleanComment := strings.TrimSpace(strings.TrimPrefix(line, ";"))
		switch cleanComment {
		case "authanswer":
			p.currentAttribute = "authanswer"
			return
		case "authauthority":
			p.currentAttribute = "authauthority"
			return
		case "glue":
			p.currentAttribute = "glue"
			return
		case "answer":
			p.currentAttribute = "answer"
			return
		case "credential":
			p.currentAttribute = "credential"
			return
		case "additional":
			p.currentAttribute = "additional"
			return
		}

		fields := strings.Fields(cleanComment)
		if len(fields) >= 2 {
			p.parseProofRecord(cleanComment)
		}
		return
	}

	if strings.HasPrefix(line, "$") {
		return
	}

	// 3. 通用多行解析模式处理
	if p.inMultiLine {
		trimmedLine := strings.TrimLeft(line, " \t")
		closeIdx := strings.Index(trimmedLine, ")")
		if closeIdx != -1 {
			p.inMultiLine = false
			p.multiLineBuffer += " " + trimmedLine[:closeIdx]
			value := strings.TrimSpace(p.multiLineBuffer)
			if p.multiLineType == "TYPE65" {
				value = strings.ReplaceAll(value, " ", "")
				value = strings.ReplaceAll(value, "\t", "")
			}
			p.parseNormal(p.currentDomain, p.currentTTL, p.multiLineType, value)
			p.multiLineBuffer = ""
			p.multiLineType = ""
		} else {
			p.multiLineBuffer += " " + trimmedLine
		}
		return
	}

	trimmedLine := strings.TrimSpace(line)
	if trimmedLine == "" {
		return
	}

	// 判断是否缩进
	isIndent := line[0] == ' ' || line[0] == '\t'
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}

	var domain string
	var ttlStr string
	var dnsType string
	var valueStartIdx int

	if isIndent {
		if p.currentDomain == "" {
			return
		}
		domain = p.currentDomain
		ttlStr = fields[0]

		if len(fields) >= 3 && fields[1] == "IN" {
			nextType := fields[2]
			if nextType == "NS" || nextType == "SOA" || nextType == "MX" || nextType == "PTR" || nextType == "TXT" || nextType == "SRV" || nextType == "CAA" || nextType == "TLSA" || nextType == "NAPTR" {
				dnsType = "IN " + nextType
			} else {
				dnsType = nextType
			}
			valueStartIdx = 3
		} else {
			dnsType = fields[1]
			valueStartIdx = 2
		}
	} else {
		domain = fields[0]
		ttlStr = fields[1]

		if len(fields) >= 4 && fields[2] == "IN" {
			nextType := fields[3]
			if nextType == "NS" || nextType == "SOA" || nextType == "MX" || nextType == "PTR" || nextType == "TXT" || nextType == "SRV" || nextType == "CAA" || nextType == "TLSA" || nextType == "NAPTR" {
				dnsType = "IN " + nextType
			} else {
				dnsType = nextType
			}
			valueStartIdx = 4
		} else {
			dnsType = fields[2]
			valueStartIdx = 3
		}
	}

	ttl, err := strconv.Atoi(ttlStr)
	if err != nil {
		return
	}

	if !isIndent && domain != "" && strings.HasSuffix(domain, ".") {
		p.currentDomain = domain
		p.ensureDomain(domain)
	}

	if p.currentDomain == "" {
		return
	}

	if valueStartIdx >= len(fields) {
		return
	}

	typeToken := fields[valueStartIdx-1]
	typeIdx := strings.Index(line, typeToken)
	var value string
	if typeIdx != -1 {
		rem := line[typeIdx+len(typeToken):]
		valToken := fields[valueStartIdx]
		valTokenIdx := strings.Index(rem, valToken)
		if valTokenIdx != -1 {
			value = strings.TrimSpace(rem[valTokenIdx:])
		} else {
			value = strings.Join(fields[valueStartIdx:], " ")
		}
	} else {
		value = strings.Join(fields[valueStartIdx:], " ")
	}

	// 检查多行起始
	if strings.HasSuffix(value, "(") {
		p.inMultiLine = true
		p.currentTTL = ttl
		p.multiLineType = dnsType
		leftParenIdx := strings.Index(value, "(")
		if leftParenIdx != -1 {
			p.multiLineBuffer = value[:leftParenIdx] + " " + value[leftParenIdx+1:]
		} else {
			p.multiLineBuffer = ""
		}
		return
	}

	// 检查否定缓存
	if strings.HasPrefix(dnsType, "\\-") || strings.HasPrefix(dnsType, "-") {
		trueType := strings.TrimPrefix(dnsType, "\\-")
		trueType = strings.TrimPrefix(trueType, "-")
		rcode := strings.TrimPrefix(value, ";-$")
		rcode = strings.ToLower(strings.TrimSpace(rcode))
		p.parseSpecial(p.currentDomain, ttl, trueType, rcode)
		return
	}

	p.parseNormal(p.currentDomain, ttl, dnsType, value)
}

func (p *Parser) selectCacheView(view string) bool {
	view = strings.TrimSpace(view)
	if p.targetView != "" {
		if view == p.targetView {
			p.selectedView = view
			p.view = view
			return true
		}
		return false
	}
	if p.selectedView == "" && view != "" && view != "_bind" {
		p.selectedView = view
		p.view = view
	}
	return view != "" && view == p.selectedView
}

// ensureDomain 确保域名被初始化
func (p *Parser) ensureDomain(domain string) {
	if _, exists := p.records[domain]; !exists {
		p.records[domain] = Record{}
	}
}

// parseProofRecord 解析注释形式的证明记录（通常在否定缓存下）
func (p *Parser) parseProofRecord(line string) {
	oldDomain := p.currentDomain
	defer func() {
		p.currentDomain = oldDomain
	}()

	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}

	var domain string
	var ttl int
	var dnsType string
	var value string

	domain = fields[0]
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	// 检查是否有 TTL 列
	if len(fields) >= 3 && isNumeric(fields[1]) {
		ttl, _ = strconv.Atoi(fields[1])
		dnsType = fields[2]
		value = strings.Join(fields[3:], " ")
	} else {
		ttl = p.currentTTL // 继承上下文 TTL
		dnsType = fields[1]
		value = strings.Join(fields[2:], " ")
	}

	p.currentDomain = domain
	p.ensureDomain(domain)

	oldAttr := p.currentAttribute
	p.currentAttribute = oldAttr + "-proof"

	// 检查多行
	if strings.HasSuffix(value, "(") {
		p.inMultiLine = true
		p.currentTTL = ttl
		p.multiLineType = dnsType
		leftParenIdx := strings.Index(value, "(")
		if leftParenIdx != -1 {
			p.multiLineBuffer = value[:leftParenIdx] + " " + value[leftParenIdx+1:]
		} else {
			p.multiLineBuffer = ""
		}
	} else {
		p.parseNormal(domain, ttl, dnsType, value)
	}

	p.currentAttribute = oldAttr
}

// parseNormal 普通类型解析分发
func (p *Parser) parseNormal(domain string, ttl int, dnsType string, value string) {
	// fmt.Printf("DEBUG parseNormal: domain=%s, type=%s, val=%s\n", domain, dnsType, value)
	if domain != "" && p.domainPattern.MatchString(domain) {
		p.currentDomain = domain
		p.ensureDomain(domain)
	}

	if p.currentDomain == "" {
		return
	}

	attr := p.currentAttribute
	if attr == "" {
		attr = "unknown"
	}

	record := p.records[p.currentDomain]
	switch dnsType {
	case "IN NS", "NS":
		record.NSs = append(record.NSs, NS{
			NsDomain:  value,
			TTL:       ttl,
			Attribute: attr,
		})
	case "A":
		record.As = append(record.As, A{
			TTL:       ttl,
			IP:        value,
			Attribute: attr,
		})
	case "AAAA":
		record.AAAAs = append(record.AAAAs, AAAA{
			TTL:       ttl,
			IP:        value,
			Attribute: attr,
		})
	case "CNAME":
		record.CNAMEs = append(record.CNAMEs, CNAME{
			TTL:       ttl,
			IP:        value,
			Attribute: attr,
		})
	case "DNAME":
		record.DNAMEs = append(record.DNAMEs, DNAME{
			TTL:       ttl,
			Target:    value,
			Attribute: attr,
		})
	case "ANY":
		record.ANYs = append(record.ANYs, ANY{
			TTL:       ttl,
			IP:        value,
			Attribute: attr,
		})
	case "IN MX", "MX":
		parts := strings.SplitN(value, " ", 2)
		if len(parts) == 2 {
			priority, _ := strconv.Atoi(parts[0])
			mailServer := parts[1]
			record.MXs = append(record.MXs, MX{
				TTL:        ttl,
				Priority:   priority,
				MailServer: mailServer,
				Attribute:  attr,
			})
		}
	case "PTR":
		record.PTRs = append(record.PTRs, PTR{
			TTL:       ttl,
			Target:    value,
			Attribute: attr,
		})
	case "IN TXT", "TXT":
		record.TXTs = append(record.TXTs, TXT{
			TTL:       ttl,
			Content:   value,
			Attribute: attr,
		})
	case "IN SOA", "SOA":
		parts := strings.Fields(value)
		if len(parts) >= 7 {
			mname := parts[0]
			rname := parts[1]
			serial, _ := strconv.ParseUint(parts[2], 10, 32)
			refresh, _ := strconv.Atoi(parts[3])
			retry, _ := strconv.Atoi(parts[4])
			expire, _ := strconv.Atoi(parts[5])
			minimum, _ := strconv.Atoi(parts[6])
			record.SOAs = append(record.SOAs, SOA{
				TTL:       ttl,
				MName:     mname,
				RName:     rname,
				Serial:    uint32(serial),
				Refresh:   refresh,
				Retry:     retry,
				Expire:    expire,
				Minimum:   minimum,
				Attribute: attr,
			})
		}
	case "IN SRV", "SRV":
		parts := strings.Fields(value)
		if len(parts) >= 4 {
			priority, _ := strconv.Atoi(parts[0])
			weight, _ := strconv.Atoi(parts[1])
			port, _ := strconv.Atoi(parts[2])
			target := parts[3]
			record.SRVs = append(record.SRVs, SRV{
				TTL:       ttl,
				Priority:  priority,
				Weight:    weight,
				Port:      port,
				Target:    target,
				Attribute: attr,
			})
		}
	case "IN CAA", "CAA":
		parts := strings.Fields(value)
		if len(parts) >= 3 {
			flag, _ := strconv.Atoi(parts[0])
			tag := parts[1]
			val := strings.Join(parts[2:], " ")
			record.CAAs = append(record.CAAs, CAA{
				TTL:       ttl,
				Flag:      flag,
				Tag:       tag,
				Value:     val,
				Attribute: attr,
			})
		}
	case "IN TLSA", "TLSA":
		parts := strings.Fields(value)
		if len(parts) >= 4 {
			usage, _ := strconv.Atoi(parts[0])
			selector, _ := strconv.Atoi(parts[1])
			mtype, _ := strconv.Atoi(parts[2])
			data := strings.Join(parts[3:], "")
			record.TLSAs = append(record.TLSAs, TLSA{
				TTL:                  ttl,
				Usage:                usage,
				Selector:             selector,
				MatchingType:         mtype,
				CertificateAssocData: data,
				Attribute:            attr,
			})
		}
	case "IN NAPTR", "NAPTR":
		parts := strings.Fields(value)
		if len(parts) >= 6 {
			order, _ := strconv.Atoi(parts[0])
			pref, _ := strconv.Atoi(parts[1])
			flags := parts[2]
			services := parts[3]
			regex := parts[4]
			replacement := parts[5]
			record.NAPTRs = append(record.NAPTRs, NAPTR{
				TTL:         ttl,
				Order:       order,
				Preference:  pref,
				Flags:       flags,
				Services:    services,
				Regexp:      regex,
				Replacement: replacement,
				Attribute:   attr,
			})
		}
	case "RRSIG":
		parts := strings.Fields(value)
		if len(parts) >= 8 {
			typeCovered := parts[0]
			algorithm, _ := strconv.Atoi(parts[1])
			labels, _ := strconv.Atoi(parts[2])
			origTTL, _ := strconv.Atoi(parts[3])
			expiration := parts[4]
			inception := parts[5]
			keyTag, _ := strconv.Atoi(parts[6])
			signerName := parts[7]
			sig := strings.Join(parts[8:], "")
			record.RRSIGs = append(record.RRSIGs, RRSIG{
				TTL:         ttl,
				TypeCovered: typeCovered,
				Algorithm:   algorithm,
				Labels:      labels,
				OriginalTTL: origTTL,
				Expiration:  expiration,
				Inception:   inception,
				KeyTag:      keyTag,
				SignerName:  signerName,
				Signature:   sig,
				Attribute:   attr,
			})
		}
	case "DNSKEY":
		parts := strings.Fields(value)
		if len(parts) >= 4 {
			flags, _ := strconv.Atoi(parts[0])
			protocol, _ := strconv.Atoi(parts[1])
			algorithm, _ := strconv.Atoi(parts[2])
			pubkey := strings.Join(parts[3:], "")
			record.DNSKEYs = append(record.DNSKEYs, DNSKEY{
				TTL:       ttl,
				Flags:     flags,
				Protocol:  protocol,
				Algorithm: algorithm,
				PublicKey: pubkey,
				Attribute: attr,
			})
		}
	case "DS":
		parts := strings.Fields(value)
		if len(parts) >= 4 {
			keyTag, _ := strconv.Atoi(parts[0])
			algorithm, _ := strconv.Atoi(parts[1])
			dtype, _ := strconv.Atoi(parts[2])
			digest := strings.Join(parts[3:], "")
			record.DSs = append(record.DSs, DS{
				TTL:        ttl,
				KeyTag:     keyTag,
				Algorithm:  algorithm,
				DigestType: dtype,
				Digest:     digest,
				Attribute:  attr,
			})
		}
	case "NSEC":
		parts := strings.Fields(value)
		if len(parts) >= 1 {
			nextDomain := parts[0]
			var types []string
			if len(parts) > 1 {
				types = parts[1:]
			}
			record.NSECs = append(record.NSECs, NSEC{
				TTL:        ttl,
				NextDomain: nextDomain,
				Types:      types,
				Attribute:  attr,
			})
		}
	case "NSEC3":
		parts := strings.Fields(value)
		if len(parts) >= 5 {
			hashAlg, _ := strconv.Atoi(parts[0])
			flags, _ := strconv.Atoi(parts[1])
			iters, _ := strconv.Atoi(parts[2])
			salt := parts[3]
			nextDomain := parts[4]
			var types []string
			if len(parts) > 5 {
				types = parts[5:]
			}
			record.NSEC3s = append(record.NSEC3s, NSEC3{
				TTL:        ttl,
				HashAlg:    hashAlg,
				Flags:      flags,
				Iterations: iters,
				Salt:       salt,
				NextDomain: nextDomain,
				Types:      types,
				Attribute:  attr,
			})
		}
	case "TYPE65", "HTTPS", "TYPE64", "SVCB":
		isType64 := dnsType == "TYPE64" || dnsType == "SVCB"
		labelName := "HTTPS"
		if isType64 {
			labelName = "SVCB"
		}

		cleanValue := p.cleanValuePattern.ReplaceAllString(value, "")
		if len(cleanValue)%2 != 0 {
			cleanValue += "0"
		}

		data, err := hex.DecodeString(cleanValue)
		if err != nil {
			if isType64 {
				record.TYPE64 = append(record.TYPE64, TYPE64{
					TTL:       ttl,
					IP:        "解码失败",
					Attribute: attr,
				})
			} else {
				record.TYPE65 = append(record.TYPE65, TYPE65{
					TTL:       ttl,
					IP:        "解码失败",
					Attribute: attr,
				})
			}
			p.records[p.currentDomain] = record
			return
		}

		if len(data) < 2 {
			p.records[p.currentDomain] = record
			return
		}

		priority := int(binary.BigEndian.Uint16(data[0:2]))
		targetName, offset, _ := parseDomainName(data, 2)

		params := []string{}
		for offset < len(data) {
			if offset+4 > len(data) {
				break
			}

			key := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
			offset += 4

			if offset+length > len(data) {
				break
			}

			valueBytes := data[offset : offset+length]

			switch key {
			case 1:
				var alpnList []string
				currentPos := 0
				for currentPos < len(valueBytes) {
					protoLen := int(valueBytes[currentPos])
					currentPos++
					if currentPos+protoLen <= len(valueBytes) {
						alpnList = append(alpnList, string(valueBytes[currentPos:currentPos+protoLen]))
						currentPos += protoLen
					}
				}
				if len(alpnList) > 0 {
					params = append(params, fmt.Sprintf("alpn=\"%s\"", strings.Join(alpnList, ",")))
				}
			case 4:
				if len(valueBytes)%4 == 0 {
					var ipv4s []string
					for i := 0; i < len(valueBytes); i += 4 {
						ipv4 := net.IP(valueBytes[i : i+4])
						ipv4s = append(ipv4s, ipv4.String())
					}
					params = append(params, fmt.Sprintf("ipv4hint=\"%s\"", strings.Join(ipv4s, ",")))
				}
			case 6:
				if len(valueBytes)%16 == 0 {
					var ipv6s []string
					for i := 0; i < len(valueBytes); i += 16 {
						ipv6 := net.IP(valueBytes[i : i+16])
						ipv6s = append(ipv6s, ipv6.String())
					}
					params = append(params, fmt.Sprintf("ipv6hint=\"%s\"", strings.Join(ipv6s, ",")))
				}
			case 5:
				if len(valueBytes) > 0 {
					params = append(params, fmt.Sprintf("echconfig=0x%X", valueBytes))
				}
			default:
				if key <= 65535 && len(valueBytes) <= 256 {
					params = append(params, fmt.Sprintf("key%d=0x%X", key, valueBytes))
				}
			}

			offset += length
		}

		readableValue := fmt.Sprintf("%s(priority=%d, target=%s, params=[%s])",
			labelName, priority, targetName, strings.Join(params, ", "))

		if isType64 {
			record.TYPE64 = append(record.TYPE64, TYPE64{
				TTL:       ttl,
				IP:        readableValue,
				Attribute: attr,
			})
		} else {
			record.TYPE65 = append(record.TYPE65, TYPE65{
				TTL:       ttl,
				IP:        readableValue,
				Attribute: attr,
			})
		}
	}

	p.records[p.currentDomain] = record
}

// parseSpecial 特殊否定缓存状态解析
func (p *Parser) parseSpecial(domain string, ttl int, dnsType string, rcode string) {
	if domain != "" && p.domainPattern.MatchString(domain) {
		p.currentDomain = domain
		p.ensureDomain(domain)
	}
	if p.currentDomain == "" {
		return
	}

	attr := p.currentAttribute
	if attr == "" {
		attr = "unknown"
	}

	record := p.records[p.currentDomain]
	switch dnsType {
	case "A":
		record.As = append(record.As, A{TTL: ttl, IP: "", Attribute: attr, Rcode: rcode})
	case "AAAA":
		record.AAAAs = append(record.AAAAs, AAAA{TTL: ttl, IP: "", Attribute: attr, Rcode: rcode})
	case "CNAME":
		record.CNAMEs = append(record.CNAMEs, CNAME{TTL: ttl, IP: "", Attribute: attr, Rcode: rcode})
	case "DNAME":
		record.DNAMEs = append(record.DNAMEs, DNAME{TTL: ttl, Target: "", Attribute: attr, Rcode: rcode})
	case "ANY":
		record.ANYs = append(record.ANYs, ANY{TTL: ttl, IP: "", Attribute: attr, Rcode: rcode})
	case "TYPE65", "HTTPS":
		record.TYPE65 = append(record.TYPE65, TYPE65{TTL: ttl, IP: "", Attribute: attr, Rcode: rcode})
	case "TYPE64", "SVCB":
		record.TYPE64 = append(record.TYPE64, TYPE64{TTL: ttl, IP: "", Attribute: attr, Rcode: rcode})
	case "MX":
		record.MXs = append(record.MXs, MX{TTL: ttl, Priority: 0, MailServer: "", Attribute: attr, Rcode: rcode})
	case "PTR":
		record.PTRs = append(record.PTRs, PTR{TTL: ttl, Target: "", Attribute: attr, Rcode: rcode})
	case "TXT":
		record.TXTs = append(record.TXTs, TXT{TTL: ttl, Content: "", Attribute: attr, Rcode: rcode})
	case "SRV":
		record.SRVs = append(record.SRVs, SRV{TTL: ttl, Attribute: attr, Rcode: rcode})
	case "CAA":
		record.CAAs = append(record.CAAs, CAA{TTL: ttl, Attribute: attr, Rcode: rcode})
	case "TLSA":
		record.TLSAs = append(record.TLSAs, TLSA{TTL: ttl, Attribute: attr, Rcode: rcode})
	case "NAPTR":
		record.NAPTRs = append(record.NAPTRs, NAPTR{TTL: ttl, Attribute: attr, Rcode: rcode})
	case "SOA":
		record.SOAs = append(record.SOAs, SOA{TTL: ttl, Attribute: attr, Rcode: rcode})
	case "RRSIG":
		record.RRSIGs = append(record.RRSIGs, RRSIG{TTL: ttl, Attribute: attr, Rcode: rcode})
	case "DNSKEY":
		record.DNSKEYs = append(record.DNSKEYs, DNSKEY{TTL: ttl, Attribute: attr, Rcode: rcode})
	case "DS":
		record.DSs = append(record.DSs, DS{TTL: ttl, Attribute: attr, Rcode: rcode})
	case "NSEC":
		record.NSECs = append(record.NSECs, NSEC{TTL: ttl, Attribute: attr, Rcode: rcode})
	case "NSEC3":
		record.NSEC3s = append(record.NSEC3s, NSEC3{TTL: ttl, Attribute: attr, Rcode: rcode})
	}
	p.records[p.currentDomain] = record
	if rcode == "nxdomain" {
		p.nxdomainRecords[p.currentDomain] = record
	} else if rcode == "nxrrset" {
		p.nxrrsetRecords[p.currentDomain] = record
	}
}

// String 格式化输出 Record 结构体数据
func (r Record) String() string {
	var lines []string

	formatField := func(name string, items []string) string {
		if len(items) == 0 {
			return fmt.Sprintf("  %s: []", name)
		}
		// 对 items 进行去重（保持原有顺序）
		seen := make(map[string]bool)
		var unique []string
		for _, item := range items {
			if !seen[item] {
				seen[item] = true
				unique = append(unique, item)
			}
		}

		if len(unique) == 1 {
			return fmt.Sprintf("  %s: [%s]", name, unique[0])
		}

		var fieldLines []string
		fieldLines = append(fieldLines, fmt.Sprintf("  %s:", name))
		for _, item := range unique {
			fieldLines = append(fieldLines, fmt.Sprintf("    - %s", item))
		}
		return strings.Join(fieldLines, "\n")
	}

	// 1. NSs
	nsItems := make([]string, 0, len(r.NSs))
	for _, ns := range r.NSs {
		nsItems = append(nsItems, fmt.Sprintf("{NsDomain=%s, TTL=%d, Attribute=%s}", ns.NsDomain, ns.TTL, ns.Attribute))
	}
	lines = append(lines, formatField("NSs", nsItems))

	// 2. As
	var aItems []string
	type aGroup struct {
		ttl       int
		attribute string
		ips       []string
	}
	var aGroups []aGroup
	hasARcode := false
	var aRcodeItem string

	for _, a := range r.As {
		if a.Rcode != "" {
			aRcodeItem = fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", a.TTL, a.Rcode, a.Attribute)
			hasARcode = true
			break
		}
		found := false
		for i, g := range aGroups {
			if g.attribute == a.Attribute && g.ttl == a.TTL {
				aGroups[i].ips = append(aGroups[i].ips, a.IP)
				found = true
				break
			}
		}
		if !found {
			aGroups = append(aGroups, aGroup{
				ttl:       a.TTL,
				attribute: a.Attribute,
				ips:       []string{a.IP},
			})
		}
	}

	if hasARcode {
		aItems = []string{aRcodeItem}
	} else {
		for _, g := range aGroups {
			seenIP := make(map[string]bool)
			var uniqueIPs []string
			for _, ip := range g.ips {
				if !seenIP[ip] {
					seenIP[ip] = true
					uniqueIPs = append(uniqueIPs, ip)
				}
			}
			aItems = append(aItems, fmt.Sprintf("{TTL=%d, IP=%s, Attribute=%s}", g.ttl, strings.Join(uniqueIPs, ";"), g.attribute))
		}
	}
	lines = append(lines, formatField("As", aItems))

	// 3. AAAAs
	var aaaaItems []string
	type aaaaGroup struct {
		ttl       int
		attribute string
		ips       []string
	}
	var aaaaGroups []aaaaGroup
	hasAAAARcode := false
	var aaaaRcodeItem string

	for _, aaaa := range r.AAAAs {
		if aaaa.Rcode != "" {
			aaaaRcodeItem = fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", aaaa.TTL, aaaa.Rcode, aaaa.Attribute)
			hasAAAARcode = true
			break
		}
		found := false
		for i, g := range aaaaGroups {
			if g.attribute == aaaa.Attribute && g.ttl == aaaa.TTL {
				aaaaGroups[i].ips = append(aaaaGroups[i].ips, aaaa.IP)
				found = true
				break
			}
		}
		if !found {
			aaaaGroups = append(aaaaGroups, aaaaGroup{
				ttl:       aaaa.TTL,
				attribute: aaaa.Attribute,
				ips:       []string{aaaa.IP},
			})
		}
	}

	if hasAAAARcode {
		aaaaItems = []string{aaaaRcodeItem}
	} else {
		for _, g := range aaaaGroups {
			seenIP := make(map[string]bool)
			var uniqueIPs []string
			for _, ip := range g.ips {
				if !seenIP[ip] {
					seenIP[ip] = true
					uniqueIPs = append(uniqueIPs, ip)
				}
			}
			aaaaItems = append(aaaaItems, fmt.Sprintf("{TTL=%d, IP=%s, Attribute=%s}", g.ttl, strings.Join(uniqueIPs, ";"), g.attribute))
		}
	}
	lines = append(lines, formatField("AAAAs", aaaaItems))

	// 4. ANYs
	var anyItems []string
	type anyGroup struct {
		ttl       int
		attribute string
		ips       []string
	}
	var anyGroups []anyGroup
	hasANYRcode := false
	var anyRcodeItem string

	for _, any := range r.ANYs {
		if any.Rcode != "" {
			anyRcodeItem = fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", any.TTL, any.Rcode, any.Attribute)
			hasANYRcode = true
			break
		}
		found := false
		for i, g := range anyGroups {
			if g.attribute == any.Attribute && g.ttl == any.TTL {
				anyGroups[i].ips = append(anyGroups[i].ips, any.IP)
				found = true
				break
			}
		}
		if !found {
			anyGroups = append(anyGroups, anyGroup{
				ttl:       any.TTL,
				attribute: any.Attribute,
				ips:       []string{any.IP},
			})
		}
	}

	if hasANYRcode {
		anyItems = []string{anyRcodeItem}
	} else {
		for _, g := range anyGroups {
			seenIP := make(map[string]bool)
			var uniqueIPs []string
			for _, ip := range g.ips {
				if !seenIP[ip] {
					seenIP[ip] = true
					uniqueIPs = append(uniqueIPs, ip)
				}
			}
			anyItems = append(anyItems, fmt.Sprintf("{TTL=%d, IP=%s, Attribute=%s}", g.ttl, strings.Join(uniqueIPs, ";"), g.attribute))
		}
	}
	lines = append(lines, formatField("ANYs", anyItems))

	// 5. TYPE65
	var type65Items []string
	for _, t65 := range r.TYPE65 {
		if t65.Rcode != "" {
			type65Items = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", t65.TTL, t65.Rcode, t65.Attribute)}
			break
		}
		type65Items = append(type65Items, fmt.Sprintf("{TTL=%d, IP=%s, Attribute=%s}", t65.TTL, t65.IP, t65.Attribute))
	}
	lines = append(lines, formatField("TYPE65", type65Items))

	// 6. TYPE64
	var type64Items []string
	for _, t64 := range r.TYPE64 {
		if t64.Rcode != "" {
			type64Items = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", t64.TTL, t64.Rcode, t64.Attribute)}
			break
		}
		type64Items = append(type64Items, fmt.Sprintf("{TTL=%d, IP=%s, Attribute=%s}", t64.TTL, t64.IP, t64.Attribute))
	}
	lines = append(lines, formatField("TYPE64", type64Items))

	// 7. CNAMEs
	var cnameItems []string
	for _, cname := range r.CNAMEs {
		if cname.Rcode != "" {
			cnameItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", cname.TTL, cname.Rcode, cname.Attribute)}
			break
		}
		cnameItems = append(cnameItems, fmt.Sprintf("{TTL=%d, IP=%s, Attribute=%s}", cname.TTL, cname.IP, cname.Attribute))
	}
	lines = append(lines, formatField("CNAMEs", cnameItems))

	// 7.1. DNAMEs
	var dnameItems []string
	for _, dname := range r.DNAMEs {
		if dname.Rcode != "" {
			dnameItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", dname.TTL, dname.Rcode, dname.Attribute)}
			break
		}
		dnameItems = append(dnameItems, fmt.Sprintf("{TTL=%d, Target=%s, Attribute=%s}", dname.TTL, dname.Target, dname.Attribute))
	}
	lines = append(lines, formatField("DNAMEs", dnameItems))

	// 8. MXs
	var mxItems []string
	for _, mx := range r.MXs {
		if mx.Rcode != "" {
			mxItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", mx.TTL, mx.Rcode, mx.Attribute)}
			break
		}
		mxItems = append(mxItems, fmt.Sprintf("{TTL=%d, Priority=%d, MailServer=%s, Attribute=%s}", mx.TTL, mx.Priority, mx.MailServer, mx.Attribute))
	}
	lines = append(lines, formatField("MXs", mxItems))

	// 9. PTRs
	var ptrItems []string
	for _, ptr := range r.PTRs {
		if ptr.Rcode != "" {
			ptrItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", ptr.TTL, ptr.Rcode, ptr.Attribute)}
			break
		}
		ptrItems = append(ptrItems, fmt.Sprintf("{TTL=%d, Target=%s, Attribute=%s}", ptr.TTL, ptr.Target, ptr.Attribute))
	}
	lines = append(lines, formatField("PTRs", ptrItems))

	// 10. TXTs
	var txtItems []string
	for _, txt := range r.TXTs {
		if txt.Rcode != "" {
			txtItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", txt.TTL, txt.Rcode, txt.Attribute)}
			break
		}
		txtItems = append(txtItems, fmt.Sprintf("{TTL=%d, Content=%s, Attribute=%s}", txt.TTL, txt.Content, txt.Attribute))
	}
	lines = append(lines, formatField("TXTs", txtItems))

	// 11. SRVs
	var srvItems []string
	for _, s := range r.SRVs {
		if s.Rcode != "" {
			srvItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", s.TTL, s.Rcode, s.Attribute)}
			break
		}
		srvItems = append(srvItems, fmt.Sprintf("{TTL=%d, Priority=%d, Weight=%d, Port=%d, Target=%s, Attribute=%s}", s.TTL, s.Priority, s.Weight, s.Port, s.Target, s.Attribute))
	}
	lines = append(lines, formatField("SRVs", srvItems))

	// 12. CAAs
	var caaItems []string
	for _, c := range r.CAAs {
		if c.Rcode != "" {
			caaItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", c.TTL, c.Rcode, c.Attribute)}
			break
		}
		caaItems = append(caaItems, fmt.Sprintf("{TTL=%d, Flag=%d, Tag=%s, Value=%s, Attribute=%s}", c.TTL, c.Flag, c.Tag, c.Value, c.Attribute))
	}
	lines = append(lines, formatField("CAAs", caaItems))

	// 13. TLSAs
	var tlsaItems []string
	for _, t := range r.TLSAs {
		if t.Rcode != "" {
			tlsaItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", t.TTL, t.Rcode, t.Attribute)}
			break
		}
		tlsaItems = append(tlsaItems, fmt.Sprintf("{TTL=%d, Usage=%d, Selector=%d, MatchingType=%d, Hash=%s, Attribute=%s}", t.TTL, t.Usage, t.Selector, t.MatchingType, t.CertificateAssocData, t.Attribute))
	}
	lines = append(lines, formatField("TLSAs", tlsaItems))

	// 14. NAPTRs
	var naptrItems []string
	for _, n := range r.NAPTRs {
		if n.Rcode != "" {
			naptrItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", n.TTL, n.Rcode, n.Attribute)}
			break
		}
		naptrItems = append(naptrItems, fmt.Sprintf("{TTL=%d, Order=%d, Preference=%d, Flags=%s, Services=%s, Regexp=%s, Replacement=%s, Attribute=%s}", n.TTL, n.Order, n.Preference, n.Flags, n.Services, n.Regexp, n.Replacement, n.Attribute))
	}
	lines = append(lines, formatField("NAPTRs", naptrItems))

	// 15. SOAs
	var soaItems []string
	for _, s := range r.SOAs {
		if s.Rcode != "" {
			soaItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", s.TTL, s.Rcode, s.Attribute)}
			break
		}
		soaItems = append(soaItems, fmt.Sprintf("{TTL=%d, MName=%s, RName=%s, Serial=%d, Refresh=%d, Retry=%d, Expire=%d, Minimum=%d, Attribute=%s}", s.TTL, s.MName, s.RName, s.Serial, s.Refresh, s.Retry, s.Expire, s.Minimum, s.Attribute))
	}
	lines = append(lines, formatField("SOAs", soaItems))

	// 16. RRSIGs
	var rrsigItems []string
	for _, rr := range r.RRSIGs {
		if rr.Rcode != "" {
			rrsigItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", rr.TTL, rr.Rcode, rr.Attribute)}
			break
		}
		rrsigItems = append(rrsigItems, fmt.Sprintf("{TTL=%d, TypeCovered=%s, Alg=%d, KeyTag=%d, Signer=%s, Attribute=%s}", rr.TTL, rr.TypeCovered, rr.Algorithm, rr.KeyTag, rr.SignerName, rr.Attribute))
	}
	lines = append(lines, formatField("RRSIGs", rrsigItems))

	// 17. DNSKEYs
	var dnskeyItems []string
	for _, dk := range r.DNSKEYs {
		if dk.Rcode != "" {
			dnskeyItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", dk.TTL, dk.Rcode, dk.Attribute)}
			break
		}
		dnskeyItems = append(dnskeyItems, fmt.Sprintf("{TTL=%d, Flags=%d, Proto=%d, Alg=%d, Key=%s, Attribute=%s}", dk.TTL, dk.Flags, dk.Protocol, dk.Algorithm, dk.PublicKey, dk.Attribute))
	}
	lines = append(lines, formatField("DNSKEYs", dnskeyItems))

	// 18. DSs
	var dsItems []string
	for _, ds := range r.DSs {
		if ds.Rcode != "" {
			dsItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", ds.TTL, ds.Rcode, ds.Attribute)}
			break
		}
		dsItems = append(dsItems, fmt.Sprintf("{TTL=%d, KeyTag=%d, Alg=%d, DigestType=%d, Digest=%s, Attribute=%s}", ds.TTL, ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest, ds.Attribute))
	}
	lines = append(lines, formatField("DSs", dsItems))

	// 19. NSECs
	var nsecItems []string
	for _, ns := range r.NSECs {
		if ns.Rcode != "" {
			nsecItems = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", ns.TTL, ns.Rcode, ns.Attribute)}
			break
		}
		nsecItems = append(nsecItems, fmt.Sprintf("{TTL=%d, Next=%s, Types=%v, Attribute=%s}", ns.TTL, ns.NextDomain, ns.Types, ns.Attribute))
	}
	lines = append(lines, formatField("NSECs", nsecItems))

	// 20. NSEC3s
	var nsec3Items []string
	for _, ns3 := range r.NSEC3s {
		if ns3.Rcode != "" {
			nsec3Items = []string{fmt.Sprintf("{TTL=%d, Rcode=%s, Attribute=%s}", ns3.TTL, ns3.Rcode, ns3.Attribute)}
			break
		}
		nsec3Items = append(nsec3Items, fmt.Sprintf("{TTL=%d, HashAlg=%d, Flags=%d, Iterations=%d, Salt=%s, Next=%s, Types=%v, Attribute=%s}", ns3.TTL, ns3.HashAlg, ns3.Flags, ns3.Iterations, ns3.Salt, ns3.NextDomain, ns3.Types, ns3.Attribute))
	}
	lines = append(lines, formatField("NSEC3s", nsec3Items))

	return strings.Join(lines, "\n")
}

// Deduplicate 返回去重清洗后的 Record 副本，主要用于外部 JSON 格式化输出
func (r Record) Deduplicate() Record {
	clean := Record{
		NSs:     make([]NS, 0),
		As:      make([]A, 0),
		AAAAs:   make([]AAAA, 0),
		ANYs:    make([]ANY, 0),
		TYPE65:  make([]TYPE65, 0),
		TYPE64:  make([]TYPE64, 0),
		CNAMEs:  make([]CNAME, 0),
		DNAMEs:  make([]DNAME, 0),
		MXs:     make([]MX, 0),
		PTRs:    make([]PTR, 0),
		TXTs:    make([]TXT, 0),
		SRVs:    make([]SRV, 0),
		CAAs:    make([]CAA, 0),
		TLSAs:   make([]TLSA, 0),
		NAPTRs:  make([]NAPTR, 0),
		SOAs:    make([]SOA, 0),
		RRSIGs:  make([]RRSIG, 0),
		DNSKEYs: make([]DNSKEY, 0),
		DSs:     make([]DS, 0),
		NSECs:   make([]NSEC, 0),
		NSEC3s:  make([]NSEC3, 0),
	}

	// 1. NSs
	seenNS := make(map[string]bool)
	for _, item := range r.NSs {
		key := fmt.Sprintf("%v", item)
		if !seenNS[key] {
			seenNS[key] = true
			clean.NSs = append(clean.NSs, item)
		}
	}

	// 2. As
	seenA := make(map[string]bool)
	for _, item := range r.As {
		key := fmt.Sprintf("%v", item)
		if !seenA[key] {
			seenA[key] = true
			clean.As = append(clean.As, item)
		}
	}

	// 3. AAAAs
	seenAAAA := make(map[string]bool)
	for _, item := range r.AAAAs {
		key := fmt.Sprintf("%v", item)
		if !seenAAAA[key] {
			seenAAAA[key] = true
			clean.AAAAs = append(clean.AAAAs, item)
		}
	}

	// 4. ANYs
	seenANY := make(map[string]bool)
	for _, item := range r.ANYs {
		key := fmt.Sprintf("%v", item)
		if !seenANY[key] {
			seenANY[key] = true
			clean.ANYs = append(clean.ANYs, item)
		}
	}

	// 5. TYPE65
	seen65 := make(map[string]bool)
	for _, item := range r.TYPE65 {
		key := fmt.Sprintf("%v", item)
		if !seen65[key] {
			seen65[key] = true
			clean.TYPE65 = append(clean.TYPE65, item)
		}
	}

	// 6. TYPE64
	seen64 := make(map[string]bool)
	for _, item := range r.TYPE64 {
		key := fmt.Sprintf("%v", item)
		if !seen64[key] {
			seen64[key] = true
			clean.TYPE64 = append(clean.TYPE64, item)
		}
	}

	// 7. CNAMEs
	seenCNAME := make(map[string]bool)
	for _, item := range r.CNAMEs {
		key := fmt.Sprintf("%v", item)
		if !seenCNAME[key] {
			seenCNAME[key] = true
			clean.CNAMEs = append(clean.CNAMEs, item)
		}
	}

	// 7.1. DNAMEs
	seenDNAME := make(map[string]bool)
	for _, item := range r.DNAMEs {
		key := fmt.Sprintf("%v", item)
		if !seenDNAME[key] {
			seenDNAME[key] = true
			clean.DNAMEs = append(clean.DNAMEs, item)
		}
	}

	// 8. MXs
	seenMX := make(map[string]bool)
	for _, item := range r.MXs {
		key := fmt.Sprintf("%v", item)
		if !seenMX[key] {
			seenMX[key] = true
			clean.MXs = append(clean.MXs, item)
		}
	}

	// 9. PTRs
	seenPTR := make(map[string]bool)
	for _, item := range r.PTRs {
		key := fmt.Sprintf("%v", item)
		if !seenPTR[key] {
			seenPTR[key] = true
			clean.PTRs = append(clean.PTRs, item)
		}
	}

	// 10. TXTs
	seenTXT := make(map[string]bool)
	for _, item := range r.TXTs {
		key := fmt.Sprintf("%v", item)
		if !seenTXT[key] {
			seenTXT[key] = true
			clean.TXTs = append(clean.TXTs, item)
		}
	}

	// 11. SRVs
	seenSRV := make(map[string]bool)
	for _, item := range r.SRVs {
		key := fmt.Sprintf("%v", item)
		if !seenSRV[key] {
			seenSRV[key] = true
			clean.SRVs = append(clean.SRVs, item)
		}
	}

	// 12. CAAs
	seenCAA := make(map[string]bool)
	for _, item := range r.CAAs {
		key := fmt.Sprintf("%v", item)
		if !seenCAA[key] {
			seenCAA[key] = true
			clean.CAAs = append(clean.CAAs, item)
		}
	}

	// 13. TLSAs
	seenTLSA := make(map[string]bool)
	for _, item := range r.TLSAs {
		key := fmt.Sprintf("%v", item)
		if !seenTLSA[key] {
			seenTLSA[key] = true
			clean.TLSAs = append(clean.TLSAs, item)
		}
	}

	// 14. NAPTRs
	seenNAPTR := make(map[string]bool)
	for _, item := range r.NAPTRs {
		key := fmt.Sprintf("%v", item)
		if !seenNAPTR[key] {
			seenNAPTR[key] = true
			clean.NAPTRs = append(clean.NAPTRs, item)
		}
	}

	// 15. SOAs
	seenSOA := make(map[string]bool)
	for _, item := range r.SOAs {
		key := fmt.Sprintf("%v", item)
		if !seenSOA[key] {
			seenSOA[key] = true
			clean.SOAs = append(clean.SOAs, item)
		}
	}

	// 16. RRSIGs
	seenRRSIG := make(map[string]bool)
	for _, item := range r.RRSIGs {
		key := fmt.Sprintf("%v", item)
		if !seenRRSIG[key] {
			seenRRSIG[key] = true
			clean.RRSIGs = append(clean.RRSIGs, item)
		}
	}

	// 17. DNSKEYs
	seenDNSKEY := make(map[string]bool)
	for _, item := range r.DNSKEYs {
		key := fmt.Sprintf("%v", item)
		if !seenDNSKEY[key] {
			seenDNSKEY[key] = true
			clean.DNSKEYs = append(clean.DNSKEYs, item)
		}
	}

	// 18. DSs
	seenDS := make(map[string]bool)
	for _, item := range r.DSs {
		key := fmt.Sprintf("%v", item)
		if !seenDS[key] {
			seenDS[key] = true
			clean.DSs = append(clean.DSs, item)
		}
	}

	// 19. NSECs
	seenNSEC := make(map[string]bool)
	for _, item := range r.NSECs {
		key := fmt.Sprintf("%v", item)
		if !seenNSEC[key] {
			seenNSEC[key] = true
			clean.NSECs = append(clean.NSECs, item)
		}
	}

	// 20. NSEC3s
	seenNSEC3 := make(map[string]bool)
	for _, item := range r.NSEC3s {
		key := fmt.Sprintf("%v", item)
		if !seenNSEC3[key] {
			seenNSEC3[key] = true
			clean.NSEC3s = append(clean.NSEC3s, item)
		}
	}

	return clean
}

// parseDomainName 解析DNS域名
func parseDomainName(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return ".", offset, nil
	}

	if data[offset] == 0x00 {
		return ".", offset + 1, nil
	}

	labels := []string{}
	current := offset

	for current < len(data) {
		length := int(data[current])
		current++

		if length == 0 {
			break
		}

		if length&0xC0 == 0xC0 {
			if current >= len(data) {
				return ".", current, nil
			}
			return ".", current + 1, nil
		}

		if current+length > len(data) {
			return ".", current, nil
		}

		labels = append(labels, string(data[current:current+length]))
		current += length
	}

	if len(labels) == 0 {
		return ".", current, nil
	}

	return strings.Join(labels, ".") + ".", current, nil
}

// parseADBLine 解析 Address Database (ADB) 遥测行数据
func (p *Parser) parseADBLine(line string) {
	// 去掉开头的分号
	cleanLine := strings.TrimPrefix(line, ";")
	if cleanLine == "" {
		return
	}

	// 区分是权威域名行还是 IP 数据行
	// 域名行去前缀分号后为 " domain.name"，只以一个空格开头。
	// IP 行去前缀分号后为 "\tIP" 或 "  IP"（含两个以上空格缩进），即以制表符或多个空格开头。
	isIPLine := strings.HasPrefix(cleanLine, "\t") || strings.HasPrefix(cleanLine, "  ")

	fields := strings.Fields(cleanLine)
	if len(fields) == 0 {
		return
	}

	if !isIPLine {
		// 权威域名行
		name := fields[0]
		// 排除说明性的注释行
		if name == "Address" || name == "[edns" || name == "[plain" || strings.HasPrefix(name, "[") {
			return
		}
		// 规范化权威域名名称
		if !strings.HasSuffix(name, ".") {
			name += "."
		}
		p.currentADBName = name
	} else {
		// IP 数据行
		if p.currentADBName == "" {
			return
		}
		ip := fields[0]
		// 验证是否是非法格式（例如非IP字段）
		if strings.HasPrefix(ip, "[") {
			return
		}

		record := ADBRecord{
			Name: p.currentADBName,
			IP:   ip,
		}

		// 查找所有中括号内部的数据并解析
		currentStr := cleanLine
		for {
			startIdx := strings.IndexByte(currentStr, '[')
			if startIdx == -1 {
				break
			}
			endIdx := strings.IndexByte(currentStr[startIdx:], ']')
			if endIdx == -1 {
				break
			}
			content := currentStr[startIdx+1 : startIdx+endIdx]
			currentStr = currentStr[startIdx+endIdx+1:]

			if strings.HasPrefix(content, "cookie=") {
				record.Cookie = strings.TrimPrefix(content, "cookie=")
				continue
			}

			parts := strings.Fields(content)
			if len(parts) == 2 {
				key := parts[0]
				val := parts[1]
				switch key {
				case "srtt":
					record.SRTT, _ = strconv.Atoi(val)
				case "flags":
					record.Flags = val
				case "udpsize":
					record.UDPSize, _ = strconv.Atoi(val)
				case "ttl":
					record.TTL, _ = strconv.Atoi(val)
				case "edns":
					sub := strings.Split(val, "/")
					if len(sub) >= 2 {
						record.EDNSSuccess, _ = strconv.Atoi(sub[0])
						timeouts := make([]int, len(sub)-1)
						for index := 1; index < len(sub); index++ {
							timeouts[index-1], _ = strconv.Atoi(sub[index])
							record.EDNSTimeout += timeouts[index-1]
						}
						if len(timeouts) == 1 {
							record.EDNSTimeout4096 = timeouts[0]
						} else if len(timeouts) >= 4 {
							record.EDNSTimeout4096 = timeouts[0]
							record.EDNSTimeout1432 = timeouts[1]
							record.EDNSTimeout1232 = timeouts[2]
							record.EDNSTimeout512 = timeouts[3]
						}
					}
				case "plain":
					sub := strings.Split(val, "/")
					if len(sub) == 2 {
						record.PlainSuccess, _ = strconv.Atoi(sub[0])
						record.PlainTimeout, _ = strconv.Atoi(sub[1])
					}
				}
			}
		}

		p.adbRecords = append(p.adbRecords, record)
	}
}

// parseADBFlags 将 BIND adb entry 的十六进制标志翻译为易读的标志列表
func parseADBFlags(flagsHex string) string {
	if flagsHex == "" {
		return "0(0x00000000)"
	}
	val64, err := strconv.ParseUint(flagsHex, 16, 32)
	if err != nil {
		return fmt.Sprintf("(0x%s)", flagsHex)
	}
	val := uint32(val64)
	if val == 0 {
		return "0(0x00000000)"
	}

	var matched []string
	if val&0x00000001 != 0 {
		matched = append(matched, "FCTX_ADDRINFO_MARK")
	}
	if val&0x00000002 != 0 {
		matched = append(matched, "FCTX_ADDRINFO_FORWARDER")
	}
	if val&0x00000004 != 0 {
		matched = append(matched, "FCTX_ADDRINFO_EDNSOK")
	}
	if val&0x00000008 != 0 {
		matched = append(matched, "FCTX_ADDRINFO_NOCOOKIE")
	}
	if val&0x00000010 != 0 {
		matched = append(matched, "FCTX_ADDRINFO_BADCOOKIE")
	}
	if val&0x00000020 != 0 {
		matched = append(matched, "FCTX_ADDRINFO_DUALSTACK")
	}
	if val&0x00000040 != 0 {
		matched = append(matched, "FCTX_ADDRINFO_NOEDNS0")
	}
	if val&0x80000000 != 0 {
		matched = append(matched, "ENTRY_IS_DEAD")
	}

	if len(matched) == 0 {
		return fmt.Sprintf("UNKNOWN(0x%08x)", val)
	}
	return fmt.Sprintf("%s(0x%08x)", strings.Join(matched, "|"), val)
}
