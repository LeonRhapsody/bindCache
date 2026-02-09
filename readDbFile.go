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
	TTL        int    // MX 记录的 TTL
	Priority   int    // MX 优先级
	MailServer string // 邮件服务器域名
	Attribute  string // 属性（authanswer 或 glue）
	Rcode      string // Rcode（如 nxdomain、nxrrset）
}

// PTR 记录结构体
type PTR struct {
	TTL       int    // PTR 记录的 TTL
	Target    string // 目标域名
	Attribute string // 属性（authanswer 或 glue）
	Rcode     string // Rcode（如 nxdomain、nxrrset）
}

// TXT 记录结构体
type TXT struct {
	TTL       int    // TXT 记录的 TTL
	Content   string // TXT 内容
	Attribute string // 属性（authanswer 或 glue）
	Rcode     string // Rcode（如 nxdomain、nxrrset）
}

// Record 表示一条 DNS 记录
type Record struct {
	NSs    []NS     // NS 记录
	As     []A      // A 记录
	AAAAs  []AAAA   // AAAA 记录
	ANYs   []ANY    // ANY 记录
	TYPE65 []TYPE65 // TYPE65 记录
	TYPE64 []TYPE64
	CNAMEs []CNAME // CNAME 记录
	MXs    []MX    // MX 记录
	PTRs   []PTR   // PTR 记录
	TXTs   []TXT   // TXT 记录
}

type NS struct {
	NsDomain  string // NS 域名
	TTL       int    // NS 的 TTL
	IP        string // NS 的 IP（如果有）
	Attribute string // 属性（authanswer 或 glue）
}

type A struct {
	TTL       int    // A 记录的 TTL
	IP        string // A 记录的 IP（为空时表示无 IP）
	Attribute string // 属性（authanswer 或 glue）
	Rcode     string // Rcode（如 nxdomain、nxrrset）
}

type AAAA struct {
	TTL       int    // AAAA 记录的 TTL
	IP        string // AAAA 记录的 IP（为空时表示无 IP）
	Attribute string // 属性（authanswer 或 glue）
	Rcode     string // Rcode（如 nxdomain、nxrrset）
}

type ANY struct {
	TTL       int    // ANY 记录的 TTL
	IP        string // ANY 记录的值（为空时表示无值）
	Attribute string // 属性（authanswer 或 glue）
	Rcode     string // Rcode（如 nxdomain、nxrrset）
}

type TYPE65 struct {
	TTL       int    // TYPE65 记录的 TTL
	IP        string // TYPE65 记录的值（为空时表示无值）
	Attribute string // 属性（authanswer 或 glue）
	Rcode     string // Rcode（如 nxdomain、nxrrset）
}

type TYPE64 struct {
	TTL       int    // TYPE65 记录的 TTL
	IP        string // TYPE65 记录的值（为空时表示无值）
	Attribute string // 属性（authanswer 或 glue）
	Rcode     string // Rcode（如 nxdomain、nxrrset）
}

type CNAME struct {
	TTL       int    // CNAME 记录的 TTL
	IP        string // CNAME 目标（为空时表示无值）
	Attribute string // 属性（authanswer 或 glue）
	Rcode     string // Rcode（如 nxdomain、nxrrset）
}

// Parser 定义解析器，封装状态和模板
type Parser struct {
	records          map[string]Record
	nxdomainRecords  map[string]Record
	nxrrsetRecords   map[string]Record
	currentDomain    string
	currentAttribute string
	currentTTL       int
	inCache          bool
	normalPattern    *regexp.Regexp // 普通记录模板
	specialPattern   *regexp.Regexp // 特殊记录模板
	domainPattern    *regexp.Regexp
	// 多行记录处理
	inMultiLine     bool
	multiLineBuffer string
	multiLineType   string
}

// NewParser 创建一个新的解析器
func NewParser() *Parser {
	const initialCapacity = 1000
	return &Parser{
		records:         make(map[string]Record, initialCapacity),
		nxdomainRecords: make(map[string]Record, initialCapacity/10),
		nxrrsetRecords:  make(map[string]Record, initialCapacity/10),
		normalPattern:   regexp.MustCompile(`^([^\s]+)?\s*(\d+)\s+(IN\s+NS|NS|A|AAAA|CNAME|ANY|TYPE65|IN\s+SOA|SOA|IN\s+MX|MX|IN\s+PTR|PTR|IN\s+TXT|TXT)\s+([^\s]+(?:\s+[^\s]+(?:\s*\(.*)?)?)$`),
		specialPattern:  regexp.MustCompile(`^([^\s]+)?\s*(\d+)\s+\\-(A|AAAA|CNAME|ANY|TYPE65|MX|PTR|TXT)\s+;\-\$([^\s]+)$`),
		domainPattern:   regexp.MustCompile(`^.*\.$`),
	}
}

// ParseDNSCacheFile 解析 DNS 缓存文件
func ParseDNSCacheFile(filename string) (*BindCache, error) {

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	parser := NewParser()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024) // 1MB 缓冲区

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
	}, nil

}

// parseLine 处理单行数据
func (p *Parser) parseLine(line string) {
	// 检测 BindCache dump 状态
	switch {
	case strings.Contains(line, "Cache dump of view"):
		p.inCache = true
		return
	case strings.Contains(line, "Address database dump") || strings.Contains(line, "Start view"):
		p.inCache = false
		return
	}

	if !p.inCache {
		return
	}

	// 检测属性注释
	if strings.HasPrefix(line, ";") {
		line = strings.TrimSpace(strings.TrimPrefix(line, ";"))
		switch line {
		case "authanswer":
			p.currentAttribute = "authanswer"
		case "glue":
			p.currentAttribute = "glue"
		case "answer":
			p.currentAttribute = "answer"
		default:
			// 忽略其他注释
		}
		return
	}

	// 跳过 $ 开头的行
	if strings.HasPrefix(line, "$") {
		return
	}

	// 多行记录处理
	if p.inMultiLine {
		// 移除行首空白字符
		trimmedLine := strings.TrimLeft(line, " 	")
		p.multiLineBuffer += trimmedLine

		// 检查是否到达多行记录结束
		if strings.Contains(trimmedLine, ")") {
			p.inMultiLine = false
			// 处理完整的多行记录
			if p.multiLineType == "TYPE65" {
				// 提取括号内的内容
				content := strings.Trim(p.multiLineBuffer, "() ")
				// 移除所有空白字符
				content = strings.ReplaceAll(content, " ", "")
				// 创建匹配项并调用parseNormal
				matches := []string{
					"",                         // 整体匹配
					p.currentDomain,            // 域名
					strconv.Itoa(p.currentTTL), // TTL
					"TYPE65",                   // 类型
					content,                    // 值
				}
				p.parseNormal(matches)
			}
			// 重置缓冲区
			p.multiLineBuffer = ""
			p.multiLineType = ""
		}
		return
	}

	// 检查是否是TYPE65多行记录的开始
	type65StartPattern := regexp.MustCompile(`^([^\s]+)?\s*(\d+)\s+(TYPE65)\s+\\#\s+\d+\s*\(\s*`)
	if matches := type65StartPattern.FindStringSubmatch(line); matches != nil {
		p.inMultiLine = true
		p.multiLineType = "TYPE65"
		p.currentDomain = strings.TrimSpace(matches[1])
		p.currentTTL, _ = strconv.Atoi(matches[2])
		p.ensureDomain(p.currentDomain)
		// 提取第一行中的部分内容
		firstPart := strings.TrimPrefix(line, type65StartPattern.FindString(line))
		p.multiLineBuffer = firstPart
		return
	}

	// 匹配普通记录
	if matches := p.normalPattern.FindStringSubmatch(line); matches != nil {
		p.parseNormal(matches)
		return
	}

	// 尝试匹配没有域名前缀的记录格式（域名继承）
	// 检查是否是缩进格式的记录（表示继承前面的域名）
	indentPattern := regexp.MustCompile(`^\s+(\d+)\s+(A|AAAA|CNAME|ANY|TYPE65|IN\s+SOA|SOA|IN\s+MX|MX|IN\s+PTR|PTR|IN\s+TXT|TXT)\s+(.+)$`)
	if matches := indentPattern.FindStringSubmatch(line); matches != nil && p.currentDomain != "" {
		// 使用当前域名来解析这条记录
		newMatches := []string{
			matches[0],      // 整体匹配
			p.currentDomain, // 域名（继承当前域名）
			matches[1],      // TTL
			matches[2],      // 类型
			matches[3],      // 值
		}
		p.parseNormal(newMatches)
		return
	}

	// 匹配特殊记录
	if matches := p.specialPattern.FindStringSubmatch(line); matches != nil {
		p.parseSpecial(matches)
		return
	}
}

// ensureDomain 确保域名在 records 中初始化
func (p *Parser) ensureDomain(domain string) {
	if _, exists := p.records[domain]; !exists {
		p.records[domain] = Record{
			NSs:    make([]NS, 0, 2),
			As:     make([]A, 0, 2),
			AAAAs:  make([]AAAA, 0, 2),
			ANYs:   make([]ANY, 0, 2),
			TYPE65: make([]TYPE65, 0, 2),
			CNAMEs: make([]CNAME, 0, 2),
			MXs:    make([]MX, 0, 2),
			PTRs:   make([]PTR, 0, 2),
			TXTs:   make([]TXT, 0, 2),
		}
	}
}

// parseNormal 解析普通记录
func (p *Parser) parseNormal(matches []string) {
	domain := strings.TrimSpace(matches[1])
	ttl, _ := strconv.Atoi(matches[2])
	dnsType := matches[3]
	value := matches[4]

	if domain != "" && p.domainPattern.MatchString(domain) {
		p.currentDomain = domain
		p.ensureDomain(domain)
	}

	if p.currentDomain == "" {
		// fmt.Printf("警告: 记录缺少域名上下文: %s\n", value)
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
	case "ANY":
		record.ANYs = append(record.ANYs, ANY{
			TTL:       ttl,
			IP:        value,
			Attribute: attr,
		})
	case "IN MX", "MX":
		// MX记录格式: priority mailServer
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
	case "TYPE65":
		// 解码16进制字符串为字节数组
		// 预处理：移除所有非十六进制字符
		cleanValue := regexp.MustCompile(`[^0-9a-fA-F]`).ReplaceAllString(value, "")
		// 处理奇数长度
		if len(cleanValue)%2 != 0 {
			// log.Printf("TYPE65数据长度为奇数，自动补零: %s -> %s0", cleanValue, cleanValue)
			cleanValue += "0"
		}

		// 解析十六进制数据
		data, err := hex.DecodeString(cleanValue)
		if err != nil {
			// fmt.Printf("解码TYPE65数据失败: %v\n", err)
			record.TYPE65 = append(record.TYPE65, TYPE65{
				TTL:       ttl,
				IP:        "解码失败",
				Attribute: attr,
			})
			p.records[p.currentDomain] = record
			return
		}

		// 开始解析 TYPE65 记录
		priority := int(binary.BigEndian.Uint16(data[0:2]))
		targetName, offset, _ := parseDomainName(data, 2)

		// 解析 SVCB 参数
		params := []string{}
		for offset < len(data) {
			// 检查是否有足够的数据来读取key和length
			if offset+4 > len(data) {
				break
			}

			key := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
			offset += 4

			// 检查值部分是否超出数据范围
			if offset+length > len(data) {
				break
			}

			valueBytes := data[offset : offset+length]

			// 根据 RFC 9460 解析标准参数
			switch key {
			case 1: // alpn
				// ALPN 列表是一系列长度前缀的字符串
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
			case 4: // ipv4hint
				// IPv4hint 是一系列 4 字节的 IP 地址
				if len(valueBytes)%4 == 0 {
					var ipv4s []string
					for i := 0; i < len(valueBytes); i += 4 {
						ipv4 := net.IP(valueBytes[i : i+4])
						ipv4s = append(ipv4s, ipv4.String())
					}
					params = append(params, fmt.Sprintf("ipv4hint=\"%s\"", strings.Join(ipv4s, ",")))
				}
			case 6: // ipv6hint
				// IPv6hint 是一系列 16 字节的 IP 地址
				if len(valueBytes)%16 == 0 {
					var ipv6s []string
					for i := 0; i < len(valueBytes); i += 16 {
						ipv6 := net.IP(valueBytes[i : i+16])
						ipv6s = append(ipv6s, ipv6.String())
					}
					params = append(params, fmt.Sprintf("ipv6hint=\"%s\"", strings.Join(ipv6s, ",")))
				}
			case 5: // echconfig
				if len(valueBytes) > 0 {
					// ECH配置完整显示为十六进制
					params = append(params, fmt.Sprintf("echconfig=0x%X", valueBytes))
				}
			default:
				// 非标准参数，根据key值范围决定是否显示
				if key <= 65535 && len(valueBytes) <= 256 {
					params = append(params, fmt.Sprintf("key%d=0x%X", key, valueBytes))
				}
			}

			offset += length
		}

		// 格式化可读输出
		readableValue := fmt.Sprintf("SVCB(priority=%d, target=%s, params=[%s])",
			priority, targetName, strings.Join(params, ", "))

		record.TYPE65 = append(record.TYPE65, TYPE65{
			TTL:       ttl,
			IP:        readableValue,
			Attribute: attr,
		})
	}

	p.records[p.currentDomain] = record
}

// parseSpecial 解析特殊记录
func (p *Parser) parseSpecial(matches []string) {
	domain := strings.TrimSpace(matches[1])
	ttl, _ := strconv.Atoi(matches[2])
	dnsType := matches[3]
	rcode := strings.ToLower(matches[4])

	if domain != "" && p.domainPattern.MatchString(domain) {
		p.currentDomain = domain
		p.ensureDomain(domain)
	}
	if p.currentDomain == "" {
		// fmt.Println(matches)
		// fmt.Printf("警告: Special 记录缺少域名上下文: %s %s\n", dnsType, rcode)
		return
	}

	attr := p.currentAttribute
	if attr == "" {
		attr = "unknown"
	}

	record := p.records[p.currentDomain]
	switch dnsType {
	case "A":
		record.As = append(record.As, A{
			TTL:       ttl,
			IP:        "",
			Attribute: attr,
			Rcode:     rcode,
		})
	case "AAAA":
		record.AAAAs = append(record.AAAAs, AAAA{
			TTL:       ttl,
			IP:        "",
			Attribute: attr,
			Rcode:     rcode,
		})
	case "CNAME":
		record.CNAMEs = append(record.CNAMEs, CNAME{
			TTL:       ttl,
			IP:        "",
			Attribute: attr,
			Rcode:     rcode,
		})
	case "ANY":
		record.ANYs = append(record.ANYs, ANY{
			TTL:       ttl,
			IP:        "",
			Attribute: attr,
			Rcode:     rcode,
		})
	case "TYPE65":
		record.TYPE65 = append(record.TYPE65, TYPE65{
			TTL:       ttl,
			IP:        "",
			Attribute: attr,
			Rcode:     rcode,
		})
	case "TYPE64":
		record.TYPE64 = append(record.TYPE64, TYPE64{
			TTL:       ttl,
			IP:        "",
			Attribute: attr,
			Rcode:     rcode,
		})
	case "MX":
		record.MXs = append(record.MXs, MX{
			TTL:        ttl,
			Priority:   0,
			MailServer: "",
			Attribute:  attr,
			Rcode:      rcode,
		})
	case "PTR":
		record.PTRs = append(record.PTRs, PTR{
			TTL:       ttl,
			Target:    "",
			Attribute: attr,
			Rcode:     rcode,
		})
	case "TXT":
		record.TXTs = append(record.TXTs, TXT{
			TTL:       ttl,
			Content:   "",
			Attribute: attr,
			Rcode:     rcode,
		})
	}
	p.records[p.currentDomain] = record
	if rcode == "nxdomain" {
		p.nxdomainRecords[p.currentDomain] = record
	} else if rcode == "nxrrset" {
		p.nxrrsetRecords[p.currentDomain] = record
	}
}

// String 用于格式化输出 Record
func (r Record) String() string {
	nsStr := fmt.Sprintf("%v", r.NSs)

	var asStr string
	if len(r.As) == 0 {
		asStr = "[]"
	} else {
		asItems := make([]string, 0, len(r.As))
		for _, a := range r.As {
			if a.Rcode != "" {
				asStr = fmt.Sprintf("[{TTL=%d, Rcode=%s, Attribute=%s}]", a.TTL, a.Rcode, a.Attribute)
				break
			} else {
				asItems = append(asItems, fmt.Sprintf("{TTL=%d, IP=%s, Attribute=%s}", a.TTL, a.IP, a.Attribute))
			}
		}
		if len(asItems) > 0 {
			asStr = fmt.Sprintf("[%s]", strings.Join(asItems, " "))
		}
	}

	var aaaasStr string
	if len(r.AAAAs) == 0 {
		aaaasStr = "[]"
	} else {
		aaaasItems := make([]string, 0, len(r.AAAAs))
		for _, aaaa := range r.AAAAs {
			if aaaa.Rcode != "" {
				aaaasStr = fmt.Sprintf("[{TTL=%d, Rcode=%s, Attribute=%s}]", aaaa.TTL, aaaa.Rcode, aaaa.Attribute)
				break
			} else {
				aaaasItems = append(aaaasItems, fmt.Sprintf("{TTL=%d, IP=%s, Attribute=%s}", aaaa.TTL, aaaa.IP, aaaa.Attribute))
			}
		}
		if len(aaaasItems) > 0 {
			aaaasStr = fmt.Sprintf("[%s]", strings.Join(aaaasItems, " "))
		}
	}

	var anyStr string
	if len(r.ANYs) == 0 {
		anyStr = "[]"
	} else {
		anyItems := make([]string, 0, len(r.ANYs))
		for _, any := range r.ANYs {
			if any.Rcode != "" {
				anyStr = fmt.Sprintf("[{TTL=%d, Rcode=%s, Attribute=%s}]", any.TTL, any.Rcode, any.Attribute)
				break
			} else {
				anyItems = append(anyItems, fmt.Sprintf("{TTL=%d, IP=%s, Attribute=%s}", any.TTL, any.IP, any.Attribute))
			}
		}
		if len(anyItems) > 0 {
			anyStr = fmt.Sprintf("[%s]", strings.Join(anyItems, " "))
		}
	}

	var type65Str string
	if len(r.TYPE65) == 0 {
		type65Str = "[]"
	} else {
		type65Items := make([]string, 0, len(r.TYPE65))
		for _, t65 := range r.TYPE65 {
			if t65.Rcode != "" {
				type65Str = fmt.Sprintf("[{TTL=%d, Rcode=%s, Attribute=%s}]", t65.TTL, t65.Rcode, t65.Attribute)
				break
			} else {
				type65Items = append(type65Items, fmt.Sprintf("{TTL=%d, IP=%s, Attribute=%s}", t65.TTL, t65.IP, t65.Attribute))
			}
		}
		if len(type65Items) > 0 {
			type65Str = fmt.Sprintf("[%s]", strings.Join(type65Items, " "))
		}
	}

	var type64Str string
	if len(r.TYPE64) == 0 {
		type64Str = "[]"
	} else {
		type64Items := make([]string, 0, len(r.TYPE64))
		for _, t64 := range r.TYPE64 {
			if t64.Rcode != "" {
				type64Str = fmt.Sprintf("[{TTL=%d, Rcode=%s, Attribute=%s}]", t64.TTL, t64.Rcode, t64.Attribute)
				break
			} else {
				type64Items = append(type64Items, fmt.Sprintf("{TTL=%d, IP=%s, Attribute=%s}", t64.TTL, t64.IP, t64.Attribute))
			}
		}
		if len(type64Items) > 0 {
			type64Str = fmt.Sprintf("[%s]", strings.Join(type64Items, " "))
		}
	}

	var cnameStr string
	if len(r.CNAMEs) == 0 {
		cnameStr = "[]"
	} else {
		cnameItems := make([]string, 0, len(r.CNAMEs))
		for _, cname := range r.CNAMEs {
			if cname.Rcode != "" {
				cnameStr = fmt.Sprintf("[{TTL=%d, Rcode=%s, Attribute=%s}]", cname.TTL, cname.Rcode, cname.Attribute)
				break
			} else {
				cnameItems = append(cnameItems, fmt.Sprintf("{TTL=%d, IP=%s, Attribute=%s}", cname.TTL, cname.IP, cname.Attribute))
			}
		}
		if len(cnameItems) > 0 {
			cnameStr = fmt.Sprintf("[%s]", strings.Join(cnameItems, " "))
		}
	}

	var mxStr string
	if len(r.MXs) == 0 {
		mxStr = "[]"
	} else {
		mxItems := make([]string, 0, len(r.MXs))
		for _, mx := range r.MXs {
			if mx.Rcode != "" {
				mxStr = fmt.Sprintf("[{TTL=%d, Rcode=%s, Attribute=%s}]", mx.TTL, mx.Rcode, mx.Attribute)
				break
			} else {
				mxItems = append(mxItems, fmt.Sprintf("{TTL=%d, Priority=%d, MailServer=%s, Attribute=%s}", mx.TTL, mx.Priority, mx.MailServer, mx.Attribute))
			}
		}
		if len(mxItems) > 0 {
			mxStr = fmt.Sprintf("[%s]", strings.Join(mxItems, " "))
		}
	}

	var ptrStr string
	if len(r.PTRs) == 0 {
		ptrStr = "[]"
	} else {
		ptrItems := make([]string, 0, len(r.PTRs))
		for _, ptr := range r.PTRs {
			if ptr.Rcode != "" {
				ptrStr = fmt.Sprintf("[{TTL=%d, Rcode=%s, Attribute=%s}]", ptr.TTL, ptr.Rcode, ptr.Attribute)
				break
			} else {
				ptrItems = append(ptrItems, fmt.Sprintf("{TTL=%d, Target=%s, Attribute=%s}", ptr.TTL, ptr.Target, ptr.Attribute))
			}
		}
		if len(ptrItems) > 0 {
			ptrStr = fmt.Sprintf("[%s]", strings.Join(ptrItems, " "))
		}
	}

	var txtStr string
	if len(r.TXTs) == 0 {
		txtStr = "[]"
	} else {
		txtItems := make([]string, 0, len(r.TXTs))
		for _, txt := range r.TXTs {
			if txt.Rcode != "" {
				txtStr = fmt.Sprintf("[{TTL=%d, Rcode=%s, Attribute=%s}]", txt.TTL, txt.Rcode, txt.Attribute)
				break
			} else {
				txtItems = append(txtItems, fmt.Sprintf("{TTL=%d, Content=%s, Attribute=%s}", txt.TTL, txt.Content, txt.Attribute))
			}
		}
		if len(txtItems) > 0 {
			txtStr = fmt.Sprintf("[%s]", strings.Join(txtItems, " "))
		}
	}

	return fmt.Sprintf("NSs: %s, As: %s, AAAAs: %s, ANY: %s, TYPE65: %s,TYPE64: %s, CNAME: %s, MX: %s, PTR: %s, TXT: %s",
		nsStr, asStr, aaaasStr, anyStr, type65Str, type64Str, cnameStr, mxStr, ptrStr, txtStr)
}

// parseDomainName 解析DNS域名（处理根域名和标准域名格式）
func parseDomainName(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return ".", offset, nil
	}

	// 根域名（0x00）
	if data[offset] == 0x00 {
		return ".", offset + 1, nil
	}

	// 处理标准域名格式
	labels := []string{}
	current := offset

	for current < len(data) {
		length := int(data[current])
		current++

		if length == 0 {
			break
		}

		// 检查是否为压缩指针（0xC0开头）
		if length&0xC0 == 0xC0 {
			if current >= len(data) {
				return ".", current, nil
			}
			return ".", current + 1, nil // 简化处理，返回根域名
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

	return strings.Join(labels, "."), current, nil
}

// parseSvcParam 解析SVCB参数值
func parseSvcParam(key uint16, value []byte) (string, error) {
	switch key {
	case 0x0000: // Reserved
		return fmt.Sprintf("reserved=0x%X", value), nil
	case 0x0001: // ALPN
		var alpn []string
		offset := 0
		for offset < len(value) {
			if offset+1 > len(value) {
				return "", fmt.Errorf("ALPN格式错误: 长度字节不足")
			}
			strLen := int(value[offset])
			offset++
			if offset+strLen > len(value) {
				return "", fmt.Errorf("ALPN格式错误: 字符串长度不足")
			}
			alpn = append(alpn, string(value[offset:offset+strLen]))
			offset += strLen
		}
		return fmt.Sprintf("alpn=\"%s\"", strings.Join(alpn, ",")), nil
	case 0x0004: // IPv4Hint
		if len(value)%4 != 0 {
			return "", fmt.Errorf("IPv4Hint长度必须是4的倍数")
		}
		var ips []string
		for i := 0; i < len(value); i += 4 {
			ip := net.IPv4(value[i], value[i+1], value[i+2], value[i+3]).String()
			ips = append(ips, ip)
		}
		return fmt.Sprintf("ipv4hint=\"%s\"", strings.Join(ips, ",")), nil
	case 0x0006: // IPv6Hint
		if len(value)%16 != 0 {
			return "", fmt.Errorf("IPv6Hint长度必须是16的倍数")
		}
		var ips []string
		for i := 0; i < len(value); i += 16 {
			ip := net.IP(value[i : i+16]).String()
			ips = append(ips, ip)
		}
		return fmt.Sprintf("ipv6hint=\"%s\"", strings.Join(ips, ",")), nil
	default:
		return fmt.Sprintf("key=0x%04X, value=0x%X", key, value), nil
	}
}
