package main

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"hash/fnv"
	"strings"
	"time"
)

type digResult struct {
	Domain      string
	TTL_A       int
	Qtype       []uint16
	RCode       int
	RR_A        []string
	RR_AAAA     []string
	RR_CNAME    []string
	RR_NS       []string
	RR_MX       []string
	RR_TXT      []string
	RR_DS       []string //dnssec
	RR_AUTHNS   []string //auth字段的NS
	RR_AUTHTYPE string
}

type TraceResult struct {
	Domain   string
	RR_A     []string
	RR_AAAA  []string
	ChildNS  []string
	ParentNs []string
}

func simpleDig(domain string, dnsAddress string) (string, error) {
	// 创建 DNS 客户端
	client := dns.Client{
		Timeout: 5 * time.Second,
	}
	message := dns.Msg{}
	message.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	// 执行 DNS 查询
	response, _, err := client.Exchange(&message, dnsAddress+":53")
	if err != nil {
		return "无响应", err
	}

	if response.Rcode == 0 {
		//如果结果是空的，也视为错误
		if len(response.Answer) == 0 {
			return "NODATA", err
		}

		//检测结果是否是127.0.0.1的错误结果，暂未找到更好的检测方法
		//if response.Len() < 100 {
		//	return "错误结果(127.0.0.1)", err
		//}
	}

	//返回状态string
	return dns.RcodeToString[response.Rcode], nil
}

// 计算 IP 地址的固定 UDP 端口
func getFixedPort(ip string) int {
	h := fnv.New32a()
	h.Write([]byte(ip))
	return int(h.Sum32()%55536) + 10000 // 1024-65535 之间的端口
}

func getDNSStatus(domain string, dnsAddress string, Qtype ...uint16) (digResult, error) {

	result := digResult{}
	result.Domain = domain

	if len(Qtype) == 0 {
		Qtype = []uint16{dns.TypeA}
	}
	result.Qtype = Qtype

	// 创建 DNS 客户端
	client := dns.Client{
		//Timeout: 5 * time.Second,

		//固定端口
		//Dialer:  &net.Dialer{
		//LocalAddr: &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: getFixedPort(dnsAddress)},
		//},
	}
	message := dns.Msg{}

	for _, qtype := range Qtype {
		message.SetQuestion(dns.Fqdn(domain), qtype)

		// 执行 DNS 查询
		response, _, err := client.Exchange(&message, dnsAddress+":53")
		if err != nil {
			//fmt.Println(err)
			return result, err
		}

		result.RCode = response.Rcode

		for _, authNSs := range response.Ns {

			fields := strings.Fields(authNSs.String())

			result.RR_AUTHTYPE = fields[3]

			authNS := fields[4]
			result.RR_AUTHNS = append(result.RR_AUTHNS, authNS)

		}

		// 遍历回答并转换为字符串
		for _, ans := range response.Answer {

			value := strings.Split(ans.String(), "\t")[4]
			switch ans.Header().Rrtype {
			case dns.TypeA:
				result.TTL_A = int(ans.Header().Ttl)
				result.RR_A = append(result.RR_A, value)
			case dns.TypeAAAA:
				result.RR_AAAA = append(result.RR_AAAA, value)
			case dns.TypeCNAME:
				result.RR_CNAME = append(result.RR_CNAME, value)
			case dns.TypeNS:
				result.RR_NS = append(result.RR_NS, value)
			case dns.TypeMX:
				result.RR_MX = append(result.RR_MX, value)
			case dns.TypeTXT:
				result.RR_TXT = append(result.RR_TXT, value)
			case dns.TypeDS:
				result.RR_DS = append(result.RR_DS, value)
			default:

			}

		}
	}

	return result, nil

}

// 获取 DNS 解析时延
func getDNSQueryLatency(domain string, dnsAddress string) (int64, error) {
	// 记录查询开始时间
	startTime := time.Now()

	// 创建 DNS 客户端
	client := dns.Client{}
	message := dns.Msg{}
	message.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	// 执行 DNS 查询
	_, _, err := client.Exchange(&message, dnsAddress+":53")
	if err != nil {
		return 0, err // 如果查询失败，返回错误
	}

	// 计算查询时延
	latency := time.Since(startTime).Milliseconds()
	return latency, nil
}

func getTraceResult(domain string) (*TraceResult, error) {
	traceResult := new(TraceResult)
	err := traceResult.digTrace(domain, 0, dns.TypeA)
	if err != nil {
		return nil, err
	}
	return traceResult, nil
}

// 模拟dig +trace，获取迭代的最终结果和父子NS
// 如何理解：父子NS：在迭代过程中，第n-1次迭代的authNS 和 第n次的authNS
func (t *TraceResult) digTrace(domain string, depth int, Qtype ...uint16) error {
	const maxDepth = 10 // 最大递归深度
	const maxRecursion = 10
	Recursion := 0
	if depth == 0 {
		t.Domain = domain
	}

	// 默认查询 A 记录
	QueryType := dns.TypeA
	if len(Qtype) != 0 {
		QueryType = Qtype[0]
	}

	// 检查递归深度
	if depth > maxDepth {
		return errors.New("超过最大递归深度")
	}

	//初始化查询
	digResponse, _ := getDNSStatus(".", "112.4.0.55", QueryType)
	//fmt.Println(digResponse)

	//获取NS和父级NS
	//if len(t.ParentNs) == 0 {
	//	//第一次迭代时，记录ns
	//	t.ParentNs = digResponse.RR_AUTHNS
	//	t.ChildNS = digResponse.RR_AUTHNS
	//}

	//fmt.Printf("初始化：\np: %s\nC: %s\n", t.ParentNs, t.ChildNS)

	for digResponse.RCode == 0 && len(digResponse.RR_AUTHNS) > 0 && Recursion < maxRecursion {
		Recursion++

		//如果没有迭代完成，则更新父NS结果（n-1）
		t.ParentNs = digResponse.RR_AUTHNS

		//继续迭代
		//fmt.Printf("dig @%s %s\n", digResponse.RR_AUTHNS[0], domain)
		digResponse, _ = getDNSStatus(domain, digResponse.RR_AUTHNS[0], QueryType)

		childNs := digResponse.RR_AUTHNS

		if digResponse.RR_AUTHTYPE == "SOA" {
			childNs = []string{}
		}

		//fmt.Printf("dig @%s %s 的AUTH字段为：%s\n", ns, domain, digResponse.RR_AUTHNS)
		//fmt.Println("dig 结果： ", dns.RcodeToString[int(digResponse.RCode)])
		//fmt.Printf("authns长度为%d\n", len(digResponse.RR_AUTHNS))

		//trace中断，退出
		if digResponse.RCode != dns.RcodeSuccess {
			//更新子NS
			//fmt.Println("结果异常，推出")
			t.ChildNS = childNs
			return nil
		}

		//出现cname，迭代查询
		if len(digResponse.RR_CNAME) > 0 {
			return t.digTrace(digResponse.RR_CNAME[0], depth+1, QueryType)
		}

		//fmt.Printf("p: %s\nC: %s\n", t.ParentNs, t.ChildNS)

		switch QueryType {
		case dns.TypeA:
			if len(digResponse.RR_A) > 0 {
				t.RR_A = digResponse.RR_A
				//更新子NS
				t.ChildNS = childNs
				return nil
			}
		case dns.TypeAAAA:
			if len(digResponse.RR_AAAA) > 0 {
				t.RR_AAAA = digResponse.RR_AAAA
				//更新子NS
				t.ChildNS = childNs
				return nil
			}
		default:
		}

	}
	return fmt.Errorf("not result")

}

// 模拟dig +trace，仅获取最终结果
func digTraceSimple(domain string, depth int, Qtype ...uint16) ([]string, error) {
	const maxDepth = 10 // 最大递归深度

	QueryType := dns.TypeA

	if len(Qtype) != 0 {
		QueryType = Qtype[0]
	}

	if depth > maxDepth {
		return nil, errors.New("超过最大递归深度")
	}
	digResponse, _ := getDNSStatus(".", "112.4.0.55", QueryType)

	for digResponse.RCode == 0 && len(digResponse.RR_AUTHNS) > 0 {

		//fmt.Printf("dig @%s %s\n", firstDig.RR_AUTHNS[0], domain)
		digResponse, _ = getDNSStatus(domain, digResponse.RR_AUTHNS[0], QueryType)
		if len(digResponse.RR_CNAME) > 0 {
			return digTraceSimple(digResponse.RR_CNAME[0], depth+1, QueryType)
		}

		switch QueryType {
		case dns.TypeA:
			if len(digResponse.RR_A) > 0 {
				return digResponse.RR_A, nil
			}
		case dns.TypeAAAA:
			if len(digResponse.RR_AAAA) > 0 {
				return digResponse.RR_AAAA, nil

			}
		default:
		}

	}
	return nil, fmt.Errorf("not result")

}
