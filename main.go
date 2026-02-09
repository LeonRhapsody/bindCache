package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type BindCache struct {
	dnsServer       string
	records         map[string]Record
	nxdomainRecords map[string]Record
	nxrrsetRecords  map[string]Record
	domainNsRecirds map[string][]string
}

func (bC *BindCache) getDomainNs(domain string) (result []string) {

	for _, ns := range bC.records[domain].NSs {
		result = append(result, ns.NsDomain)
	}

	return result

}

func (bC *BindCache) getDomain(domain string) {

	if record, exists := bC.records[domain]; exists {
		fmt.Printf("Domain (%s): %s\n\n", domain, record)
	} else {
		fmt.Printf("未找到域名: %s\n", domain)
	}

}

func (bC *BindCache) dig() {

	x := 0
	num := 0
	var buffer bytes.Buffer
	tasks := make(chan string, 100)

	// 分发扫描任务
	go func() {
		for domain, _ := range bC.nxrrsetRecords {
			tasks <- domain
		}
		close(tasks)
	}()

	// 启动 worker Goroutine
	var wg sync.WaitGroup

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range tasks {

				status, _ := simpleDig(domain, "112.4.0.55")
				x++
				if status != "NOERROR" && status != "NODATA" {
					num++
					buffer.WriteString(fmt.Sprintf("%s|%s\n", status, domain))
				}
				fmt.Printf("%d,%d/%d\n", num, x, len(bC.nxrrsetRecords))
			}
		}()
	}

	wg.Wait()

	file, err := os.Create("fail.txt")
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	buffer.WriteTo(file)
}

func (bC *BindCache) parentAndChildCheck() {

	x := 0
	num := 0
	var buffer bytes.Buffer
	tasks := make(chan string, 100)

	// 分发扫描任务
	go func() {
		for domain, _ := range bC.nxdomainRecords {
			tasks <- domain
		}
		close(tasks)
	}()

	// 启动 worker Goroutine
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range tasks {
				x++

				result, err := getTraceResult(domain)
				if err != nil {
					continue
				}

				childNS := result.ChildNS
				parentNS := result.ParentNs
				if !areCnameContains(childNS, parentNS) && len(childNS) > 0 {
					num++
					fmt.Println(domain, childNS, parentNS)
					buffer.WriteString(fmt.Sprintf("%s|%s|%s\n", domain, childNS, parentNS))
				}
				fmt.Printf("%d,%d/%d\n", num, x, len(bC.nxdomainRecords))
			}
		}()
	}

	wg.Wait()

	file, err := os.Create("deffer.txt")
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	buffer.WriteTo(file)
}

// 输出NSip信息
func (bC *BindCache) outputNSIPToTxt() {

	nsIP := make(map[string]int)
	for _, record := range bC.records {
		if len(record.NSs) > 0 {
			for _, ns := range record.NSs {
				for _, a := range bC.records[ns.NsDomain].As {
					nsIP[a.IP] = 0
				}
				for _, aaaa := range bC.records[ns.NsDomain].AAAAs {

					nsIP[aaaa.IP] = 0
				}
				//fmt.Println(domain, ns.NsDomain, strings.Join(str, ","))

			}
		}
	}

	var buffer bytes.Buffer
	fmt.Printf("发现%d个权威IP\n", len(nsIP))
	// 记录开始时间

	for ip, _ := range nsIP {
		buffer.WriteString(ip + "\n")
	}

	file, err := os.Create("nsIP.txt." + time.Now().Format("0102150405"))
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	buffer.WriteTo(file)
}

// 输出NSip信息
func (bC *BindCache) outputNSIP() {

	// 读取 IP 地址段文件，构建 IP 范围列表
	_, map1, err := readIPRanges("vip.txt")
	if err != nil {
		log.Fatalf("Failed to read IP range file: %v", err)
	}
	fmt.Println("读取归属信息完成")

	nsIPToDomain := make(map[string][]string)
	for domain, record := range bC.records {
		if len(record.NSs) > 0 {
			for _, ns := range record.NSs {
				var str []string
				for _, a := range bC.records[ns.NsDomain].As {
					str = append(str, a.IP)
					nsIPToDomain[a.IP] = append(nsIPToDomain[a.IP], domain)
				}
				for _, aaaa := range bC.records[ns.NsDomain].AAAAs {
					str = append(str, aaaa.IP)
					nsIPToDomain[aaaa.IP] = append(nsIPToDomain[aaaa.IP], domain)
				}
				//fmt.Println(domain, ns.NsDomain, strings.Join(str, ","))

			}
		}
	}

	var buffer bytes.Buffer
	fmt.Printf("发现%d个权威IP\n", len(nsIPToDomain))
	// 记录开始时间
	startTime := time.Now()
	num := 0

	go func() {
		for int(num) < len(nsIPToDomain) {
			// 每秒输出一次进度
			time.Sleep(1 * time.Second)

			// 计算已耗时
			elapsedTime := time.Since(startTime)

			// 刷新输出：包括处理进度和已耗时
			fmt.Printf("\r%s %d(%.2f%%) 已耗时: %v", "匹配完成：", num, (float32(num)/float32(len(nsIPToDomain)))*100, elapsedTime)

		}
	}()

	buffer.WriteString("NS IP归属,NS IP,解析域名数,域名清单\n")
	for ip, domains := range nsIPToDomain {
		var result string
		if ok, client := isInIPRanges(ip, &map1); ok {
			result = client
		} else {
			result = "未知"
		}
		num++
		if len(domains) > 50 {
			buffer.WriteString(fmt.Sprintf("%s,%s,%d,%s\n", result, ip, len(domains), "过长不显示"))

		} else {
			buffer.WriteString(fmt.Sprintf("%s,%s,%d,%s\n", result, ip, len(domains), strings.Join(domains, "|")))

		}
	}

	file, err := os.Create("ipToDomain.csv")
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	buffer.WriteTo(file)
}

// 输出NSip信息
func (bC *BindCache) outputType65() {

	t65Map := make(map[string]string)
	t64Map := make(map[string]string)

	for domain, record := range bC.records {
		if len(record.TYPE65) > 0 && record.TYPE65[0].Rcode != "nxrrset" {
			t65Map[domain] = record.TYPE65[0].IP
		}
		if len(record.TYPE64) > 0 {
			t64Map[domain] = record.TYPE64[0].IP
		}
	}

	var buffer bytes.Buffer
	fmt.Printf("发现%d个65,%d个64\n", len(t65Map), len(t64Map))
	// 记录开始时间
	for domain, result := range t65Map {
		buffer.WriteString(domain + "|" + result + "\n")
	}

	file, err := os.Create("type65.txt" + time.Now().Format("20060102150405"))
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	buffer.WriteTo(file)
	buffer.Reset()
	for domain, result := range t64Map {
		buffer.WriteString(domain + "|" + result + "\n")
	}

	file2, err := os.Create("type64.txt" + time.Now().Format("20060102150405"))
	if err != nil {
		fmt.Println(err)
	}
	defer file2.Close()

	buffer.WriteTo(file2)
}

// 输出NSip信息
// 输出PTR记录信息
func (bC *BindCache) outputPTR() {

	ptrMap := make(map[string][]string)

	for domain, record := range bC.records {
		if len(record.PTRs) > 0 {
			var ptrTargets []string
			for _, v := range record.PTRs {
				// 将PTR记录的目标域名添加到列表中
				ptrTargets = append(ptrTargets, v.Target)
			}
			ptrMap[domain] = ptrTargets
		}
	}

	var buffer bytes.Buffer
	fmt.Printf("发现%d个PTR记录\n", len(ptrMap))
	// 记录开始时间
	for domain, ptrTargets := range ptrMap {
		buffer.WriteString(domain + "|" + strings.Join(ptrTargets, ",") + "\n")
	}

	file, err := os.Create("ptr_records.txt" + time.Now().Format("20060102150405"))
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	buffer.WriteTo(file)
}

// 输出TXT记录信息
func (bC *BindCache) outputTXT() {

	TXTMap := make(map[string][]string)

	for domain, record := range bC.records {
		if len(record.TXTs) > 0 {
			var txtContents []string
			for _, v := range record.TXTs {
				// 将TXT记录的内容添加到列表中（不考虑rcode）
				txtContents = append(txtContents, v.Content)
			}
			TXTMap[domain] = txtContents
		}
	}

	var buffer bytes.Buffer
	fmt.Printf("发现%d个TXT记录\n", len(TXTMap))
	// 记录开始时间
	for domain, txtContents := range TXTMap {
		buffer.WriteString(domain + "|" + strings.Join(txtContents, ",") + "\n")
	}

	file, err := os.Create("txt_records.txt" + time.Now().Format("20060102150405"))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	buffer.WriteTo(file)
}

// 输出TXT记录信息
func (bC *BindCache) outputSPF() {

	spfMap := make(map[string][]string)

	for domain, record := range bC.records {
		if len(record.TXTs) > 0 {
			var spfContents []string
			for _, v := range record.TXTs {
				// 将TXT记录的内容添加到列表中（不考虑rcode）
				if strings.Contains(v.Content, "v=spf") {
					spfContents = append(spfContents, v.Content)

				}
			}
			if len(spfContents) > 0 {
				spfMap[domain] = spfContents

			}
		}
	}

	var buffer bytes.Buffer
	fmt.Printf("发现%d个SPF记录\n", len(spfMap))
	// 记录开始时间
	for domain, txtContents := range spfMap {
		buffer.WriteString(domain + "|" + strings.Join(txtContents, ",") + "\n")
	}

	file, err := os.Create("spf_records.txt" + time.Now().Format("20060102150405"))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	buffer.WriteTo(file)
}

// 输出MX记录信息
func (bC *BindCache) outputMX() {

	MXMap := make(map[string][]string)

	for domain, record := range bC.records {
		if len(record.MXs) > 0 && record.MXs[0].Rcode != "nxrrset" {
			var mxServers []string
			for _, v := range record.MXs {
				// 将优先级和邮件服务器格式化为一个字符串
				mxServers = append(mxServers, fmt.Sprintf("%d %s", v.Priority, v.MailServer))
			}
			MXMap[domain] = mxServers
		}
	}

	var buffer bytes.Buffer
	fmt.Printf("发现%d个MX记录\n", len(MXMap))
	// 记录开始时间
	for domain, mxServers := range MXMap {
		buffer.WriteString(domain + "|" + strings.Join(mxServers, ",") + "\n")
	}

	file, err := os.Create("mx_records.txt" + time.Now().Format("20060102150405"))
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	buffer.WriteTo(file)
}

func main() {

	//_, err := getDNSStatus("gameplay.intel.com.constellium.biz.", "ns1.gandi.net.")
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println(getTraceResult("gameplay.intel.com.constellium.biz."))
	////fmt.Println(getTraceResult("www.baidu.com."))
	////
	//os.Exit(1)

	//domain:="yaomengwang.cn."

	filename := "cache_dump.db"

	if len(os.Args) > 1 {
		filename = os.Args[1]

	}
	bindCache, err := ParseDNSCacheFile(filename)
	if err != nil {
		fmt.Println("解析错误:", err)
		return
	}
	fmt.Println("总记录数:", len(bindCache.records))
	fmt.Println("nxdomain 记录数:", len(bindCache.nxdomainRecords))
	fmt.Println("nxrrset 记录数:", len(bindCache.nxrrsetRecords))
	bindCache.dnsServer = "112.4.0.55"

	// bindCache.getDomain(".")
	// //
	bindCache.getDomain("ceacfh-launches.appsflyersdk.com.")
	bindCache.getDomain("1.0.0.1.in-addr.arpa.")
	bindCache.getDomain("baidu.com.")

	// bindCache.outputType65()
	// bindCache.outputNSIP()
	// bindCache.outputNSIPToTxt()
	// bindCache.outputMX()  // 调用修改后的outputMX函数
	// bindCache.outputPTR() // 调用新添加的outputPTR函数
	// bindCache.outputTXT() // 调用新添加的outputTXT函数
	bindCache.outputSPF()

	//单一NS隐患
	//count := 0
	//for domain, record := range bindCache.records {
	//	if len(record.NSs) == 1 {
	//		count++
	//
	//	}
	//	if len(record.NSs) == 1 && len(strings.Split(domain, ".")) < 5 {
	//		fmt.Println(domain, record.NSs[0])
	//
	//	}
	//}
	//fmt.Println(count)

	//查找nxrrset域名中sevfail的结果
	//bindCache.dig()
	//bindCache.parentAndChildCheck()
	//bindCache.outputNSIP()
	//bindCache.getDomain("shifen.com.")

	//批量检索域名内存信息
	//domains := []string{
	//	".",
	//	"xymjgame.fangame.cn.",
	//	"api.xiangqianpos.com.",               //NXRRSET
	//	"tsconfigserver-cdn.xiangtatech.com.", //CNAME
	//	"xiangongyun.com.",                    //ChildNS
	//	"ws1.xiangyuerom.com.",                //nxdomain
	//	"s1.fx.kgimg.com.wswebcdn.com.",       //A+NXRRSET
	//	"adsfile.kugou.com.wswebcdn.com.",     //AAAA+NXRRSET
	//
	//}
	//
	//for _, domain := range domains {
	//	bindCache.getDomain(domain)
	//}

	//bindCache.getDomain(".")
	//fmt.Println(bindCache.records["."])

}
