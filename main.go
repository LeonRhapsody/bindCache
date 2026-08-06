package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2"
)

type BindCache struct {
	dnsServer       string
	records         map[string]Record
	nxdomainRecords map[string]Record
	nxrrsetRecords  map[string]Record
	domainNsRecords map[string][]string
	Date            string
	View            string
	ADBRecords      []ADBRecord
}

func (bC *BindCache) getDomainNs(domain string) (result []string) {

	for _, ns := range bC.records[domain].NSs {
		result = append(result, ns.NsDomain)
	}

	return result

}

func (bC *BindCache) getDomain(domain string, format string) {
	if record, exists := bC.records[domain]; exists {
		if strings.ToLower(format) == "json" {
			jsonBytes, err := json.MarshalIndent(record, "", "  ")
			if err != nil {
				fmt.Printf("JSON序列化失败: %v\n", err)
				return
			}
			fmt.Println(string(jsonBytes))
		} else {
			fmt.Printf("Domain (%s):\n%s\n\n", domain, record)
		}
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

	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range tasks {

				status, _ := simpleDig(domain, "127.0.0.1")
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
		for _, ns := range record.NSs {
			for _, a := range bC.records[ns.NsDomain].As {
				nsIPToDomain[a.IP] = append(nsIPToDomain[a.IP], domain)
			}
			for _, aaaa := range bC.records[ns.NsDomain].AAAAs {
				nsIPToDomain[aaaa.IP] = append(nsIPToDomain[aaaa.IP], domain)
			}
		}
	}

	total := len(nsIPToDomain)
	fmt.Printf("发现%d个权威IP，准备开始归属匹配...\n", total)

	results := make([]string, total)
	startTime := time.Now()

	ips := make([]string, 0, total)
	for ip := range nsIPToDomain {
		ips = append(ips, ip)
	}

	// 单线程极速匹配，无锁无 Goroutine 开销
	for i := 0; i < total; i++ {
		ip := ips[i]
		domains := nsIPToDomain[ip]
		var result string
		if ok, client := isInIPRanges(ip, &map1); ok {
			result = client
		} else {
			result = "未知"
		}

		var line string
		if len(domains) > 50 {
			line = fmt.Sprintf("%s,%s,%d,%s\n", result, ip, len(domains), "过长不显示")
		} else {
			line = fmt.Sprintf("%s,%s,%d,%s\n", result, ip, len(domains), strings.Join(domains, "|"))
		}

		results[i] = line
		if (i+1)%100 == 0 || (i+1) == total {
			elapsedTime := time.Since(startTime)
			fmt.Printf("\r匹配进度： %d(%.2f%%) 已耗时: %v", i+1, (float32(i+1)/float32(total))*100, elapsedTime)
		}
	}
	fmt.Println("\n匹配完成，正在写入文件...")

	var buffer bytes.Buffer
	buffer.WriteString("NS IP归属,NS IP,解析域名数,域名清单\n")
	for _, line := range results {
		if line != "" {
			buffer.WriteString(line)
		}
	}

	file, err := os.Create("ipToDomain.csv")
	if err != nil {
		fmt.Println("创建文件失败:", err)
		return
	}
	defer file.Close()

	buffer.WriteTo(file)
	fmt.Println("结果已写入 ipToDomain.csv")
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
				if v.Target != "" {
					ptrTargets = append(ptrTargets, v.Target)
				} else if v.Rcode != "" {
					// 目标为空（否定缓存）时，用 Rcode 状态（如 nxrrset、nxdomain 等）补充
					ptrTargets = append(ptrTargets, v.Rcode)
				}
			}
			if len(ptrTargets) > 0 {
				ptrMap[domain] = ptrTargets
			}
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

// buildRuntimeNSControls 把配置文件的拨测与告警设置装配为运行时对象。采集机
// 默认使用 relay；只有明确设置 probe.backend=direct 才会自行访问外部 DNS。
func buildRuntimeNSControls(enabled bool, backend, recursiveResolver, trustedResolvers string, timeout time.Duration, maxDomains, maxParallel, maxEventsPerImport int) (*NSProbeConfig, *NSAlertConfig, error) {
	backend = strings.ToLower(strings.TrimSpace(backend))
	if backend == "" {
		backend = "relay"
	}
	if backend != "relay" && backend != "direct" {
		return nil, nil, fmt.Errorf("probe.backend 必须为 relay 或 direct")
	}
	probe, err := ParseNSProbeConfig(enabled, recursiveResolver, trustedResolvers, timeout, maxDomains, maxParallel)
	if err != nil {
		return nil, nil, err
	}
	probe.DirectPort = GlobalConfig.Probe.DirectPort
	if maxEventsPerImport > 0 {
		probe.MaxEventsPerImport = maxEventsPerImport
	}
	eventTimeout, err := configDuration(GlobalConfig.Probe.EventTimeout, DefaultNSProbeConfig().EventTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("probe.event_timeout: %w", err)
	}
	probe.EventTimeout = eventTimeout

	needsRelay := (enabled && backend == "relay") || GlobalConfig.Alerts.Enabled
	var relay *NSRelayClient
	if needsRelay {
		relay, err = NewNSRelayClient(GlobalConfig.RelayClient)
		if err != nil {
			return nil, nil, err
		}
	}
	if enabled && backend == "relay" {
		probe.Executor = relay
	}
	alerts, err := BuildNSAlertConfig(GlobalConfig.Alerts, relay)
	if err != nil {
		return nil, nil, err
	}
	return probe, alerts, nil
}

func main() {
	if configPath := strings.TrimSpace(appConfigPathFromArgs(os.Args[1:])); configPath != "" && configPath != GlobalConfigPath {
		GlobalConfigError = ReloadGlobalConfig(configPath)
	}
	if GlobalConfigError != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", GlobalConfigError)
		os.Exit(1)
	}
	watchIntervalDefault, err := configDuration(GlobalConfig.DumpMonitor.PollInterval, 30*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置 dump_monitor.poll_interval 无效: %v\n", err)
		os.Exit(1)
	}
	stableForDefault, err := configDuration(GlobalConfig.DumpMonitor.StabilityWindow, 90*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置 dump_monitor.stability_window 无效: %v\n", err)
		os.Exit(1)
	}
	probeTimeoutDefault, err := configDuration(GlobalConfig.Probe.Timeout, 2*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置 probe.timeout 无效: %v\n", err)
		os.Exit(1)
	}
	// 定义命令行标志
	configFlag := flag.String("config", GlobalConfigPath, "配置文件路径；也可使用 APP_CONFIG 环境变量")
	fileFlag := flag.String("file", "cache_dump.db", "指定要解析的 BIND 缓存快照文件路径")
	snapshotsFlag := flag.String("snapshots", "", "NS 监测使用的快照文件（逗号分隔）或目录；未指定时使用 -file")
	geoIPDirFlag := flag.String("geoip-dir", GlobalConfig.GeoIP.Directory, "GeoLite2 ASN/Country CSV 的父目录")
	domainFlag := flag.String("query", "", "查询指定域名在内存中的解析记录")
	formatFlag := flag.String("format", "text", "指定查询输出格式，支持: text (人眼友好文本), json (标准JSON)")
	exportFlag := flag.String("export", "", "执行数据导出，支持: all, type65, dname, adb, ns, nsip, nsip-txt, domain-ns-ip, mx, ptr, txt, spf, soa, srv, caa, tlsa, naptr, rrsig, dnskey, ds, nsec, nsec3, mysql")
	checkFlag := flag.String("check", "", "执行缓存状态与安全扫描，支持: single-ns, nxrrset-fail, parent-child, ns-diff, hijack")
	webFlag := flag.Bool("web", false, "启动无 ClickHouse 依赖的 NS 内存监测调试台")
	webDBFlag := flag.Bool("web-db", false, "启动读取 ClickHouse 持久化 NS 数据的正式只读 Web")
	nsImportFlag := flag.Bool("ns-import", false, "解析 -snapshots 并批量写入 ClickHouse 的 NS 时序、基线和变更事件表")
	portFlag := flag.String("port", GlobalConfig.Web.Port, "指定 Web 服务端口（默认读取 web.port）")
	listenFlag := flag.String("listen", GlobalConfig.Web.Listen, "正式 NS Web 监听地址；经反向代理发布时使用 127.0.0.1")
	dumpDirFlag := flag.String("dump-dir", GlobalConfig.DumpMonitor.Directory, "正式 NS Web 用于按需展开完整 RR、并递归监测新增 dump 的目录")
	dumpLedgerFlag := flag.String("dump-ledger", GlobalConfig.DumpMonitor.LedgerPath, "已处理 dump 本地账本路径")
	watchIntervalFlag := flag.Duration("watch-interval", watchIntervalDefault, "dump 目录轮询间隔")
	dumpStableForFlag := flag.Duration("dump-stable-for", stableForDefault, "同一 dump 连续观察稳定且静默多久才允许导入")
	probeEnabledFlag := flag.Bool("probe-enabled", GlobalConfig.Probe.Enabled, "对新增或更新的 NS 异常执行受限组内 DNS 拨测")
	probeBackendFlag := flag.String("probe-backend", GlobalConfig.Probe.Backend, "DNS 拨测后端：relay 或 direct")
	probeRecursiveFlag := flag.String("probe-recursive", GlobalConfig.Probe.RecursiveResolver, "受监控递归 DNS（RD=1），用于确认异常结果是否已实际命中")
	probeTrustedFlag := flag.String("probe-trusted", strings.Join(GlobalConfig.Probe.TrustedResolvers, ","), "可信递归 DNS（逗号分隔，至少两个），用于交叉验证稳定 NS 共识")
	probeTimeoutFlag := flag.Duration("probe-timeout", probeTimeoutDefault, "单次 DNS 拨测超时")
	probeMaxDomainsFlag := flag.Int("probe-max-domains", GlobalConfig.Probe.MaxDomains, "每个 NS 事件最多拨测的受影响名称数")
	probeParallelFlag := flag.Int("probe-parallel", GlobalConfig.Probe.MaxParallel, "每个 NS 事件 DNS 拨测并发数")
	probeMaxEventsFlag := flag.Int("probe-max-events", GlobalConfig.Probe.MaxEventsPerImport, "每份新快照最多自动拨测的 NS 事件数；其余事件保留并等待人工补测")
	probeEventFlag := flag.String("ns-probe-event", "", "对指定已入库 NS 事件补充执行一次拨测；需要 -dump-dir")
	relayFlag := flag.Bool("relay", false, "启动同网段 DNS 拨测与邮件 relay 服务")
	analyzeFlag := flag.Bool("analyze", false, "对解析出的缓存数据执行隐患分析并写入数据库")
	cleanupNSLocationRisksFlag := flag.Bool("cleanup-obsolete-ns-location-risks", false, "删除同 ASN/同国家旧规则事件并迁移仍有有效单点原因的事件")
	cleanupNSSingleHistoryFlag := flag.Bool("cleanup-ns-single-history", false, "删除 NS 单一与冗余事件及其拨测、告警、处置和审计历史")

	flag.Parse()
	if *configFlag != GlobalConfigPath {
		// -config 已在 flag 定义前预读取，这里只防御性确认用户没有传入不同值。
		if err := ReloadGlobalConfig(*configFlag); err != nil {
			fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
			os.Exit(1)
		}
	}
	if *relayFlag {
		if err := StartNSRelayServer(GlobalConfig.RelayServer); err != nil {
			fmt.Fprintf(os.Stderr, "启动 NS relay 失败: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *cleanupNSLocationRisksFlag {
		db, err := OpenNSClickHouseReadDatabase(GlobalConfig.ClickhouseDSN)
		if err != nil {
			fmt.Fprintf(os.Stderr, "连接 NS 时序数据库失败: %v\n", err)
			os.Exit(1)
		}
		defer db.Close()
		report, err := cleanupObsoleteNSLocationRisks(db, GlobalConfig.ClickhouseDSN)
		if err != nil {
			fmt.Fprintf(os.Stderr, "清理同 ASN/同国家旧规则事件失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("清理完成：删除纯旧规则事件 %d，迁移保留有效单点原因事件 %d\n", report.DeletedPure, report.Migrated)
		return
	}
	if *cleanupNSSingleHistoryFlag {
		db, err := OpenNSClickHouseReadDatabase(GlobalConfig.ClickhouseDSN)
		if err != nil {
			fmt.Fprintf(os.Stderr, "连接 NS 时序数据库失败: %v\n", err)
			os.Exit(1)
		}
		defer db.Close()
		report, err := cleanupNSSingleRiskHistory(db)
		if err != nil {
			fmt.Fprintf(os.Stderr, "清理 NS 单一与冗余历史失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("清理完成：事件 %d，拨测 %d，告警 %d，处置 %d，审计 %d\n",
			report.Events, report.Probes, report.Alerts, report.Actions, report.AuditLogs)
		return
	}
	if strings.TrimSpace(*probeEventFlag) != "" {
		if strings.TrimSpace(*dumpDirFlag) == "" {
			fmt.Fprintln(os.Stderr, "-ns-probe-event 需要指定保留原始 dump 的 -dump-dir")
			os.Exit(1)
		}
		probe, _, err := buildRuntimeNSControls(*probeEnabledFlag, *probeBackendFlag, *probeRecursiveFlag, *probeTrustedFlag, *probeTimeoutFlag, *probeMaxDomainsFlag, *probeParallelFlag, *probeMaxEventsFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "NS 拨测参数无效: %v\n", err)
			os.Exit(1)
		}
		db, err := OpenNSClickHouseDatabase(GlobalConfig.ClickhouseDSN)
		if err != nil {
			fmt.Fprintf(os.Stderr, "初始化 NS 时序数据库失败: %v\n", err)
			os.Exit(1)
		}
		defer db.Close()
		result, err := ProbePersistedNSEvent(db, GlobalConfig.ClickhouseDSN, *dumpDirFlag, *probeEventFlag, *probe)
		if err != nil {
			fmt.Fprintf(os.Stderr, "NS 事件拨测失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("NS 事件拨测完成：事件 %s，结论 %s，名称 %d/%d，%s\n", result.EventID, result.Verdict, result.ProbedDomains, result.DomainLimit, result.Summary)
		return
	}
	if *nsImportFlag {
		files, err := ParseSnapshotInputs(*fileFlag, *snapshotsFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取 NS 导入快照参数失败: %v\n", err)
			os.Exit(1)
		}

		var geo IPMetadataProvider
		resolver, err := LoadGeoLiteResolver(*geoIPDirFlag)
		if err != nil {
			fmt.Printf("GeoLite 离线数据未加载（网络归属变化不会提升风险等级）: %v\n", err)
		} else {
			geo = resolver
		}

		probe, alerts, err := buildRuntimeNSControls(*probeEnabledFlag, *probeBackendFlag, *probeRecursiveFlag, *probeTrustedFlag, *probeTimeoutFlag, *probeMaxDomainsFlag, *probeParallelFlag, *probeMaxEventsFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "NS 拨测参数无效: %v\n", err)
			os.Exit(1)
		}

		db, err := OpenNSClickHouseDatabase(GlobalConfig.ClickhouseDSN)
		if err != nil {
			fmt.Fprintf(os.Stderr, "初始化 NS 时序数据库失败: %v\n", err)
			os.Exit(1)
		}
		defer db.Close()

		fmt.Printf("开始导入 %d 份 NS 快照...\n", len(files))
		report, err := ImportNSSnapshotsWithProbeAndAlerts(db, GlobalConfig.ClickhouseDSN, files, geo, probe, alerts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "NS 时序导入失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("NS 时序导入完成：新增快照 %d，跳过已存在快照 %d，NS 观测 %d，时间线节点 %d，事件 %d，批量变化 %d，拨测 %d，告警成功 %d，告警失败 %d，基线 %d\n",
			report.ImportedSnapshots, report.SkippedSnapshots, report.Observations, report.TimelinePoints, report.Events, report.Campaigns, report.Probes, report.AlertsSent, report.AlertsFailed, report.Baselines)
		return
	}

	if *webDBFlag {
		db, err := OpenNSClickHouseReadDatabase(GlobalConfig.ClickhouseDSN)
		if err != nil {
			fmt.Fprintf(os.Stderr, "初始化正式 NS 数据 Web 失败: %v\n", err)
			os.Exit(1)
		}
		defer db.Close()

		if strings.TrimSpace(*dumpDirFlag) != "" {
			var geo IPMetadataProvider
			resolver, geoErr := LoadGeoLiteResolver(*geoIPDirFlag)
			if geoErr != nil {
				fmt.Printf("GeoLite 离线数据未加载（目录监测导入不会提升网络风险等级）: %v\n", geoErr)
			} else {
				geo = resolver
			}
			probe, alerts, probeErr := buildRuntimeNSControls(*probeEnabledFlag, *probeBackendFlag, *probeRecursiveFlag, *probeTrustedFlag, *probeTimeoutFlag, *probeMaxDomainsFlag, *probeParallelFlag, *probeMaxEventsFlag)
			if probeErr != nil {
				fmt.Fprintf(os.Stderr, "NS 拨测参数无效: %v\n", probeErr)
				os.Exit(1)
			}
			watcher, watcherErr := NewNSDumpWatcher(db, GlobalConfig.ClickhouseDSN, NSDumpWatcherOptions{
				Directory:    *dumpDirFlag,
				LedgerPath:   *dumpLedgerFlag,
				PollInterval: *watchIntervalFlag,
				StableFor:    *dumpStableForFlag,
				Geo:          geo,
				Probe:        probe,
				Alerts:       alerts,
			})
			if watcherErr != nil {
				fmt.Fprintf(os.Stderr, "初始化 NS dump 目录监测失败: %v\n", watcherErr)
				os.Exit(1)
			}
			go watcher.Run(context.Background())
		}

		port := *portFlag
		if port == "8888" && GlobalConfig.WebPort != "" {
			port = GlobalConfig.WebPort
		}
		listenAddr := net.JoinHostPort(*listenFlag, port)
		if err := StartNSMonitorDatabaseServer(listenAddr, db, *dumpDirFlag); err != nil {
			fmt.Fprintf(os.Stderr, "NS 正式数据 Web 启动失败: %v\n", err)
		}
		return
	}

	if *webFlag {
		files, err := ParseSnapshotInputs(*fileFlag, *snapshotsFlag)
		if err != nil {
			fmt.Printf("读取 NS 监测快照参数失败: %v\n", err)
			return
		}

		var geo IPMetadataProvider
		resolver, err := LoadGeoLiteResolver(*geoIPDirFlag)
		if err != nil {
			fmt.Printf("GeoLite 离线数据未加载（不会提升网络风险等级）: %v\n", err)
		} else {
			geo = resolver
		}

		fmt.Printf("开始分析 %d 份 NS 快照...\n", len(files))
		analysis, err := AnalyzeNSFiles(files, geo)
		if err != nil {
			fmt.Printf("NS 快照分析失败: %v\n", err)
			return
		}
		overview := analysis.Overview()
		fmt.Printf("NS 基线分析完成：%d 个域名，%d 个事件\n", overview.TrackedDomains, len(analysis.Events))
		port := *portFlag
		if port == "8888" && GlobalConfig.WebPort != "" {
			port = GlobalConfig.WebPort
		}
		if err := StartNSMonitorServer(port, analysis); err != nil {
			fmt.Printf("NS 内存监测台启动失败: %v\n", err)
		}
		return
	}

	// 非 Web 的一次性大文件解析路径保持原有策略；常驻监测台保留 GC。
	debug.SetGCPercent(-1)

	filename := *fileFlag

	fmt.Printf("准备解析缓存文件: %s\n", filename)
	bindCache, err := ParseDNSCacheFile(filename)
	if err != nil {
		fmt.Printf("解析错误: %v\n", err)
		return
	}
	fmt.Printf("解析完成。视图: %s | 快照生成时间: %s | 总域名记录数: %d | NXDOMAIN: %d | NXRRSET: %d\n",
		bindCache.View, bindCache.Date, len(bindCache.records), len(bindCache.nxdomainRecords), len(bindCache.nxrrsetRecords))

	bindCache.dnsServer = "127.0.0.1"

	// 0. 手动隐患分析逻辑
	if *analyzeFlag {
		snapshotDate := parseSnapshotDate(bindCache.Date)
		db, err := sql.Open("clickhouse", GlobalConfig.ClickhouseDSN)
		if err != nil {
			fmt.Printf("打开数据库连接失败: %v\n", err)
			return
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			fmt.Printf("无法连接到 ClickHouse 服务: %v\n", err)
			return
		}

		bindCache.runDailyAnalysisAndSave(snapshotDate, db)
		return
	}

	// 1. 域名单项查询
	if *domainFlag != "" {
		queryDomain := *domainFlag
		if !strings.HasSuffix(queryDomain, ".") {
			queryDomain += "."
		}
		bindCache.getDomain(queryDomain, *formatFlag)
		return
	}

	// 2. 扫描检测逻辑
	if *checkFlag != "" {
		switch strings.ToLower(*checkFlag) {
		case "single-ns":
			fmt.Println("开始扫描单一 NS 隐患域名...")
			bindCache.checkSingleNS()
		case "nxrrset-fail":
			fmt.Println("开始并发扫描 NXRRSET 域名中的异常响应...")
			bindCache.dig()
		case "parent-child":
			fmt.Println("开始本地离线探测父子 NS 解析一致性...")
			bindCache.parentAndChildCheck()
		case "ns-diff":
			fmt.Println("开始并发比对权威服务器与标准 DNS 的解析一致性...")
			bindCache.nsDiffers()
		case "hijack":
			fmt.Println("开始扫描被国际安全组织黑洞劫持的域名...")
			bindCache.checkNSHijack()
		default:
			fmt.Printf("未知的检测类型: %s。支持: single-ns, nxrrset-fail, parent-child, ns-diff, hijack\n", *checkFlag)
		}
		return
	}

	// 3. 导出逻辑
	if *exportFlag != "" {
		switch strings.ToLower(*exportFlag) {
		case "all":
			fmt.Println("开始执行全量记录导出...")
			bindCache.outputType65()
			bindCache.outputDNAME()
			bindCache.outputADB()
			bindCache.outputNS()
			bindCache.outputNSIP()
			bindCache.outputNSIPToTxt()
			bindCache.outputDomainNsIP()
			bindCache.outputMX()
			bindCache.outputPTR()
			bindCache.outputTXT()
			bindCache.outputSPF()
			bindCache.outputSOA()
			bindCache.outputSRV()
			bindCache.outputCAA()
			bindCache.outputTLSA()
			bindCache.outputNAPTR()
			bindCache.outputRRSIG()
			bindCache.outputDNSKEY()
			bindCache.outputDS()
			bindCache.outputNSEC()
			bindCache.outputNSEC3()
			bindCache.exportToClickHouse()
		case "type65":
			bindCache.outputType65()
		case "dname":
			bindCache.outputDNAME()
		case "adb":
			bindCache.outputADB()
		case "ns":
			bindCache.outputNS()
		case "nsip":
			bindCache.outputNSIP()
		case "clickhouse":
			bindCache.exportToClickHouse()
		default:
			fmt.Printf("未知的导出类型: %s\n", *exportFlag)
		}
		return
	}
}

// checkSingleNS 扫描并统计仅使用单一 NS 服务的域名（隐患检测）
func (bC *BindCache) checkSingleNS() {
	count := 0
	for domain, record := range bC.records {
		if len(record.NSs) == 1 {
			count++
			if len(strings.Split(domain, ".")) < 5 {
				fmt.Println(domain, record.NSs[0].NsDomain)
			}
		}
	}
	fmt.Printf("单一 NS 隐患域名总数: %d\n", count)
}

// checkNSHijack 检测二级域被安全机构劫持的情况（场景三）
func (bC *BindCache) checkNSHijack() {
	count := 0
	var buffer bytes.Buffer
	for domain, record := range bC.records {
		for _, ns := range record.NSs {
			if strings.Contains(ns.NsDomain, "shadowserver.org") {
				count++
				msg := fmt.Sprintf("[疑似被劫持] 域名: %s | 被修改为 NS: %s (Attribute: %s)\n", domain, ns.NsDomain, ns.Attribute)
				fmt.Print(msg)
				buffer.WriteString(msg)
				break
			}
		}
	}
	file, _ := os.Create("hijack.txt")
	defer file.Close()
	buffer.WriteTo(file)
	fmt.Printf("劫持/黑洞检测完成。共发现 %d 例被国际安全机构劫持的域名记录，结果已写入 hijack.txt\n", count)
}

// mapAttributeToTrustLevel 映射 BIND 快照记录属性到 RFC 定义的信任等级 (0-12)
func mapAttributeToTrustLevel(attr string) int {
	switch attr {
	case "authanswer":
		return 8
	case "authauthority":
		return 7
	case "answer":
		return 5
	case "credential":
		return 4
	case "additional":
		return 3
	case "glue":
		return 2
	default:
		return 0
	}
}

// toJSONString 序列化切片为 JSON 格式的字符串以符合落库需要
func toJSONString(slice []string) string {
	if len(slice) == 0 {
		return "[]"
	}
	bytes, err := json.Marshal(slice)
	if err != nil {
		return "[]"
	}
	return string(bytes)
}

// dbRow 定义快照二维表行数据，供批量插入使用
// runDailyAnalysisAndSave 对当前快照进行标签化异常扫描与 Tracker 时序流转
func (bC *BindCache) runDailyAnalysisAndSave(snapshotDate string, db *sql.DB) {
	fmt.Printf("正在对快照 [%s] 执行基于标签系统的每日隐患分析...\n", snapshotDate)

	// 1. 创建 snapshots 表（若不存在）
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS snapshots (
		snapshot_date Date COMMENT '快照生成日期',
		total_domains Int32 COMMENT '本快照包含的域名总数',
		view String COMMENT '所属 DNS View 视图',
		imported_at DateTime DEFAULT now() COMMENT '导入系统的时间'
	) ENGINE = MergeTree()
	PARTITION BY snapshot_date
	ORDER BY snapshot_date;`)
	if err != nil {
		fmt.Printf("创建 snapshots 表失败: %v\n", err)
	}

	// 2. 创建 analysis_results 表（明细表，用于前端视图呈现）
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS analysis_results (
		snapshot_date Date COMMENT '扫描快照日期',
		domain String COMMENT '隐患域名',
		issue_type LowCardinality(String) COMMENT '隐患类型',
		risk_level LowCardinality(String) COMMENT '风险等级',
		details String COMMENT '隐患细节描述',
		detected_at DateTime DEFAULT now() COMMENT '检测时间'
	) ENGINE = MergeTree()
	PARTITION BY snapshot_date
	ORDER BY (snapshot_date, issue_type, risk_level);`)
	if err != nil {
		fmt.Printf("创建 analysis_results 表失败: %v\n", err)
	}

	// 3. 创建 analysis_results_tracker 长期时序追踪表
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS analysis_results_tracker (
		domain String COMMENT '隐患域名',
		issue_type LowCardinality(String) COMMENT '隐患类型',
		risk_level LowCardinality(String) COMMENT '风险等级',
		first_detected DateTime COMMENT '首次发现时间',
		last_active DateTime COMMENT '最近一次处于活跃状态的时间',
		status LowCardinality(String) COMMENT '状态 (active / resolved)',
		resolved_at Nullable(DateTime) COMMENT '消除时间',
		details String COMMENT '最新的细节描述'
	) ENGINE = MergeTree()
	PARTITION BY toYYYYMM(first_detected)
	ORDER BY (status, issue_type, domain, first_detected)
	SETTINGS index_granularity = 8192;`)
	if err != nil {
		fmt.Printf("创建 analysis_results_tracker 表失败: %v\n", err)
	}

	// 4. 创建 dns_cache_baseline 基线共识数据表
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS dns_cache_baseline (
		view LowCardinality(String) COMMENT 'DNS View 视图',
		domain String COMMENT '域名',
		record_type LowCardinality(String) COMMENT '记录类型',
		baseline_data String COMMENT '基线内容',
		confidence_score UInt8 COMMENT '共识置信度评分 (0-100)',
		last_updated DateTime COMMENT '最后更新时间'
	) ENGINE = MergeTree()
	ORDER BY (view, domain, record_type)
	SETTINGS index_granularity = 8192;`)
	if err != nil {
		fmt.Printf("创建 dns_cache_baseline 表失败: %v\n", err)
	}

	// 5. 自动重新计算基线（评估最近 7 天的解析共识，构建滑动基线）
	fmt.Println("正在自动重构滑动共识基线 (dns_cache_baseline)...")
	_, _ = db.Exec("TRUNCATE TABLE dns_cache_baseline")

	// 动态检测最近 7 天内实际已导入的快照天数，以便在冷启动数据不足时也能完成比对
	var availableSnapshots int
	_ = db.QueryRow("SELECT count(DISTINCT snapshot_date) FROM dns_cache_flat WHERE rcode = 'NOERROR' AND snapshot_date >= today() - 7").Scan(&availableSnapshots)

	requiredConsensusDays := 3
	if availableSnapshots > 0 && availableSnapshots <= 2 {
		requiredConsensusDays = 1
	}
	fmt.Printf("├─ 最近 7 天可用快照数: %d 天 | 基线共识阈值设为: >= %d 天\n", availableSnapshots, requiredConsensusDays)

	_, err = db.Exec(`
	INSERT INTO dns_cache_baseline
	SELECT
		view,
		domain,
		record_type,
		record_data AS baseline_data,
		toUInt8(count() * 14) AS confidence_score,
		now() AS last_updated
	FROM dns_cache_flat
	WHERE snapshot_date >= today() - 7
	  AND rcode = 'NOERROR'
	GROUP BY view, domain, record_type, record_data
	HAVING count() >= ?`, requiredConsensusDays)
	if err != nil {
		fmt.Printf("自动计算共识基线失败: %v\n", err)
	}

	// 6. 清理当期快照下可能已有的旧分析明细（避免重复扫描导致脏数据）
	_, _ = db.Exec("ALTER TABLE analysis_results DROP PARTITION '" + snapshotDate + "'")

	// 7. 运行全新设计的标签评估引擎 (Tagging Engine) 评估快照并批量写入标签表
	tagEngine := NewTaggingEngine(db)
	detectedTags, err := tagEngine.Run(snapshotDate, bC.View)
	if err != nil {
		fmt.Printf("标签引擎运行失败: %v\n", err)
		return
	}

	// 用于存储供 Tracker 时序追踪分析使用的事件明细列表
	type tempIssue struct {
		Domain    string
		IssueType string
		RiskLevel string
		Details   string
	}
	var currentIssues []tempIssue

	// 解析出当前时间用于时序记录
	nowTime, err := time.Parse("2006-01-02", snapshotDate)
	if parsedTime, errTime := time.Parse("2006-01-02_15-04-05", bC.Date); errTime == nil {
		nowTime = parsedTime
	} else if parsedTime, errTime := time.Parse(time.RFC3339, bC.Date); errTime == nil {
		nowTime = parsedTime
	} else if parsedTime, errTime := time.Parse("2006-01-02 15:04:05", bC.Date); errTime == nil {
		nowTime = parsedTime
	}

	// 8. 双向转换与映射处理：将标签落入分析明细表 (analysis_results) 并汇总成 Tracker 任务
	if len(detectedTags) > 0 {
		tx, err := db.Begin()
		if err == nil {
			stmt, err := tx.Prepare(`
				INSERT INTO analysis_results
				(snapshot_date, domain, issue_type, risk_level, details)
				VALUES (?, ?, ?, ?, ?)`)
			if err == nil {
				defer stmt.Close()
				for _, t := range detectedTags {
					// 过滤与映射级别
					riskLvl := "low"
					if t.RiskScore >= 8 {
						riskLvl = "crisis"
					} else if t.RiskScore >= 5 {
						riskLvl = "high"
					} else if t.RiskScore >= 2 {
						riskLvl = "medium"
					}

					// 仅对带有风险分值的异常标签同步生成 analysis_results 与 tracker 事件
					if t.RiskScore > 0 {
						_, _ = stmt.Exec(snapshotDate, t.Domain, t.Tag, riskLvl, t.Details)

						currentIssues = append(currentIssues, tempIssue{
							Domain:    t.Domain,
							IssueType: t.Tag,
							RiskLevel: riskLvl,
							Details:   t.Details,
						})
					}
				}
				_ = tx.Commit()
			} else {
				_ = tx.Rollback()
			}
		}
	}

	// 9. 时序隐患状态机流转 (UPSERT 与恢复判定)
	fmt.Printf("开始对 %d 例检测出的标签隐患执行生命周期时序状态流转...\n", len(currentIssues))

	type trackerRecord struct {
		FirstDetected time.Time
		RiskLevel     string
		Details       string
	}
	activeTrackers := make(map[string]trackerRecord) // key: domain + "|" + issue_type

	rowsT, err := db.Query("SELECT domain, issue_type, risk_level, first_detected, details FROM analysis_results_tracker WHERE status = 'active'")
	if err == nil {
		defer rowsT.Close()
		for rowsT.Next() {
			var dom, iType, rLevel, details string
			var fDet time.Time
			if err := rowsT.Scan(&dom, &iType, &rLevel, &fDet, &details); err == nil {
				activeTrackers[dom+"|"+iType] = trackerRecord{
					FirstDetected: fDet,
					RiskLevel:     rLevel,
					Details:       details,
				}
			}
		}
	}

	txTracker, err := db.Begin()
	if err != nil {
		fmt.Printf("时序流转事务开启失败: %v\n", err)
		return
	}
	defer func() {
		if txTracker != nil {
			_ = txTracker.Rollback()
		}
	}()

	insertStmt, err := txTracker.Prepare(`
		INSERT INTO analysis_results_tracker
		(domain, issue_type, risk_level, first_detected, last_active, status, resolved_at, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		fmt.Printf("准备状态插入语句失败: %v\n", err)
		return
	}
	defer insertStmt.Close()

	stillActiveKeys := make(map[string]bool)
	for _, issue := range currentIssues {
		key := issue.Domain + "|" + issue.IssueType
		stillActiveKeys[key] = true

		if oldRec, exists := activeTrackers[key]; exists {
			// A. 持续活跃中：继承首次发现时间，更新最近活动时间
			_, _ = insertStmt.Exec(issue.Domain, issue.IssueType, issue.RiskLevel, oldRec.FirstDetected, nowTime, "active", nil, issue.Details)
		} else {
			// B. 首次发现：设置发现时间与活动时间一致
			_, _ = insertStmt.Exec(issue.Domain, issue.IssueType, issue.RiskLevel, nowTime, nowTime, "active", nil, issue.Details)
		}
	}

	// C. 检测已恢复隐患 (之前活跃但本次未扫出，说明已被人工排除或自然解决)
	resolvedCount := 0
	for key, oldRec := range activeTrackers {
		if !stillActiveKeys[key] {
			parts := strings.Split(key, "|")
			if len(parts) == 2 {
				dom := parts[0]
				iType := parts[1]
				_, _ = insertStmt.Exec(dom, iType, oldRec.RiskLevel, oldRec.FirstDetected, nowTime, "resolved", nowTime, oldRec.Details)
				resolvedCount++
			}
		}
	}

	_ = txTracker.Commit()
	txTracker = nil
	fmt.Printf("时序隐患追踪完成。本期活跃: %d | 成功自动恢复: %d\n", len(currentIssues), resolvedCount)
}

func stripDatabaseName(dsn string) string {
	lastSlash := strings.LastIndex(dsn, "/")
	if lastSlash == -1 {
		return dsn
	}
	qMark := strings.Index(dsn[lastSlash:], "?")
	if qMark == -1 {
		return dsn[:lastSlash+1]
	}
	return dsn[:lastSlash+1] + dsn[lastSlash+qMark:]
}

func getDatabaseName(dsn string) string {
	lastSlash := strings.LastIndex(dsn, "/")
	if lastSlash == -1 {
		return "bind_cache_analyze"
	}
	qMark := strings.Index(dsn[lastSlash:], "?")
	var dbName string
	if qMark == -1 {
		dbName = dsn[lastSlash+1:]
	} else {
		dbName = dsn[lastSlash+1 : lastSlash+qMark]
	}
	if dbName == "" {
		return "bind_cache_analyze"
	}
	return dbName
}

// dbRow 定义快照二维表行数据，供批量插入使用
type dbRow struct {
	SnapshotDate string
	Domain       string
	RecordType   string
	RecordData   string
	TTL          int
	TrustCode    string
	TrustLevel   int
	Rcode        any
}

// parseSnapshotDate 将快照快照元数据的日期格式（通常为 YYYYMMDDHHMMSS）标准化为 YYYY-MM-DD
func parseSnapshotDate(dateStr string) string {
	if len(dateStr) >= 8 {
		allDigits := true
		for i := 0; i < 8; i++ {
			if dateStr[i] < '0' || dateStr[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return fmt.Sprintf("%s-%s-%s", dateStr[0:4], dateStr[4:6], dateStr[6:8])
		}
	}
	return time.Now().Format("2006-01-02")
}

// getRegisteredDomain 提取 NS 服务器的主域名
func getRegisteredDomain(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	parts := strings.Split(domain, ".")
	n := len(parts)
	if n <= 1 {
		return domain
	}
	return parts[n-2] + "." + parts[n-1]
}

func (bC *BindCache) exportToClickHouse() {
	dsn := GlobalConfig.ClickhouseDSN
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		fmt.Printf("打开 ClickHouse 连接失败: %v\n", err)
		return
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		fmt.Printf("无法连接到 ClickHouse 服务: %v\n", err)
		return
	}

	// 1. 创建扁平记录表
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS dns_cache_flat
	(
		snapshot_date Date COMMENT '快照日期',
		view LowCardinality(String) COMMENT 'DNS View 视图',
		domain String COMMENT '域名',
		record_type LowCardinality(String) COMMENT '记录类型',
		record_data String COMMENT '记录值',
		ttl Int32 COMMENT 'TTL',
		trust_code LowCardinality(String) COMMENT '信任标志',
		trust_level UInt8 COMMENT '信任等级',
		rcode LowCardinality(String) COMMENT '响应状态码'
	)
	ENGINE = MergeTree()
	PARTITION BY snapshot_date
	ORDER BY (snapshot_date, domain, record_type)
	SETTINGS index_granularity = 8192;`)
	if err != nil {
		fmt.Printf("创建 dns_cache_flat 表失败: %v\n", err)
		return
	}

	// 2. 创建遥测数据表
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS dns_adb_telemetry
	(
		snapshot_date Date,
		view LowCardinality(String),
		ns_name String,
		ip String,
		srtt UInt32,
		flags String,
		edns_success UInt32,
		edns_timeout UInt32,
		plain_success UInt32,
		plain_timeout UInt32,
		udpsize UInt16,
		cookie String,
		ttl Int32
	)
	ENGINE = MergeTree()
	PARTITION BY snapshot_date
	ORDER BY (snapshot_date, ns_name, ip)
	SETTINGS index_granularity = 8192;`)
	if err != nil {
		fmt.Printf("创建 dns_adb_telemetry 表失败: %v\n", err)
		return
	}

	snapshotDate := parseSnapshotDate(bC.Date)
	fmt.Printf("即将为快照日期 [%s] 导入数据到 ClickHouse...\n", snapshotDate)

	// 清理当前日期旧的数据 (在 ClickHouse 中通过 DROP PARTITION 会秒级清空，非常高效安全)
	_, _ = db.Exec(fmt.Sprintf("ALTER TABLE dns_cache_flat DROP PARTITION '%s'", snapshotDate))
	_, _ = db.Exec(fmt.Sprintf("ALTER TABLE dns_adb_telemetry DROP PARTITION '%s'", snapshotDate))

	// 写入 snapshots
	_, _ = db.Exec("INSERT INTO snapshots (snapshot_date, total_domains, view) VALUES (?, ?, ?)",
		snapshotDate, len(bC.records), bC.View)

	// 4. 批量写入 dns_cache_flat
	tx, err := db.Begin()
	if err != nil {
		fmt.Printf("开启 Flat 写入事务失败: %v\n", err)
		return
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.Prepare(`
		INSERT INTO dns_cache_flat
		(snapshot_date, view, domain, record_type, record_data, ttl, trust_code, trust_level, rcode)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		fmt.Printf("准备 Flat INSERT 语句失败: %v\n", err)
		return
	}
	defer stmt.Close()

	totalInserted := 0
	for domain, record := range bC.records {
		var rows []dbRow
		// 1. NS
		for _, ns := range record.NSs {
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "NS", RecordData: ns.NsDomain, TTL: ns.TTL, TrustCode: ns.Attribute, TrustLevel: mapAttributeToTrustLevel(ns.Attribute), Rcode: nil})
		}
		// 2. A
		for _, a := range record.As {
			var rc any = nil
			if a.Rcode != "" {
				rc = a.Rcode
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "A", RecordData: a.IP, TTL: a.TTL, TrustCode: a.Attribute, TrustLevel: mapAttributeToTrustLevel(a.Attribute), Rcode: rc})
		}
		// 3. AAAA
		for _, aaaa := range record.AAAAs {
			var rc any = nil
			if aaaa.Rcode != "" {
				rc = aaaa.Rcode
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "AAAA", RecordData: aaaa.IP, TTL: aaaa.TTL, TrustCode: aaaa.Attribute, TrustLevel: mapAttributeToTrustLevel(aaaa.Attribute), Rcode: rc})
		}
		// 4. CCNAME
		for _, cname := range record.CNAMEs {
			var rc any = nil
			if cname.Rcode != "" {
				rc = cname.Rcode
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "CNAME", RecordData: cname.IP, TTL: cname.TTL, TrustCode: cname.Attribute, TrustLevel: mapAttributeToTrustLevel(cname.Attribute), Rcode: rc})
		}
		// 4.1 DNAME
		for _, dname := range record.DNAMEs {
			var rc any = nil
			if dname.Rcode != "" {
				rc = dname.Rcode
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "DNAME", RecordData: dname.Target, TTL: dname.TTL, TrustCode: dname.Attribute, TrustLevel: mapAttributeToTrustLevel(dname.Attribute), Rcode: rc})
		}
		// 5. MX
		for _, mx := range record.MXs {
			var rc any = nil
			if mx.Rcode != "" {
				rc = mx.Rcode
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "MX", RecordData: fmt.Sprintf("%d %s", mx.Priority, mx.MailServer), TTL: mx.TTL, TrustCode: mx.Attribute, TrustLevel: mapAttributeToTrustLevel(mx.Attribute), Rcode: rc})
		}
		// 6. TXT
		for _, txt := range record.TXTs {
			var rc any = nil
			if txt.Rcode != "" {
				rc = txt.Rcode
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "TXT", RecordData: txt.Content, TTL: txt.TTL, TrustCode: txt.Attribute, TrustLevel: mapAttributeToTrustLevel(txt.Attribute), Rcode: rc})
		}
		// 7. TYPE65
		for _, t65 := range record.TYPE65 {
			var rc any = nil
			if t65.Rcode != "" {
				rc = t65.Rcode
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "TYPE65", RecordData: t65.IP, TTL: t65.TTL, TrustCode: t65.Attribute, TrustLevel: mapAttributeToTrustLevel(t65.Attribute), Rcode: rc})
		}
		// 8. SRV
		for _, srv := range record.SRVs {
			var rc any = nil
			if srv.Rcode != "" {
				rc = srv.Rcode
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "SRV", RecordData: fmt.Sprintf("%d %d %d %s", srv.Priority, srv.Weight, srv.Port, srv.Target), TTL: srv.TTL, TrustCode: srv.Attribute, TrustLevel: mapAttributeToTrustLevel(srv.Attribute), Rcode: rc})
		}
		// 9. SOA
		for _, soa := range record.SOAs {
			var rc any = nil
			if soa.Rcode != "" {
				rc = soa.Rcode
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "SOA", RecordData: fmt.Sprintf("%s %s %d", soa.MName, soa.RName, soa.Serial), TTL: soa.TTL, TrustCode: soa.Attribute, TrustLevel: mapAttributeToTrustLevel(soa.Attribute), Rcode: rc})
		}
		// 10. RRSIG
		for _, rrsig := range record.RRSIGs {
			var rc any = nil
			if rrsig.Rcode != "" {
				rc = rrsig.Rcode
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "RRSIG", RecordData: fmt.Sprintf("%s %d %s", rrsig.TypeCovered, rrsig.KeyTag, rrsig.SignerName), TTL: rrsig.TTL, TrustCode: rrsig.Attribute, TrustLevel: mapAttributeToTrustLevel(rrsig.Attribute), Rcode: rc})
		}
		// 11. PTR
		for _, ptr := range record.PTRs {
			var rc any = nil
			dataVal := ptr.Target
			if ptr.Rcode != "" {
				rc = ptr.Rcode
				dataVal = ""
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "PTR", RecordData: dataVal, TTL: ptr.TTL, TrustCode: ptr.Attribute, TrustLevel: mapAttributeToTrustLevel(ptr.Attribute), Rcode: rc})
		}
		// 12. CAA
		for _, caa := range record.CAAs {
			var rc any = nil
			dataVal := fmt.Sprintf("%d %s %s", caa.Flag, caa.Tag, caa.Value)
			if caa.Rcode != "" {
				rc = caa.Rcode
				dataVal = ""
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "CAA", RecordData: dataVal, TTL: caa.TTL, TrustCode: caa.Attribute, TrustLevel: mapAttributeToTrustLevel(caa.Attribute), Rcode: rc})
		}
		// 13. TLSA
		for _, tlsa := range record.TLSAs {
			var rc any = nil
			dataVal := fmt.Sprintf("%d %d %d %s", tlsa.Usage, tlsa.Selector, tlsa.MatchingType, tlsa.CertificateAssocData)
			if tlsa.Rcode != "" {
				rc = tlsa.Rcode
				dataVal = ""
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "TLSA", RecordData: dataVal, TTL: tlsa.TTL, TrustCode: tlsa.Attribute, TrustLevel: mapAttributeToTrustLevel(tlsa.Attribute), Rcode: rc})
		}
		// 14. NAPTR
		for _, naptr := range record.NAPTRs {
			var rc any = nil
			dataVal := fmt.Sprintf("%d %d %s %s %s %s", naptr.Order, naptr.Preference, naptr.Flags, naptr.Services, naptr.Regexp, naptr.Replacement)
			if naptr.Rcode != "" {
				rc = naptr.Rcode
				dataVal = ""
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "NAPTR", RecordData: dataVal, TTL: naptr.TTL, TrustCode: naptr.Attribute, TrustLevel: mapAttributeToTrustLevel(naptr.Attribute), Rcode: rc})
		}
		// 15. DNSKEY
		for _, dnskey := range record.DNSKEYs {
			var rc any = nil
			dataVal := fmt.Sprintf("%d %d %d %s", dnskey.Flags, dnskey.Protocol, dnskey.Algorithm, dnskey.PublicKey)
			if dnskey.Rcode != "" {
				rc = dnskey.Rcode
				dataVal = ""
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "DNSKEY", RecordData: dataVal, TTL: dnskey.TTL, TrustCode: dnskey.Attribute, TrustLevel: mapAttributeToTrustLevel(dnskey.Attribute), Rcode: rc})
		}
		// 16. DS
		for _, ds := range record.DSs {
			var rc any = nil
			dataVal := fmt.Sprintf("%d %d %d %s", ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
			if ds.Rcode != "" {
				rc = ds.Rcode
				dataVal = ""
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "DS", RecordData: dataVal, TTL: ds.TTL, TrustCode: ds.Attribute, TrustLevel: mapAttributeToTrustLevel(ds.Attribute), Rcode: rc})
		}
		// 17. NSEC
		for _, nsec := range record.NSECs {
			var rc any = nil
			dataVal := fmt.Sprintf("%s %s", nsec.NextDomain, strings.Join(nsec.Types, " "))
			if nsec.Rcode != "" {
				rc = nsec.Rcode
				dataVal = ""
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "NSEC", RecordData: dataVal, TTL: nsec.TTL, TrustCode: nsec.Attribute, TrustLevel: mapAttributeToTrustLevel(nsec.Attribute), Rcode: rc})
		}
		// 18. NSEC3
		for _, nsec3 := range record.NSEC3s {
			var rc any = nil
			dataVal := fmt.Sprintf("%d %d %d %s %s %s", nsec3.HashAlg, nsec3.Flags, nsec3.Iterations, nsec3.Salt, nsec3.NextDomain, strings.Join(nsec3.Types, " "))
			if nsec3.Rcode != "" {
				rc = nsec3.Rcode
				dataVal = ""
			}
			rows = append(rows, dbRow{SnapshotDate: snapshotDate, Domain: domain, RecordType: "NSEC3", RecordData: dataVal, TTL: nsec3.TTL, TrustCode: nsec3.Attribute, TrustLevel: mapAttributeToTrustLevel(nsec3.Attribute), Rcode: rc})
		}

		for _, row := range rows {
			rcStr := ""
			if row.Rcode != nil {
				rcStr = fmt.Sprintf("%v", row.Rcode)
			}
			_, err = stmt.Exec(row.SnapshotDate, bC.View, row.Domain, row.RecordType, row.RecordData, row.TTL, row.TrustCode, row.TrustLevel, rcStr)
			if err == nil {
				totalInserted++
			}
		}
	}

	if err := tx.Commit(); err != nil {
		fmt.Printf("提交 Flat 事务失败: %v\n", err)
		return
	}
	tx = nil
	fmt.Printf("快照 Flat 数据导入成功，共向 ClickHouse 导入 %d 行数据。\n", totalInserted)

	// 5. 批量写入 dns_adb_telemetry
	if len(bC.ADBRecords) > 0 {
		tx, err = db.Begin()
		if err != nil {
			fmt.Printf("开启 ADB 写入事务失败: %v\n", err)
			return
		}
		defer func() {
			if tx != nil {
				_ = tx.Rollback()
			}
		}()

		stmtAdb, err := tx.Prepare(`
			INSERT INTO dns_adb_telemetry
			(snapshot_date, view, ns_name, ip, srtt, flags, edns_success, edns_timeout, plain_success, plain_timeout, udpsize, cookie, ttl)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			fmt.Printf("准备 ADB INSERT 语句失败: %v\n", err)
			return
		}
		defer stmtAdb.Close()

		adbInserted := 0
		for _, adb := range bC.ADBRecords {
			_, err = stmtAdb.Exec(
				snapshotDate,
				bC.View,
				adb.Name,
				adb.IP,
				adb.SRTT,
				adb.Flags,
				adb.EDNSSuccess,
				adb.EDNSTimeout,
				adb.PlainSuccess,
				adb.PlainTimeout,
				adb.UDPSize,
				adb.Cookie,
				adb.TTL,
			)
			if err == nil {
				adbInserted++
			}
		}

		if err := tx.Commit(); err != nil {
			fmt.Printf("提交 ADB 事务失败: %v\n", err)
			return
		}
		tx = nil
		fmt.Printf("快照 ADB 数据导入成功，共向 ClickHouse 导入 %d 行遥测数据。\n", adbInserted)
	}

	// 运行标签评估及状态机追踪
	bC.runDailyAnalysisAndSave(snapshotDate, db)
}

func (bC *BindCache) outputNS() {
	var buffer bytes.Buffer
	for domain, record := range bC.records {
		if len(record.NSs) > 0 {
			var targets []string
			for _, v := range record.NSs {
				targets = append(targets, v.NsDomain)
			}
			buffer.WriteString(domain + "|" + strings.Join(targets, ",") + "\n")
		}
	}
	_ = os.WriteFile("ns_records.txt."+time.Now().Format("20060102150405"), buffer.Bytes(), 0644)
}

func (bC *BindCache) outputDomainNsIP() {
	var buffer bytes.Buffer
	for domain, record := range bC.records {
		for _, ns := range record.NSs {
			var ips []string
			for _, a := range bC.records[ns.NsDomain].As {
				ips = append(ips, a.IP)
			}
			for _, aaaa := range bC.records[ns.NsDomain].AAAAs {
				ips = append(ips, aaaa.IP)
			}
			if len(ips) > 0 {
				buffer.WriteString(fmt.Sprintf("%s|%s|%s\n", domain, ns.NsDomain, strings.Join(ips, ",")))
			}
		}
	}
	_ = os.WriteFile("domain_ns_ip.txt."+time.Now().Format("20060102150405"), buffer.Bytes(), 0644)
}

func (bC *BindCache) outputSOA() {
	var buffer bytes.Buffer
	for domain, record := range bC.records {
		for _, soa := range record.SOAs {
			buffer.WriteString(fmt.Sprintf("%s|%s %s %d\n", domain, soa.MName, soa.RName, soa.Serial))
		}
	}
	_ = os.WriteFile("soa_records.txt."+time.Now().Format("20060102150405"), buffer.Bytes(), 0644)
}

func (bC *BindCache) outputSRV() {
	var buffer bytes.Buffer
	for domain, record := range bC.records {
		for _, srv := range record.SRVs {
			buffer.WriteString(fmt.Sprintf("%s|%d %d %d %s\n", domain, srv.Priority, srv.Weight, srv.Port, srv.Target))
		}
	}
	_ = os.WriteFile("srv_records.txt."+time.Now().Format("20060102150405"), buffer.Bytes(), 0644)
}

func (bC *BindCache) outputCAA() {
	var buffer bytes.Buffer
	for domain, record := range bC.records {
		for _, caa := range record.CAAs {
			buffer.WriteString(fmt.Sprintf("%s|%d %s %s\n", domain, caa.Flag, caa.Tag, caa.Value))
		}
	}
	_ = os.WriteFile("caa_records.txt."+time.Now().Format("20060102150405"), buffer.Bytes(), 0644)
}

func (bC *BindCache) outputTLSA() {
	var buffer bytes.Buffer
	for domain, record := range bC.records {
		for _, tlsa := range record.TLSAs {
			buffer.WriteString(fmt.Sprintf("%s|%d %d %d %s\n", domain, tlsa.Usage, tlsa.Selector, tlsa.MatchingType, tlsa.CertificateAssocData))
		}
	}
	_ = os.WriteFile("tlsa_records.txt."+time.Now().Format("20060102150405"), buffer.Bytes(), 0644)
}

func (bC *BindCache) outputNAPTR() {
	var buffer bytes.Buffer
	for domain, record := range bC.records {
		for _, naptr := range record.NAPTRs {
			buffer.WriteString(fmt.Sprintf("%s|%d %d %s %s %s %s\n", domain, naptr.Order, naptr.Preference, naptr.Flags, naptr.Services, naptr.Regexp, naptr.Replacement))
		}
	}
	_ = os.WriteFile("naptr_records.txt."+time.Now().Format("20060102150405"), buffer.Bytes(), 0644)
}

func (bC *BindCache) outputRRSIG() {
	var buffer bytes.Buffer
	for domain, record := range bC.records {
		for _, rrsig := range record.RRSIGs {
			buffer.WriteString(fmt.Sprintf("%s|%s %d %s\n", domain, rrsig.TypeCovered, rrsig.KeyTag, rrsig.SignerName))
		}
	}
	_ = os.WriteFile("rrsig_records.txt."+time.Now().Format("20060102150405"), buffer.Bytes(), 0644)
}

func (bC *BindCache) outputDNSKEY() {
	var buffer bytes.Buffer
	for domain, record := range bC.records {
		for _, dnskey := range record.DNSKEYs {
			buffer.WriteString(fmt.Sprintf("%s|%d %d %d %s\n", domain, dnskey.Flags, dnskey.Protocol, dnskey.Algorithm, dnskey.PublicKey))
		}
	}
	_ = os.WriteFile("dnskey_records.txt."+time.Now().Format("20060102150405"), buffer.Bytes(), 0644)
}

func (bC *BindCache) outputDS() {
	var buffer bytes.Buffer
	for domain, record := range bC.records {
		for _, ds := range record.DSs {
			buffer.WriteString(fmt.Sprintf("%s|%d %d %d %s\n", domain, ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest))
		}
	}
	_ = os.WriteFile("ds_records.txt."+time.Now().Format("20060102150405"), buffer.Bytes(), 0644)
}

func (bC *BindCache) outputNSEC() {
	var buffer bytes.Buffer
	for domain, record := range bC.records {
		for _, nsec := range record.NSECs {
			buffer.WriteString(fmt.Sprintf("%s|%s|%s\n", domain, nsec.NextDomain, strings.Join(nsec.Types, ",")))
		}
	}
	_ = os.WriteFile("nsec_records.txt."+time.Now().Format("20060102150405"), buffer.Bytes(), 0644)
}

func (bC *BindCache) outputNSEC3() {
	var buffer bytes.Buffer
	for domain, record := range bC.records {
		for _, nsec3 := range record.NSEC3s {
			buffer.WriteString(fmt.Sprintf("%s|%d %d %s %s|%s\n", domain, nsec3.HashAlg, nsec3.Iterations, nsec3.Salt, nsec3.NextDomain, strings.Join(nsec3.Types, ",")))
		}
	}
	_ = os.WriteFile("nsec3_records.txt."+time.Now().Format("20060102150405"), buffer.Bytes(), 0644)
}

func (bC *BindCache) outputDNAME() {
	dnameMap := make(map[string][]string)

	for domain, record := range bC.records {
		if len(record.DNAMEs) > 0 {
			var dnameTargets []string
			for _, v := range record.DNAMEs {
				if v.Target != "" {
					dnameTargets = append(dnameTargets, v.Target)
				} else if v.Rcode != "" {
					dnameTargets = append(dnameTargets, v.Rcode)
				}
			}
			if len(dnameTargets) > 0 {
				dnameMap[domain] = dnameTargets
			}
		}
	}

	var buffer bytes.Buffer
	fmt.Printf("发现%d个DNAME记录\n", len(dnameMap))
	for domain, dnameTargets := range dnameMap {
		buffer.WriteString(domain + "|" + strings.Join(dnameTargets, ",") + "\n")
	}

	file, err := os.Create("dname_records.txt." + time.Now().Format("20060102150405"))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	buffer.WriteTo(file)
}

func (bC *BindCache) outputADB() {
	var buffer bytes.Buffer
	fmt.Printf("发现%d个ADB遥测记录\n", len(bC.ADBRecords))
	for _, rec := range bC.ADBRecords {
		buffer.WriteString(fmt.Sprintf("%s|%s|srtt:%d|flags:%s|edns:%d/%d|plain:%d/%d|udpsize:%d|cookie:%s|ttl:%d\n",
			rec.Name, rec.IP, rec.SRTT, parseADBFlags(rec.Flags), rec.EDNSSuccess, rec.EDNSTimeout,
			rec.PlainSuccess, rec.PlainTimeout, rec.UDPSize, rec.Cookie, rec.TTL))
	}
	_ = os.WriteFile("adb_records.txt."+time.Now().Format("20060102150405"), buffer.Bytes(), 0644)
}
