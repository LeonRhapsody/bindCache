package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	"time"
)

// StartWebServer 启动控制台 Web 服务
func StartWebServer(port string) {
	// 连接数据库
	db, err := sql.Open("clickhouse", GlobalConfig.ClickhouseDSN)
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}
	defer db.Close()

	// 确认数据库连接就绪
	err = db.Ping()
	if err != nil {
		log.Fatalf("无法连接到 ClickHouse 服务: %v", err)
	}

	http.HandleFunc("/api/dates", corsHandler(func(w http.ResponseWriter, r *http.Request) {
		getSnapshotDates(db, w, r)
	}))

	http.HandleFunc("/api/snapshot", corsHandler(func(w http.ResponseWriter, r *http.Request) {
		getSnapshotRecords(db, w, r)
	}))

	http.HandleFunc("/api/analysis", corsHandler(func(w http.ResponseWriter, r *http.Request) {
		getDailyAnalysis(db, w, r)
	}))

	http.HandleFunc("/api/rr-stats", corsHandler(func(w http.ResponseWriter, r *http.Request) {
		getRRStats(db, w, r)
	}))

	http.HandleFunc("/", corsHandler(func(w http.ResponseWriter, r *http.Request) {
		serveIndexPage(w, r)
	}))

	fmt.Printf("\n==================================================\n")
	fmt.Printf("  DNS 解析与缓存分析系统 Web 控制台已启动\n")
	fmt.Printf("  访问地址: http://127.0.0.1:%s/\n", port)
	fmt.Printf("==================================================\n\n")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("启动 Web 服务失败: %v", err)
	}
}

// 跨域中间件
func corsHandler(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		h(w, r)
	}
}

// 服务前端页面
func serveIndexPage(w http.ResponseWriter, r *http.Request) {
	// 试图读取本地 web/index.html 文件
	htmlBytes, err := os.ReadFile("web/index.html")
	if err == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(htmlBytes)
		return
	}

	// 如果没有文件，输出嵌入的前端页面（做为保底方案）
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(defaultEmbeddedHTML))
}

// 1. 获取已导入的快照日期列表
func getSnapshotDates(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT snapshot_date, total_domains, imported_at FROM snapshots ORDER BY snapshot_date DESC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type dateItem struct {
		Date         string `json:"snapshot_date"`
		TotalDomains int    `json:"total_domains"`
		ImportedAt   string `json:"imported_at"`
	}

	var list []dateItem
	for rows.Next() {
		var item dateItem
		var dVal time.Time
		var t time.Time
		if err := rows.Scan(&dVal, &item.TotalDomains, &t); err == nil {
			item.Date = dVal.Format("2006-01-02")
			item.ImportedAt = t.Format("2006-01-02 15:04:05")
			list = append(list, item)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// 2. 分页且支持多维检索全量详单
func getSnapshotRecords(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	date := q.Get("date")
	if date == "" {
		http.Error(w, "缺少 date 参数", http.StatusBadRequest)
		return
	}
	if len(date) > 10 {
		date = date[:10]
	}

	domain := q.Get("domain")
	domainMatch := q.Get("domain_match")
	mainDomain := q.Get("main_domain")
	mainDomainMatch := q.Get("main_domain_match")
	recType := q.Get("type")
	pageStr := q.Get("page")
	limitStr := q.Get("limit")

	page := 1
	limit := 20
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	offset := (page - 1) * limit

	// 构建查询 SQL
	whereClause := "WHERE snapshot_date = ?"
	args := []any{date}

	if mainDomain != "" {
		if !strings.HasSuffix(mainDomain, ".") {
			mainDomain += "."
		}
		if mainDomainMatch == "like" {
			cleanMain := strings.TrimSuffix(mainDomain, ".")
			whereClause += " AND domain LIKE ?"
			args = append(args, "%"+cleanMain+"%")
		} else {
			whereClause += " AND (domain = ? OR domain LIKE ?)"
			args = append(args, mainDomain, "%."+mainDomain)
		}
	}

	if domain != "" {
		if domainMatch == "exact" {
			if !strings.HasSuffix(domain, ".") {
				domain += "."
			}
			whereClause += " AND domain = ?"
			args = append(args, domain)
		} else {
			cleanDom := strings.TrimSuffix(domain, ".")
			whereClause += " AND domain LIKE ?"
			args = append(args, "%"+cleanDom+"%")
		}
	}

	if recType != "" {
		whereClause += " AND record_type = ?"
		args = append(args, recType)
	}

	// 查总数
	var total int
	countSQL := fmt.Sprintf("SELECT count() FROM dns_cache_flat %s", whereClause)
	err := db.QueryRow(countSQL, args...).Scan(&total)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 查列表 (由于 ClickHouse 表无自增 ID，这里根据主键前缀排序，并通过 Go 自增序号填充 ID 供前端渲染)
	querySQL := fmt.Sprintf("SELECT domain, record_type, record_data, ttl, trust_code, trust_level, rcode FROM dns_cache_flat %s ORDER BY domain, record_type LIMIT ? OFFSET ?", whereClause)
	queryArgs := append(args, limit, offset)

	rows, err := db.Query(querySQL, queryArgs...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type recordItem struct {
		ID         int     `json:"id"`
		Domain     string  `json:"domain"`
		RecordType string  `json:"record_type"`
		RecordData string  `json:"record_data"`
		TTL        int     `json:"ttl"`
		TrustCode  string  `json:"trust_code"`
		TrustLevel int     `json:"trust_level"`
		Rcode      *string `json:"rcode"`
	}

	list := make([]recordItem, 0)
	idx := offset + 1
	for rows.Next() {
		var item recordItem
		var rcode sql.NullString
		err := rows.Scan(
			&item.Domain, &item.RecordType, &item.RecordData, &item.TTL,
			&item.TrustCode, &item.TrustLevel, &rcode,
		)
		if err == nil {
			item.ID = idx
			idx++
			if rcode.Valid {
				item.Rcode = &rcode.String
			}
			list = append(list, item)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"total": total,
		"data":  list,
	})
}

// 3. 每日隐患分析结果（Dashboard指标与列表明细）
func getDailyAnalysis(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	date := q.Get("date")
	if date == "" {
		http.Error(w, "缺少 date 参数", http.StatusBadRequest)
		return
	}
	if len(date) > 10 {
		date = date[:10]
	}

	issueType := q.Get("issue_type")
	riskLevel := q.Get("risk_level")
	pageStr := q.Get("page")
	limitStr := q.Get("limit")

	page := 1
	limit := 20
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	offset := (page - 1) * limit

	// 1. 获取汇总大屏指标（统计指定快照日期当天处于活跃的隐患数量）
	var totalDomains int
	var view string
	db.QueryRow("SELECT total_domains, view FROM snapshots WHERE snapshot_date = ?", date).Scan(&totalDomains, &view)

	var singleNSCount, parentChildCount, hijackCount, countryJumpCount, asnChangeCount, rfc1918LeakCount, ttlAnomalyCount int
	db.QueryRow("SELECT count() FROM analysis_results_tracker WHERE toDate(first_detected) <= ? AND toDate(last_active) >= ? AND issue_type = 'single_ns'", date, date).Scan(&singleNSCount)
	db.QueryRow("SELECT count() FROM analysis_results_tracker WHERE toDate(first_detected) <= ? AND toDate(last_active) >= ? AND issue_type = 'parent_child'", date, date).Scan(&parentChildCount)
	db.QueryRow("SELECT count() FROM analysis_results_tracker WHERE toDate(first_detected) <= ? AND toDate(last_active) >= ? AND issue_type = 'hijack'", date, date).Scan(&hijackCount)
	db.QueryRow("SELECT count() FROM analysis_results_tracker WHERE toDate(first_detected) <= ? AND toDate(last_active) >= ? AND issue_type = 'country_jump'", date, date).Scan(&countryJumpCount)
	db.QueryRow("SELECT count() FROM analysis_results_tracker WHERE toDate(first_detected) <= ? AND toDate(last_active) >= ? AND issue_type = 'asn_change'", date, date).Scan(&asnChangeCount)
	db.QueryRow("SELECT count() FROM analysis_results_tracker WHERE toDate(first_detected) <= ? AND toDate(last_active) >= ? AND issue_type = 'rfc1918_leak'", date, date).Scan(&rfc1918LeakCount)
	db.QueryRow("SELECT count() FROM analysis_results_tracker WHERE toDate(first_detected) <= ? AND toDate(last_active) >= ? AND issue_type = 'ttl_anomaly'", date, date).Scan(&ttlAnomalyCount)

	// 计算危机、高危、信息级别的条数
	var crisisCount, highCount, infoCount int
	db.QueryRow("SELECT count() FROM analysis_results_tracker WHERE toDate(first_detected) <= ? AND toDate(last_active) >= ? AND risk_level = 'crisis'", date, date).Scan(&crisisCount)
	db.QueryRow("SELECT count() FROM analysis_results_tracker WHERE toDate(first_detected) <= ? AND toDate(last_active) >= ? AND risk_level = 'high'", date, date).Scan(&highCount)
	db.QueryRow("SELECT count() FROM analysis_results_tracker WHERE toDate(first_detected) <= ? AND toDate(last_active) >= ? AND risk_level = 'medium'", date, date).Scan(&infoCount)

	// 2. 查列表明细
	whereClause := "WHERE toDate(first_detected) <= ? AND toDate(last_active) >= ?"
	args := []any{date, date}

	if issueType != "" {
		whereClause += " AND issue_type = ?"
		args = append(args, issueType)
	}
	if riskLevel != "" {
		whereClause += " AND risk_level = ?"
		args = append(args, riskLevel)
	}

	// 查总数
	var total int
	countSQL := fmt.Sprintf("SELECT count() FROM analysis_results_tracker %s", whereClause)
	err := db.QueryRow(countSQL, args...).Scan(&total)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 查列表 (分页，按严重等级高低、域名升序排序)
	querySQL := fmt.Sprintf("SELECT domain, issue_type, risk_level, first_detected, last_active, status, resolved_at, details FROM analysis_results_tracker %s ORDER BY risk_level='crisis' DESC, risk_level='high' DESC, domain ASC LIMIT ? OFFSET ?", whereClause)
	queryArgs := append(args, limit, offset)

	rows, err := db.Query(querySQL, queryArgs...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type analysisItem struct {
		ID            int     `json:"id"`
		Domain        string  `json:"domain"`
		IssueType     string  `json:"issue_type"`
		RiskLevel     string  `json:"risk_level"`
		Details       string  `json:"details"`
		DetectedAt    string  `json:"detected_at"` // 兼容原有前端字段
		FirstDetected string  `json:"first_detected"`
		LastActive    string  `json:"last_active"`
		Status        string  `json:"status"`
		ResolvedAt    *string `json:"resolved_at"`
	}

	list := make([]analysisItem, 0)
	idx := offset + 1
	for rows.Next() {
		var item analysisItem
		var fDet, lAct time.Time
		var resAt sql.NullTime
		err := rows.Scan(
			&item.Domain, &item.IssueType, &item.RiskLevel,
			&fDet, &lAct, &item.Status, &resAt, &item.Details,
		)
		if err == nil {
			item.ID = idx
			idx++
			item.FirstDetected = fDet.Format("2006-01-02 15:04:05")
			item.LastActive = lAct.Format("2006-01-02 15:04:05")
			item.DetectedAt = item.FirstDetected
			if resAt.Valid {
				tStr := resAt.Time.Format("2006-01-02 15:04:05")
				item.ResolvedAt = &tStr
			}
			list = append(list, item)
		}
	}

	// 兼容大屏：把国家跳变和 ASN 跳变计数融进原 ns_change_count 呈现给前端大屏
	nsChangeCountCombined := countryJumpCount + asnChangeCount

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"metrics": map[string]any{
			"total_domains":      totalDomains,
			"view":               view,
			"single_ns_count":    singleNSCount,
			"parent_child_count": parentChildCount,
			"hijack_count":       hijackCount,
			"ns_change_count":    nsChangeCountCombined,
			"rfc1918_leak_count": rfc1918LeakCount,
			"ttl_anomaly_count":  ttlAnomalyCount,
			"crisis_count":       crisisCount,
			"high_count":         highCount,
			"info_count":         infoCount,
		},
		"total": total,
		"data":  list,
	})
}

// 静态嵌入 HTML 作为未找到 index.html 时的保底
const defaultEmbeddedHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>DNS流量监测与分析</title>
</head>
<body>
    <div style="padding: 50px; text-align: center; font-family: sans-serif;">
        <h2>系统已启动，未检测到本地前端页面。</h2>
        <p>请在项目根目录下创建 <code>web/index.html</code> 页面文件，并重新加载。</p>
    </div>
</body>
</html>`

// 4. 获取各资源记录类型的计数分布
func getRRStats(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	date := q.Get("date")
	if date == "" {
		http.Error(w, "缺少 date 参数", http.StatusBadRequest)
		return
	}
	if len(date) > 10 {
		date = date[:10]
	}

	rows, err := db.Query(`
		SELECT record_type, count()
		FROM dns_cache_flat
		WHERE snapshot_date = ?
		GROUP BY record_type
		ORDER BY count() DESC`, date)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	stats := make(map[string]int)
	for rows.Next() {
		var rType string
		var count int
		if err := rows.Scan(&rType, &count); err == nil {
			stats[rType] = count
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
