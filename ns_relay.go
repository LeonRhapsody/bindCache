package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/smtp"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	nsRelayDNSProbePath = "/v1/dns-probe"
	nsRelayEmailPath    = "/v1/email"
)

// DNSProbeExecutor 允许采集机将 DNS 拨测委托给同网段 relay；接口返回结构化
// DNSProbeAnswer，使后续的组内共识与风险判定与直连模式完全一致。
type DNSProbeExecutor interface {
	QueryDNS(ctx context.Context, domain, resolver string, recursive bool, timeout time.Duration) DNSProbeAnswer
}

type typedDNSProbeExecutor interface {
	QueryDNSRecords(ctx context.Context, domain, resolver string, recursive bool, timeout time.Duration, types []string) DNSProbeAnswer
}

type directDNSProbeExecutor struct{}

func (directDNSProbeExecutor) QueryDNS(ctx context.Context, domain, resolver string, recursive bool, timeout time.Duration) DNSProbeAnswer {
	return queryDNSProbe(ctx, domain, resolver, recursive, timeout)
}

func (directDNSProbeExecutor) QueryDNSRecords(ctx context.Context, domain, resolver string, recursive bool, timeout time.Duration, types []string) DNSProbeAnswer {
	return queryDNSProbeTypes(ctx, domain, resolver, recursive, timeout, types)
}

type NSRelayClient struct {
	baseURL string
	token   string
	client  *http.Client
}

type nsRelayDNSProbeRequest struct {
	RequestID string   `json:"request_id,omitempty"`
	Domain    string   `json:"domain"`
	Resolver  string   `json:"resolver"`
	Recursive bool     `json:"recursive"`
	Types     []string `json:"types,omitempty"`
	TimeoutMS int64    `json:"timeout_ms"`
}

type nsRelayDNSProbeResponse struct {
	Answer DNSProbeAnswer `json:"answer"`
	Error  string         `json:"error,omitempty"`
}

type nsRelayEmailRequest struct {
	RequestID string   `json:"request_id,omitempty"`
	To        []string `json:"to"`
	Subject   string   `json:"subject"`
	Text      string   `json:"text"`
}

type nsRelayEmailResponse struct {
	Accepted int    `json:"accepted"`
	Message  string `json:"message,omitempty"`
	Error    string `json:"error,omitempty"`
}

func NewNSRelayClient(config RelayClientConfig) (*NSRelayClient, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(config.URL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("relay_client.url 不能为空")
	}
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("relay_client.url 必须以 http:// 或 https:// 开头")
	}
	tokenEnv := strings.TrimSpace(config.TokenEnv)
	if tokenEnv == "" {
		return nil, fmt.Errorf("relay_client.token_env 不能为空")
	}
	token := strings.TrimSpace(os.Getenv(tokenEnv))
	if token == "" {
		return nil, fmt.Errorf("relay 令牌环境变量 %s 未设置", tokenEnv)
	}
	timeout, err := configDuration(config.Timeout, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("relay_client.timeout: %w", err)
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if caPath := strings.TrimSpace(config.TLSCA); caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("读取 relay CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("relay CA 文件未包含有效证书")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &NSRelayClient{baseURL: baseURL, token: token, client: &http.Client{Transport: transport, Timeout: timeout}}, nil
}

func (c *NSRelayClient) QueryDNS(ctx context.Context, domain, resolver string, recursive bool, timeout time.Duration) DNSProbeAnswer {
	return c.QueryDNSRecords(ctx, domain, resolver, recursive, timeout, []string{"A", "AAAA"})
}

// QueryDNSRecords 是 relay 的通用 DNS 拨测入口。调用方显式传入记录类型，
// 采集机仍只连接 relay，不会直接访问目标 DNS。
func (c *NSRelayClient) QueryDNSRecords(ctx context.Context, domain, resolver string, recursive bool, timeout time.Duration, types []string) DNSProbeAnswer {
	started := time.Now()
	fallback := DNSProbeAnswer{Resolver: resolver, Recursive: recursive, Transport: "relay", RCode: "UNKNOWN"}
	if c == nil || c.client == nil {
		fallback.Error = "relay 客户端未初始化"
		fallback.DurationMS = time.Since(started).Milliseconds()
		return fallback
	}
	response, err := c.doJSON(ctx, nsRelayDNSProbePath, nsRelayDNSProbeRequest{
		Domain: domain, Resolver: resolver, Recursive: recursive,
		Types: types, TimeoutMS: timeout.Milliseconds(),
	}, 256<<10)
	if err != nil {
		fallback.Error = "relay DNS 请求失败: " + err.Error()
		fallback.DurationMS = time.Since(started).Milliseconds()
		return fallback
	}
	var payload nsRelayDNSProbeResponse
	if err := json.Unmarshal(response, &payload); err != nil {
		fallback.Error = "解析 relay DNS 响应失败: " + err.Error()
		fallback.DurationMS = time.Since(started).Milliseconds()
		return fallback
	}
	if payload.Error != "" {
		fallback.Error = "relay DNS 拒绝: " + payload.Error
		fallback.DurationMS = time.Since(started).Milliseconds()
		return fallback
	}
	if payload.Answer.Resolver == "" {
		payload.Answer.Resolver = resolver
	}
	payload.Answer.Recursive = recursive
	if payload.Answer.Transport == "" {
		payload.Answer.Transport = "relay"
	}
	return payload.Answer
}

func (c *NSRelayClient) SendEmail(ctx context.Context, request nsRelayEmailRequest) (nsRelayEmailResponse, error) {
	if c == nil || c.client == nil {
		return nsRelayEmailResponse{}, fmt.Errorf("relay 客户端未初始化")
	}
	response, err := c.doJSON(ctx, nsRelayEmailPath, request, 128<<10)
	if err != nil {
		return nsRelayEmailResponse{}, err
	}
	var payload nsRelayEmailResponse
	if err := json.Unmarshal(response, &payload); err != nil {
		return nsRelayEmailResponse{}, fmt.Errorf("解析 relay 邮件响应: %w", err)
	}
	if payload.Error != "" {
		return payload, fmt.Errorf("relay 邮件拒绝: %s", payload.Error)
	}
	return payload, nil
}

func (c *NSRelayClient) Health(ctx context.Context) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("relay 客户端未初始化")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("relay health HTTP %d", response.StatusCode)
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&payload); err != nil {
		return fmt.Errorf("解析 relay health: %w", err)
	}
	if payload.Status != "ok" {
		return fmt.Errorf("relay 状态 %q", payload.Status)
	}
	return nil
}

func (c *NSRelayClient) doJSON(ctx context.Context, path string, body any, maxResponse int64) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponse))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		var remote struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(payload, &remote)
		if remote.Error != "" {
			return nil, fmt.Errorf("HTTP %d: %s", response.StatusCode, remote.Error)
		}
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return payload, nil
}

type nsRelayServer struct {
	config       RelayServerConfig
	token        string
	allowedCIDRs []netip.Prefix
	maxDNSDelay  time.Duration
	recipients   map[string]struct{}
	allowedPorts map[string]struct{}
}

func StartNSRelayServer(config RelayServerConfig) error {
	server, err := newNSRelayServer(config)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.health)
	mux.HandleFunc(nsRelayDNSProbePath, server.dnsProbe)
	mux.HandleFunc(nsRelayEmailPath, server.email)
	httpServer := &http.Server{Addr: server.config.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second}
	fmt.Printf("NS relay 已启动: %s（DNS 拨测与邮件代理）\n", server.config.Listen)
	if server.config.TLSCert != "" || server.config.TLSKey != "" {
		if server.config.TLSCert == "" || server.config.TLSKey == "" {
			return fmt.Errorf("relay TLS 证书与私钥必须同时配置")
		}
		return httpServer.ListenAndServeTLS(server.config.TLSCert, server.config.TLSKey)
	}
	return httpServer.ListenAndServe()
}

func newNSRelayServer(config RelayServerConfig) (*nsRelayServer, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("relay_server.enabled 未启用")
	}
	if strings.TrimSpace(config.Listen) == "" {
		return nil, fmt.Errorf("relay_server.listen 不能为空")
	}
	tokenEnv := strings.TrimSpace(config.TokenEnv)
	if tokenEnv == "" {
		return nil, fmt.Errorf("relay_server.token_env 不能为空")
	}
	token := strings.TrimSpace(os.Getenv(tokenEnv))
	if token == "" {
		return nil, fmt.Errorf("relay 令牌环境变量 %s 未设置", tokenEnv)
	}
	if len(config.AllowedCIDRs) == 0 {
		return nil, fmt.Errorf("relay_server.allowed_client_cidrs 不能为空")
	}
	prefixes := make([]netip.Prefix, 0, len(config.AllowedCIDRs))
	for _, value := range config.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("relay 客户端 CIDR %q: %w", value, err)
		}
		prefixes = append(prefixes, prefix)
	}
	maxDNSDuration, err := configDuration(config.MaxDNSDuration, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("relay_server.max_dns_duration: %w", err)
	}
	if config.MaxRequestBytes <= 0 {
		config.MaxRequestBytes = 1 << 20
	}
	recipients := make(map[string]struct{}, len(config.AllowedRecipients))
	for _, recipient := range config.AllowedRecipients {
		recipient = strings.ToLower(strings.TrimSpace(recipient))
		if recipient != "" {
			recipients[recipient] = struct{}{}
		}
	}
	ports := config.AllowedDNSPorts
	if len(ports) == 0 {
		ports = []int{53}
	}
	allowedPorts := make(map[string]struct{}, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("relay DNS 端口无效: %d", port)
		}
		allowedPorts[strconv.Itoa(port)] = struct{}{}
	}
	return &nsRelayServer{config: config, token: token, allowedCIDRs: prefixes, maxDNSDelay: maxDNSDuration, recipients: recipients, allowedPorts: allowedPorts}, nil
}

func (s *nsRelayServer) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		relayJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET"})
		return
	}
	relayJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *nsRelayServer) dnsProbe(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		relayJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 POST"})
		return
	}
	var request nsRelayDNSProbeRequest
	if err := s.decodeRequest(w, r, &request); err != nil {
		return
	}
	resolver, err := validateRelayResolverPorts(request.Resolver, s.allowedPorts)
	if err != nil {
		relayJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	domain := normalizeFQDN(request.Domain)
	if domain == "" || len(domain) > 254 {
		relayJSON(w, http.StatusBadRequest, map[string]string{"error": "无效 DNS 域名"})
		return
	}
	timeout := time.Duration(request.TimeoutMS) * time.Millisecond
	if timeout <= 0 || timeout > s.maxDNSDelay {
		timeout = s.maxDNSDelay
	}
	types, err := normalizeRelayQueryTypes(request.Types)
	if err != nil {
		relayJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// 每种记录类型最多经历一次 UDP 和一次 TCP；总时限随显式类型数增长，
	// 避免 NS/DS/DNSKEY 组合查询被旧的 A+AAAA 时限提前截断。
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(len(types)*2)*timeout+time.Second)
	defer cancel()
	answer := queryDNSProbeTypes(ctx, domain, resolver, request.Recursive, timeout, types)
	relayJSON(w, http.StatusOK, nsRelayDNSProbeResponse{Answer: answer})
}

func normalizeRelayQueryTypes(values []string) ([]string, error) {
	if len(values) == 0 {
		return []string{"A", "AAAA"}, nil
	}
	if len(values) > 8 {
		return nil, fmt.Errorf("单次最多查询 8 种 DNS 记录")
	}
	allowed := map[string]struct{}{"A": {}, "AAAA": {}, "CNAME": {}, "NS": {}, "SOA": {}, "TXT": {}, "MX": {}, "DS": {}, "DNSKEY": {}}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{})
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if _, ok := allowed[value]; !ok {
			return nil, fmt.Errorf("不支持的 DNS 记录类型 %q", value)
		}
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result, nil
}

func (s *nsRelayServer) email(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		relayJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 POST"})
		return
	}
	if len(s.recipients) == 0 {
		relayJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "relay 未配置邮件收件人白名单"})
		return
	}
	var request nsRelayEmailRequest
	if err := s.decodeRequest(w, r, &request); err != nil {
		return
	}
	if len(request.To) == 0 || len(request.To) > 32 || len(request.Subject) == 0 || len(request.Subject) > 512 || len(request.Text) == 0 || len(request.Text) > 256<<10 {
		relayJSON(w, http.StatusBadRequest, map[string]string{"error": "邮件参数长度或收件人数量无效"})
		return
	}
	allowed := make([]string, 0, len(request.To))
	seen := make(map[string]struct{})
	for _, recipient := range request.To {
		recipient = strings.ToLower(strings.TrimSpace(recipient))
		if _, exists := s.recipients[recipient]; !exists {
			relayJSON(w, http.StatusForbidden, map[string]string{"error": "收件人不在 relay 白名单"})
			return
		}
		if _, exists := seen[recipient]; !exists {
			seen[recipient] = struct{}{}
			allowed = append(allowed, recipient)
		}
	}
	if err := sendRelayEmail(s.config.SMTP, allowed, request.Subject, request.Text); err != nil {
		relayJSON(w, http.StatusBadGateway, nsRelayEmailResponse{Error: err.Error()})
		return
	}
	relayJSON(w, http.StatusOK, nsRelayEmailResponse{Accepted: len(allowed), Message: "accepted"})
}

func (s *nsRelayServer) authorize(w http.ResponseWriter, r *http.Request) bool {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		relayJSON(w, http.StatusForbidden, map[string]string{"error": "无法识别客户端地址"})
		return false
	}
	remote, err := netip.ParseAddr(remoteHost)
	if err != nil {
		relayJSON(w, http.StatusForbidden, map[string]string{"error": "无效客户端地址"})
		return false
	}
	allowed := false
	for _, prefix := range s.allowedCIDRs {
		if prefix.Contains(remote) {
			allowed = true
			break
		}
	}
	if !allowed {
		relayJSON(w, http.StatusForbidden, map[string]string{"error": "客户端地址未授权"})
		return false
	}
	if !constantTimeTokenEqual(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), s.token) {
		relayJSON(w, http.StatusUnauthorized, map[string]string{"error": "认证失败"})
		return false
	}
	return true
}

func (s *nsRelayServer) decodeRequest(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		relayJSON(w, http.StatusBadRequest, map[string]string{"error": "请求 JSON 无效"})
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		relayJSON(w, http.StatusBadRequest, map[string]string{"error": "请求 JSON 不可包含多个对象"})
		return fmt.Errorf("多个 JSON 对象")
	}
	return nil
}

func validateRelayResolver(value string) (string, error) {
	return validateRelayResolverPorts(value, map[string]struct{}{"53": {}})
}

func validateRelayResolverPorts(value string, allowed map[string]struct{}) (string, error) {
	resolver, err := normalizeDNSResolverAddress(value, 53)
	if err != nil {
		return "", fmt.Errorf("无效 DNS 目标: %w", err)
	}
	host, port, err := net.SplitHostPort(resolver)
	if err != nil {
		return "", fmt.Errorf("无效 DNS 目标端口")
	}
	if _, ok := allowed[port]; !ok {
		return "", fmt.Errorf("relay 不允许 DNS %s 端口", port)
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err != nil {
		return "", fmt.Errorf("relay DNS 目标必须是 IP 地址")
	}
	return resolver, nil
}

func constantTimeTokenEqual(left, right string) bool {
	if len(left) != len(right) || len(right) == 0 {
		return false
	}
	var mismatch byte
	for index := range left {
		mismatch |= left[index] ^ right[index]
	}
	return mismatch == 0
}

func relayJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func sendRelayEmail(config SMTPConfig, recipients []string, subject, text string) error {
	if strings.TrimSpace(config.Host) == "" || config.Port <= 0 || strings.TrimSpace(config.From) == "" {
		return fmt.Errorf("relay SMTP 未完整配置")
	}
	username := strings.TrimSpace(os.Getenv(strings.TrimSpace(config.UsernameEnv)))
	password := os.Getenv(strings.TrimSpace(config.PasswordEnv))
	if config.UsernameEnv != "" && username == "" {
		return fmt.Errorf("SMTP 用户名环境变量未设置")
	}
	if config.PasswordEnv != "" && password == "" {
		return fmt.Errorf("SMTP 密码环境变量未设置")
	}
	hostPort := net.JoinHostPort(config.Host, fmt.Sprintf("%d", config.Port))
	message := buildRelayEmailMessage(config.From, recipients, subject, text)
	if !config.ImplicitTLS && !config.StartTLS {
		var auth smtp.Auth
		if username != "" {
			auth = smtp.PlainAuth("", username, password, config.Host)
		}
		return smtp.SendMail(hostPort, auth, config.From, recipients, message)
	}
	var connection net.Conn
	var err error
	if config.ImplicitTLS {
		connection, err = tls.Dial("tcp", hostPort, &tls.Config{ServerName: config.Host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: config.InsecureSkipVerify})
	} else {
		connection, err = net.DialTimeout("tcp", hostPort, 10*time.Second)
	}
	if err != nil {
		return err
	}
	defer connection.Close()
	client, err := smtp.NewClient(connection, config.Host)
	if err != nil {
		return err
	}
	defer client.Quit()
	if config.StartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP 服务不支持 STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: config.Host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: config.InsecureSkipVerify}); err != nil {
			return err
		}
	}
	if username != "" {
		if err := client.Auth(smtp.PlainAuth("", username, password, config.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(config.From); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	return writer.Close()
}

func buildRelayEmailMessage(from string, recipients []string, subject, text string) []byte {
	cleanSubject := strings.ReplaceAll(strings.ReplaceAll(subject, "\r", " "), "\n", " ")
	cleanFrom := strings.ReplaceAll(strings.ReplaceAll(from, "\r", ""), "\n", "")
	sortedTo := append([]string(nil), recipients...)
	sort.Strings(sortedTo)
	return []byte("From: " + cleanFrom + "\r\nTo: " + strings.Join(sortedTo, ", ") + "\r\nSubject: " + cleanSubject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + text)
}
