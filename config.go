package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// AppConfig 是部署级唯一配置入口。密码与共享令牌不放在 JSON 内，而是通过
// *_env 指定环境变量名，避免配置文件和命令行泄露凭据。
type AppConfig struct {
	// 保留旧字段，兼容已部署的 config.json；新部署可使用下方结构化配置。
	ClickhouseDSN string `json:"clickhouse_dsn"`
	WebPort       string `json:"web_port"`

	Web         WebRuntimeConfig         `json:"web"`
	DumpMonitor DumpMonitorRuntimeConfig `json:"dump_monitor"`
	GeoIP       GeoIPRuntimeConfig       `json:"geoip"`
	Probe       ProbeRuntimeConfig       `json:"probe"`
	RelayClient RelayClientConfig        `json:"relay_client"`
	Alerts      NSAlertRuntimeConfig     `json:"alerts"`
	Blacklist   NSBlacklistRuntimeConfig `json:"blacklist"`
	Campaign    CampaignRuntimeConfig    `json:"campaign"`
	RelayServer RelayServerConfig        `json:"relay_server"`
}

type WebRuntimeConfig struct {
	Listen      string          `json:"listen"`
	Port        string          `json:"port"`
	AuthEnabled bool            `json:"auth_enabled"`
	Users       []WebUserConfig `json:"users"`
}

type WebUserConfig struct {
	Username    string `json:"username"`
	PasswordEnv string `json:"password_env"`
	Role        string `json:"role"` // observer, operator, admin
}

type DumpMonitorRuntimeConfig struct {
	Directory       string `json:"directory"`
	LedgerPath      string `json:"ledger_path"`
	PollInterval    string `json:"poll_interval"`
	StabilityWindow string `json:"stability_window"`
}

type GeoIPRuntimeConfig struct {
	Directory string `json:"directory"`
}

type ProbeRuntimeConfig struct {
	Enabled            bool     `json:"enabled"`
	Backend            string   `json:"backend"` // relay 或 direct
	RecursiveResolver  string   `json:"recursive_resolver"`
	TrustedResolvers   []string `json:"trusted_resolvers"`
	Timeout            string   `json:"timeout"`
	EventTimeout       string   `json:"event_timeout"`
	MaxDomains         int      `json:"max_domains"`
	MaxParallel        int      `json:"max_parallel"`
	MaxEventsPerImport int      `json:"max_events_per_import"`
	DirectPort         int      `json:"direct_port"`
}

type RelayClientConfig struct {
	URL      string `json:"url"`
	TokenEnv string `json:"token_env"`
	Timeout  string `json:"timeout"`
	TLSCA    string `json:"tls_ca"`
}

type NSAlertRuntimeConfig struct {
	Enabled       bool     `json:"enabled"`
	Severities    []string `json:"severities"`
	Recipients    []string `json:"recipients"`
	SubjectPrefix string   `json:"subject_prefix"`
	Cooldown      string   `json:"cooldown"`
	Timeout       string   `json:"timeout"`
}

type NSBlacklistRuntimeConfig struct {
	Directory    string `json:"directory"`
	MaxFileBytes int64  `json:"max_file_bytes"`
	MaxEntries   int    `json:"max_entries"`
}

// RelayServerConfig 仅在可访问外网/SMTP 的同网段主机启用。AllowedCIDRs、
// AllowedRecipients 为空时分别拒绝远程客户端和邮件投递，防止其成为开放代理。
type RelayServerConfig struct {
	Enabled           bool       `json:"enabled"`
	Listen            string     `json:"listen"`
	TokenEnv          string     `json:"token_env"`
	AllowedCIDRs      []string   `json:"allowed_client_cidrs"`
	MaxRequestBytes   int64      `json:"max_request_bytes"`
	MaxDNSDuration    string     `json:"max_dns_duration"`
	AllowedRecipients []string   `json:"allowed_recipients"`
	AllowedDNSPorts   []int      `json:"allowed_dns_ports,omitempty"`
	TLSCert           string     `json:"tls_cert"`
	TLSKey            string     `json:"tls_key"`
	SMTP              SMTPConfig `json:"smtp"`
}

type SMTPConfig struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	UsernameEnv        string `json:"username_env"`
	PasswordEnv        string `json:"password_env"`
	From               string `json:"from"`
	StartTLS           bool   `json:"starttls"`
	ImplicitTLS        bool   `json:"implicit_tls"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

var (
	GlobalConfig      AppConfig
	GlobalConfigPath  string
	GlobalConfigError error
)

func DefaultAppConfig() AppConfig {
	return AppConfig{
		ClickhouseDSN: "clickhouse://default@127.0.0.1:19000/bind_cache_analyze?dial_timeout=10s",
		WebPort:       "8888",
		Web:           WebRuntimeConfig{Listen: "127.0.0.1", Port: "8888"},
		DumpMonitor:   DumpMonitorRuntimeConfig{PollInterval: "30s", StabilityWindow: "90s", LedgerPath: "/var/lib/bind-cache-analyze/dump-ledger.json"},
		GeoIP:         GeoIPRuntimeConfig{Directory: "geoip_data"},
		Probe: ProbeRuntimeConfig{
			Enabled:            false,
			Backend:            "relay",
			RecursiveResolver:  "127.0.0.1:53",
			TrustedResolvers:   []string{"114.114.114.114:53", "223.5.5.5:53"},
			Timeout:            "2s",
			EventTimeout:       "60s",
			MaxDomains:         20,
			MaxParallel:        12,
			MaxEventsPerImport: 3,
			DirectPort:         53,
		},
		RelayClient: RelayClientConfig{TokenEnv: "NS_RELAY_TOKEN", Timeout: "5s"},
		Alerts: NSAlertRuntimeConfig{
			Enabled:       false,
			Severities:    []string{"critical"},
			SubjectPrefix: "[DNS NS 严重告警]",
			Cooldown:      "24h",
			Timeout:       "10s",
		},
		Blacklist: NSBlacklistRuntimeConfig{
			MaxFileBytes: 64 << 20,
			MaxEntries:   2_000_000,
		},
		Campaign: CampaignRuntimeConfig{Enabled: true, MinDistinctZones: 10, HoldBaseline: true, MaxSnapshotGap: "30m"},
		RelayServer: RelayServerConfig{
			Listen:          "0.0.0.0:18787",
			TokenEnv:        "NS_RELAY_TOKEN",
			MaxRequestBytes: 1 << 20,
			MaxDNSDuration:  "5s",
		},
	}
}

func init() {
	GlobalConfigPath = strings.TrimSpace(os.Getenv("APP_CONFIG"))
	if GlobalConfigPath == "" {
		GlobalConfigPath = "config.json"
	}
	GlobalConfigError = ReloadGlobalConfig(GlobalConfigPath)
}

func ReloadGlobalConfig(path string) error {
	config, err := LoadAppConfig(path)
	if err != nil {
		return err
	}
	GlobalConfig = config
	GlobalConfigPath = path
	return nil
}

func LoadAppConfig(path string) (AppConfig, error) {
	config := DefaultAppConfig()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return applyAppConfigEnvironment(config), nil
		}
		return AppConfig{}, fmt.Errorf("读取配置文件 %s: %w", path, err)
	}
	var fileConfig AppConfig
	if err := json.Unmarshal(raw, &fileConfig); err != nil {
		return AppConfig{}, fmt.Errorf("解析配置文件 %s: %w", path, err)
	}
	mergeAppConfig(&config, fileConfig)
	// 默认开启的布尔项需要区分“配置未出现”和“显式 false”。
	var presence struct {
		Campaign map[string]json.RawMessage `json:"campaign"`
	}
	if json.Unmarshal(raw, &presence) == nil {
		if _, exists := presence.Campaign["enabled"]; exists {
			config.Campaign.Enabled = fileConfig.Campaign.Enabled
		}
		if _, exists := presence.Campaign["hold_baseline"]; exists {
			config.Campaign.HoldBaseline = fileConfig.Campaign.HoldBaseline
		}
	}
	return applyAppConfigEnvironment(config), nil
}

func mergeAppConfig(target *AppConfig, source AppConfig) {
	if source.ClickhouseDSN != "" {
		target.ClickhouseDSN = source.ClickhouseDSN
	}
	if source.WebPort != "" {
		target.WebPort = source.WebPort
		if source.Web.Port == "" {
			target.Web.Port = source.WebPort
		}
	}
	if source.Web.Listen != "" {
		target.Web.Listen = source.Web.Listen
	}
	if source.Web.Port != "" {
		target.Web.Port = source.Web.Port
	}
	if source.Web.AuthEnabled {
		target.Web.AuthEnabled = true
	}
	if len(source.Web.Users) > 0 {
		target.Web.Users = source.Web.Users
	}
	if target.Web.Port == "" {
		target.Web.Port = target.WebPort
	}
	if source.DumpMonitor.Directory != "" {
		target.DumpMonitor.Directory = source.DumpMonitor.Directory
	}
	if source.DumpMonitor.LedgerPath != "" {
		target.DumpMonitor.LedgerPath = source.DumpMonitor.LedgerPath
	}
	if source.DumpMonitor.PollInterval != "" {
		target.DumpMonitor.PollInterval = source.DumpMonitor.PollInterval
	}
	if source.DumpMonitor.StabilityWindow != "" {
		target.DumpMonitor.StabilityWindow = source.DumpMonitor.StabilityWindow
	}
	if source.GeoIP.Directory != "" {
		target.GeoIP.Directory = source.GeoIP.Directory
	}
	mergeProbeRuntimeConfig(&target.Probe, source.Probe)
	mergeRelayClientConfig(&target.RelayClient, source.RelayClient)
	mergeNSAlertRuntimeConfig(&target.Alerts, source.Alerts)
	if source.Blacklist.Directory != "" {
		target.Blacklist.Directory = source.Blacklist.Directory
	}
	if source.Blacklist.MaxFileBytes > 0 {
		target.Blacklist.MaxFileBytes = source.Blacklist.MaxFileBytes
	}
	if source.Blacklist.MaxEntries > 0 {
		target.Blacklist.MaxEntries = source.Blacklist.MaxEntries
	}
	if source.Campaign.Enabled {
		target.Campaign.Enabled = true
	}
	if source.Campaign.MinDistinctZones > 0 {
		target.Campaign.MinDistinctZones = source.Campaign.MinDistinctZones
	}
	if source.Campaign.HoldBaseline {
		target.Campaign.HoldBaseline = true
	}
	if source.Campaign.StatePath != "" {
		target.Campaign.StatePath = source.Campaign.StatePath
	}
	if source.Campaign.MaxSnapshotGap != "" {
		target.Campaign.MaxSnapshotGap = source.Campaign.MaxSnapshotGap
	}
	mergeRelayServerConfig(&target.RelayServer, source.RelayServer)
}

func mergeProbeRuntimeConfig(target *ProbeRuntimeConfig, source ProbeRuntimeConfig) {
	if source.Enabled {
		target.Enabled = true
	}
	if source.Backend != "" {
		target.Backend = source.Backend
	}
	if source.RecursiveResolver != "" {
		target.RecursiveResolver = source.RecursiveResolver
	}
	if len(source.TrustedResolvers) > 0 {
		target.TrustedResolvers = source.TrustedResolvers
	}
	if source.Timeout != "" {
		target.Timeout = source.Timeout
	}
	if source.EventTimeout != "" {
		target.EventTimeout = source.EventTimeout
	}
	if source.MaxDomains > 0 {
		target.MaxDomains = source.MaxDomains
	}
	if source.MaxParallel > 0 {
		target.MaxParallel = source.MaxParallel
	}
	if source.MaxEventsPerImport > 0 {
		target.MaxEventsPerImport = source.MaxEventsPerImport
	}
	if source.DirectPort > 0 {
		target.DirectPort = source.DirectPort
	}
}

func mergeRelayClientConfig(target *RelayClientConfig, source RelayClientConfig) {
	if source.URL != "" {
		target.URL = source.URL
	}
	if source.TokenEnv != "" {
		target.TokenEnv = source.TokenEnv
	}
	if source.Timeout != "" {
		target.Timeout = source.Timeout
	}
	if source.TLSCA != "" {
		target.TLSCA = source.TLSCA
	}
}

func mergeNSAlertRuntimeConfig(target *NSAlertRuntimeConfig, source NSAlertRuntimeConfig) {
	if source.Enabled {
		target.Enabled = true
	}
	if len(source.Severities) > 0 {
		target.Severities = source.Severities
	}
	if len(source.Recipients) > 0 {
		target.Recipients = source.Recipients
	}
	if source.SubjectPrefix != "" {
		target.SubjectPrefix = source.SubjectPrefix
	}
	if source.Cooldown != "" {
		target.Cooldown = source.Cooldown
	}
	if source.Timeout != "" {
		target.Timeout = source.Timeout
	}
}

func mergeRelayServerConfig(target *RelayServerConfig, source RelayServerConfig) {
	if source.Enabled {
		target.Enabled = true
	}
	if source.Listen != "" {
		target.Listen = source.Listen
	}
	if source.TokenEnv != "" {
		target.TokenEnv = source.TokenEnv
	}
	if len(source.AllowedCIDRs) > 0 {
		target.AllowedCIDRs = source.AllowedCIDRs
	}
	if source.MaxRequestBytes > 0 {
		target.MaxRequestBytes = source.MaxRequestBytes
	}
	if source.MaxDNSDuration != "" {
		target.MaxDNSDuration = source.MaxDNSDuration
	}
	if len(source.AllowedRecipients) > 0 {
		target.AllowedRecipients = source.AllowedRecipients
	}
	if len(source.AllowedDNSPorts) > 0 {
		target.AllowedDNSPorts = source.AllowedDNSPorts
	}
	if source.TLSCert != "" {
		target.TLSCert = source.TLSCert
	}
	if source.TLSKey != "" {
		target.TLSKey = source.TLSKey
	}
	mergeSMTPConfig(&target.SMTP, source.SMTP)
}

func mergeSMTPConfig(target *SMTPConfig, source SMTPConfig) {
	if source.Host != "" {
		target.Host = source.Host
	}
	if source.Port > 0 {
		target.Port = source.Port
	}
	if source.UsernameEnv != "" {
		target.UsernameEnv = source.UsernameEnv
	}
	if source.PasswordEnv != "" {
		target.PasswordEnv = source.PasswordEnv
	}
	if source.From != "" {
		target.From = source.From
	}
	if source.StartTLS {
		target.StartTLS = true
	}
	if source.ImplicitTLS {
		target.ImplicitTLS = true
	}
	if source.InsecureSkipVerify {
		target.InsecureSkipVerify = true
	}
}

func applyAppConfigEnvironment(config AppConfig) AppConfig {
	if value := strings.TrimSpace(os.Getenv("CLICKHOUSE_DSN")); value != "" {
		config.ClickhouseDSN = value
	}
	if value := strings.TrimSpace(os.Getenv("WEB_LISTEN")); value != "" {
		config.Web.Listen = value
	}
	if value := strings.TrimSpace(os.Getenv("WEB_PORT")); value != "" {
		config.Web.Port, config.WebPort = value, value
	}
	if value := strings.TrimSpace(os.Getenv("NS_DUMP_DIRECTORY")); value != "" {
		config.DumpMonitor.Directory = value
	}
	if value := strings.TrimSpace(os.Getenv("NS_DUMP_LEDGER_PATH")); value != "" {
		config.DumpMonitor.LedgerPath = value
	}
	if value := strings.TrimSpace(os.Getenv("NS_RELAY_URL")); value != "" {
		config.RelayClient.URL = value
	}
	if value := strings.TrimSpace(os.Getenv("NS_BLACKLIST_DIRECTORY")); value != "" {
		config.Blacklist.Directory = value
	}
	return config
}

func configDuration(value string, fallback time.Duration) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("无效时长 %q", value)
	}
	return duration, nil
}

// appConfigPathFromArgs 在定义 flag 前读取 -config，使其余 flag 的默认值已经来自
// 指定配置文件，而不是先从默认 config.json 取值后再覆盖。
func appConfigPathFromArgs(args []string) string {
	for index := 0; index < len(args); index++ {
		if args[index] == "-config" || args[index] == "--config" {
			if index+1 < len(args) {
				return args[index+1]
			}
		}
		if strings.HasPrefix(args[index], "-config=") {
			return strings.TrimPrefix(args[index], "-config=")
		}
		if strings.HasPrefix(args[index], "--config=") {
			return strings.TrimPrefix(args[index], "--config=")
		}
	}
	return ""
}
