package main

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// NSAlertConfig 定义严重线索的交付策略。当前仅支持 relay 发送，采集机不会
// 直连 SMTP 或外网；Email 内容由同网段 relay 根据服务器端 SMTP 配置投递。
type NSAlertConfig struct {
	Enabled       bool
	Severities    map[string]struct{}
	Recipients    []string
	SubjectPrefix string
	Cooldown      time.Duration
	Timeout       time.Duration
	Sender        NSAlertSender
}

type NSAlertSender interface {
	SendNSAlert(ctx context.Context, recipients []string, subject, text string) (int, error)
}

type relayNSAlertSender struct{ client *NSRelayClient }

func (s relayNSAlertSender) SendNSAlert(ctx context.Context, recipients []string, subject, text string) (int, error) {
	response, err := s.client.SendEmail(ctx, nsRelayEmailRequest{To: recipients, Subject: subject, Text: text})
	if err != nil {
		return 0, err
	}
	return response.Accepted, nil
}

type nsAlertNotification struct {
	EventID     string
	AlertType   string
	Recipient   string
	Status      string
	AttemptedAt time.Time
	Message     string
}

func BuildNSAlertConfig(runtime NSAlertRuntimeConfig, relay *NSRelayClient) (*NSAlertConfig, error) {
	if !runtime.Enabled {
		return &NSAlertConfig{Enabled: false}, nil
	}
	if relay == nil {
		return nil, fmt.Errorf("严重告警已启用但 relay 客户端未配置")
	}
	recipients := uniqueSortedStrings(runtime.Recipients)
	if len(recipients) == 0 {
		return nil, fmt.Errorf("严重告警已启用但 alerts.recipients 为空")
	}
	severities := make(map[string]struct{}, len(runtime.Severities))
	for _, severity := range runtime.Severities {
		severity = strings.ToLower(strings.TrimSpace(severity))
		if severity != "" {
			severities[severity] = struct{}{}
		}
	}
	if len(severities) == 0 {
		return nil, fmt.Errorf("严重告警已启用但 alerts.severities 为空")
	}
	cooldown, err := configDuration(runtime.Cooldown, 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("alerts.cooldown: %w", err)
	}
	timeout, err := configDuration(runtime.Timeout, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("alerts.timeout: %w", err)
	}
	prefix := strings.TrimSpace(runtime.SubjectPrefix)
	if prefix == "" {
		prefix = "[DNS NS 严重告警]"
	}
	return &NSAlertConfig{Enabled: true, Severities: severities, Recipients: recipients, SubjectPrefix: prefix, Cooldown: cooldown, Timeout: timeout, Sender: relayNSAlertSender{client: relay}}, nil
}

func dispatchNSAlerts(db *sql.DB, writer *nsClickHouseWriter, events []NSChangeEvent, probes []NSProbeResult, config *NSAlertConfig) (int, int) {
	if db == nil || writer == nil || config == nil || !config.Enabled || config.Sender == nil {
		return 0, 0
	}
	probesByEvent := make(map[string]NSProbeResult, len(probes))
	for _, probe := range probes {
		probesByEvent[probe.EventID] = probe
	}
	sent, failed := 0, 0
	for _, event := range events {
		if _, enabled := config.Severities[strings.ToLower(event.Severity)]; !enabled {
			continue
		}
		alertType := nsAlertClusterType(event)
		for _, recipient := range config.Recipients {
			eligible, err := shouldSendNSAlert(db, alertType, recipient, config.Cooldown)
			if err != nil {
				fmt.Printf("NS 告警读取去重状态失败 %s/%s: %v\n", event.ID, recipient, err)
				continue
			}
			if !eligible {
				continue
			}
			probe, hasProbe := probesByEvent[event.ID]
			subject, text := buildNSAlertMessage(event, probe, hasProbe, config.SubjectPrefix)
			ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
			accepted, err := config.Sender.SendNSAlert(ctx, []string{recipient}, subject, text)
			cancel()
			notification := nsAlertNotification{EventID: event.ID, AlertType: alertType, Recipient: recipient, AttemptedAt: time.Now().UTC()}
			if err != nil || accepted != 1 {
				notification.Status = "failed"
				if err != nil {
					notification.Message = err.Error()
				} else {
					notification.Message = fmt.Sprintf("relay 接受收件人数量 %d，期望 1", accepted)
				}
				failed++
			} else {
				notification.Status = "sent"
				notification.Message = "relay accepted"
				sent++
			}
			if err := insertNSAlertNotifications(writer, []nsAlertNotification{notification}); err != nil {
				fmt.Printf("NS 告警写入投递记录失败 %s/%s: %v\n", event.ID, recipient, err)
			}
		}
	}
	return sent, failed
}

// nsAlertClusterType 将同一域名的同类线索折叠为一个冷却键。event_id 仍会写入
// 投递审计表，故不会损失逐事件追溯能力。
func nsAlertClusterType(event NSChangeEvent) string {
	changeTypes := append([]string(nil), event.ChangeTypes...)
	sort.Strings(changeTypes)
	key := strings.Join([]string{
		normalizeFQDN(event.Domain),
		strings.ToLower(strings.TrimSpace(event.Severity)),
		map[bool]string{true: "recovery", false: "active"}[event.Status == "resolved"],
		strings.TrimSpace(event.Summary),
		strings.Join(changeTypes, ","),
	}, "|")
	return "ns_cluster_" + shortHash(key)
}

func shouldSendNSAlert(db *sql.DB, alertType, recipient string, cooldown time.Duration) (bool, error) {
	var lastSent time.Time
	err := db.QueryRow(`SELECT attempted_at FROM ns_alert_notifications
		WHERE alert_type = ? AND recipient = ? AND status = 'sent'
		ORDER BY attempted_at DESC LIMIT 1`, alertType, recipient).Scan(&lastSent)
	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return time.Now().UTC().After(lastSent.Add(cooldown)), nil
}

func buildNSAlertMessage(event NSChangeEvent, probe NSProbeResult, hasProbe bool, prefix string) (string, string) {
	subject := fmt.Sprintf("%s %s %s", prefix, strings.ToUpper(event.Severity), event.Domain)
	intro := "检测到 DNS 递归缓存 NS 严重线索。"
	if event.Status == "resolved" {
		subject = fmt.Sprintf("%s 恢复 %s", prefix, event.Domain)
		intro = "DNS NS 风险事件已恢复，历史证据与处置记录继续保留。"
	}
	lines := []string{
		intro,
		"",
		"事件 ID: " + event.ID,
		"域名: " + event.Domain,
		"等级: " + event.Severity,
		"证据: " + event.Evidence,
		"状态: " + event.Status,
		"首次观测: " + event.FirstSeen.UTC().Format(time.RFC3339),
		"最近观测: " + event.LastSeen.UTC().Format(time.RFC3339),
		"变化: " + strings.Join(event.ChangeTypes, ", "),
		"摘要: " + event.Summary,
		"",
		"基线 NS: " + strings.Join(alertNSNames(event.Baseline.Nameservers), ", "),
		"当前 NS: " + strings.Join(alertNSNames(event.Current.Nameservers), ", "),
	}
	if hasProbe {
		lines = append(lines, "", "拨测结论: "+probe.Verdict, "拨测摘要: "+probe.Summary, fmt.Sprintf("拨测名称: %d/%d", probe.ProbedDomains, probe.DomainLimit))
	} else {
		lines = append(lines, "", "拨测结论: 本轮未形成可用拨测证据")
	}
	lines = append(lines, "", "说明：该邮件表示缓存观测线索；请结合权威委派、递归器日志和拨测明细进行人工处置。")
	return subject, strings.Join(lines, "\n")
}

func alertNSNames(hosts []NSHostObservation) []string {
	values := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if host.Name != "" {
			values = append(values, host.Name)
		}
	}
	sort.Strings(values)
	return values
}
