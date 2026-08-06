package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAppConfigMergesLegacyAndNSMonitorSettings(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config.json")
	content := `{
  "clickhouse_dsn": "clickhouse://default@example:19000/test",
  "web_port": "9999",
  "dump_monitor": {"directory":"/data/dumps","ledger_path":"/data/state/ledger.json","poll_interval":"15s","stability_window":"2m"},
  "probe": {"enabled":true,"backend":"relay","max_domains":8,"max_events_per_import":2},
  "alerts": {"enabled":true,"recipients":["security@example.com"]}
}`
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadAppConfig(filename)
	if err != nil {
		t.Fatal(err)
	}
	if config.Web.Port != "9999" || config.DumpMonitor.Directory != "/data/dumps" || config.DumpMonitor.LedgerPath != "/data/state/ledger.json" || !config.Probe.Enabled || config.Probe.MaxDomains != 8 || config.Probe.MaxEventsPerImport != 2 || !config.Alerts.Enabled || len(config.Alerts.Recipients) != 1 {
		t.Fatalf("配置合并异常: %#v", config)
	}
}

func TestCampaignConfigDefaultsOnAndAllowsExplicitDisable(t *testing.T) {
	missing, err := LoadAppConfig(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !missing.Campaign.Enabled || !missing.Campaign.HoldBaseline || missing.Campaign.MinDistinctZones != 10 {
		t.Fatalf("unexpected defaults: %#v", missing.Campaign)
	}
	directory := t.TempDir()
	filename := filepath.Join(directory, "config.json")
	if err := os.WriteFile(filename, []byte(`{"campaign":{"enabled":false,"hold_baseline":false,"min_distinct_zones":15,"max_snapshot_gap":"45m"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	configured, err := LoadAppConfig(filename)
	if err != nil {
		t.Fatal(err)
	}
	if configured.Campaign.Enabled || configured.Campaign.HoldBaseline || configured.Campaign.MinDistinctZones != 15 || configured.Campaign.MaxSnapshotGap != "45m" {
		t.Fatalf("explicit campaign config not honored: %#v", configured.Campaign)
	}
}
