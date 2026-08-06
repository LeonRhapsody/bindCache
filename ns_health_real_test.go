package main

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

// REAL_CLICKHOUSE_DSN=clickhouse://... go test -run TestInspectRealNSHealthQuery -v
func TestInspectRealNSHealthQuery(t *testing.T) {
	dsn := os.Getenv("REAL_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("set REAL_CLICKHOUSE_DSN to inspect real NS health query performance")
	}
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var sortingKey, partitionKey string
	var rowsTotal, bytesTotal uint64
	if err := db.QueryRowContext(ctx, `SELECT sorting_key, partition_key, total_rows, total_bytes
		FROM system.tables WHERE database = currentDatabase() AND name = 'ns_domain_observations'`).Scan(&sortingKey, &partitionKey, &rowsTotal, &bytesTotal); err != nil {
		t.Fatal(err)
	}
	t.Logf("ns_domain_observations: sorting=%s partition=%s rows=%d bytes=%d", sortingKey, partitionKey, rowsTotal, bytesTotal)
	store := &nsPersistentStore{db: db}
	started := time.Now()
	dependency, err := store.loadNSDependencyState(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("dependency state: snapshot=%s zones=%d hosts=%d elapsed=%s", dependency.snapshot.ID, dependency.totalZones, len(dependency.hosts), time.Since(started))
	started = time.Now()
	states, err := loadNSADBEndpointStatesContext(ctx, db, dependency.snapshot.View, dependency.snapshot.CapturedAt)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fresh ADB states=%d elapsed=%s", len(states), time.Since(started))
}
