package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// 离线名单 CSV 固定列：
// object_type,object,source,version,confidence,category,effective_at,expires_at,description
// 时间使用 RFC3339 或 YYYY-MM-DD；object_type 支持 ns、ip、asn。
type NSBlacklistEntry struct {
	ObjectType  string    `json:"objectType"`
	Object      string    `json:"object"`
	Source      string    `json:"source"`
	Version     string    `json:"version"`
	Confidence  string    `json:"confidence"`
	Category    string    `json:"category"`
	Effective   time.Time `json:"effective"`
	Expires     time.Time `json:"expires"`
	Description string    `json:"description"`
	File        string    `json:"file"`
}

type NSBlacklistSource struct {
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	UpdatedAt  time.Time `json:"updatedAt"`
	Entries    int       `json:"entries"`
	Confidence string    `json:"confidence"`
	State      string    `json:"state"`
	SHA256     string    `json:"sha256"`
	File       string    `json:"file"`
}

type NSBlacklistIndex struct {
	byNS    map[string][]NSBlacklistEntry
	byIP    map[string][]NSBlacklistEntry
	byASN   map[uint32][]NSBlacklistEntry
	Sources []NSBlacklistSource
}

func LoadNSBlacklistDirectory(config NSBlacklistRuntimeConfig, now time.Time) (*NSBlacklistIndex, error) {
	directory := strings.TrimSpace(config.Directory)
	if directory == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("黑名单目录不存在: %s", directory)
		}
		return nil, fmt.Errorf("读取黑名单目录 %s: %w", directory, err)
	}
	index := &NSBlacklistIndex{byNS: make(map[string][]NSBlacklistEntry), byIP: make(map[string][]NSBlacklistEntry), byASN: make(map[uint32][]NSBlacklistEntry)}
	total := 0
	for _, item := range entries {
		if item.IsDir() || strings.ToLower(filepath.Ext(item.Name())) != ".csv" {
			continue
		}
		path := filepath.Join(directory, item.Name())
		info, err := item.Info()
		if err != nil {
			return nil, err
		}
		if config.MaxFileBytes > 0 && info.Size() > config.MaxFileBytes {
			return nil, fmt.Errorf("黑名单文件 %s 超过大小限制 %d", item.Name(), config.MaxFileBytes)
		}
		source, parsed, err := loadNSBlacklistCSV(path, info.ModTime(), now)
		if err != nil {
			return nil, err
		}
		total += len(parsed)
		if config.MaxEntries > 0 && total > config.MaxEntries {
			return nil, fmt.Errorf("黑名单总条目超过限制 %d", config.MaxEntries)
		}
		for _, entry := range parsed {
			switch entry.ObjectType {
			case "ns":
				index.byNS[normalizeFQDN(entry.Object)] = append(index.byNS[normalizeFQDN(entry.Object)], entry)
			case "ip":
				index.byIP[entry.Object] = append(index.byIP[entry.Object], entry)
			case "asn":
				number, _ := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(entry.Object), "AS"), 10, 32)
				index.byASN[uint32(number)] = append(index.byASN[uint32(number)], entry)
			}
		}
		index.Sources = append(index.Sources, source)
	}
	return index, nil
}

func loadNSBlacklistCSV(path string, modifiedAt, now time.Time) (NSBlacklistSource, []NSBlacklistEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return NSBlacklistSource{}, nil, err
	}
	defer file.Close()
	hash := sha256.New()
	reader := csv.NewReader(io.TeeReader(file, hash))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return NSBlacklistSource{}, nil, fmt.Errorf("读取黑名单 %s 表头: %w", filepath.Base(path), err)
	}
	expected := []string{"object_type", "object", "source", "version", "confidence", "category", "effective_at", "expires_at", "description"}
	if len(header) != len(expected) {
		return NSBlacklistSource{}, nil, fmt.Errorf("黑名单 %s 表头列数错误", filepath.Base(path))
	}
	for index := range expected {
		if strings.TrimSpace(strings.ToLower(header[index])) != expected[index] {
			return NSBlacklistSource{}, nil, fmt.Errorf("黑名单 %s 第 %d 列应为 %s", filepath.Base(path), index+1, expected[index])
		}
	}
	result := make([]NSBlacklistEntry, 0)
	line := 1
	for {
		line++
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return NSBlacklistSource{}, nil, fmt.Errorf("黑名单 %s 第 %d 行: %w", filepath.Base(path), line, err)
		}
		if len(record) != len(expected) {
			return NSBlacklistSource{}, nil, fmt.Errorf("黑名单 %s 第 %d 行列数错误", filepath.Base(path), line)
		}
		entry, err := parseNSBlacklistRecord(record, filepath.Base(path))
		if err != nil {
			return NSBlacklistSource{}, nil, fmt.Errorf("黑名单 %s 第 %d 行: %w", filepath.Base(path), line, err)
		}
		result = append(result, entry)
	}
	source := NSBlacklistSource{UpdatedAt: modifiedAt.UTC(), Entries: len(result), SHA256: hex.EncodeToString(hash.Sum(nil)), File: filepath.Base(path), State: "current"}
	if len(result) > 0 {
		source.Name, source.Version, source.Confidence = result[0].Source, result[0].Version, result[0].Confidence
		for _, entry := range result {
			if !entry.Expires.IsZero() && !now.Before(entry.Expires) {
				source.State = "expired"
			}
		}
	}
	return source, result, nil
}

func parseNSBlacklistRecord(record []string, filename string) (NSBlacklistEntry, error) {
	entry := NSBlacklistEntry{
		ObjectType: strings.ToLower(strings.TrimSpace(record[0])), Object: strings.TrimSpace(record[1]),
		Source: strings.TrimSpace(record[2]), Version: strings.TrimSpace(record[3]), Confidence: strings.ToLower(strings.TrimSpace(record[4])),
		Category: strings.TrimSpace(record[5]), Description: strings.TrimSpace(record[8]), File: filename,
	}
	if entry.ObjectType != "ns" && entry.ObjectType != "ip" && entry.ObjectType != "asn" {
		return NSBlacklistEntry{}, fmt.Errorf("不支持 object_type=%q", entry.ObjectType)
	}
	if entry.Object == "" || entry.Source == "" || entry.Version == "" {
		return NSBlacklistEntry{}, fmt.Errorf("object、source、version 不能为空")
	}
	if entry.Confidence != "high" && entry.Confidence != "medium" && entry.Confidence != "low" {
		return NSBlacklistEntry{}, fmt.Errorf("confidence 仅支持 high/medium/low")
	}
	var err error
	if entry.Effective, err = parseBlacklistTime(record[6]); err != nil {
		return NSBlacklistEntry{}, fmt.Errorf("effective_at: %w", err)
	}
	if entry.Expires, err = parseBlacklistTime(record[7]); err != nil {
		return NSBlacklistEntry{}, fmt.Errorf("expires_at: %w", err)
	}
	switch entry.ObjectType {
	case "ip":
		address, err := netip.ParseAddr(entry.Object)
		if err != nil {
			return NSBlacklistEntry{}, fmt.Errorf("无效 IP %q", entry.Object)
		}
		entry.Object = address.String()
	case "asn":
		number, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(entry.Object), "AS"), 10, 32)
		if err != nil || number == 0 {
			return NSBlacklistEntry{}, fmt.Errorf("无效 ASN %q", entry.Object)
		}
		entry.Object = fmt.Sprintf("AS%d", number)
	case "ns":
		entry.Object = normalizeFQDN(entry.Object)
	}
	return entry, nil
}

func parseBlacklistTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("无效时间 %q", value)
}

func (index *NSBlacklistIndex) match(observation DomainNSObservation, now time.Time) []NSBlacklistEntry {
	if index == nil {
		return nil
	}
	seen := make(map[string]struct{})
	result := make([]NSBlacklistEntry, 0)
	add := func(entries []NSBlacklistEntry) {
		for _, entry := range entries {
			if now.Before(entry.Effective) || (!entry.Expires.IsZero() && !now.Before(entry.Expires)) {
				continue
			}
			key := entry.ObjectType + "\x00" + entry.Object + "\x00" + entry.Source + "\x00" + entry.Version
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, entry)
		}
	}
	for _, host := range observation.Nameservers {
		add(index.byNS[normalizeFQDN(host.Name)])
		for _, address := range host.Addresses {
			add(index.byIP[address.Address])
			if address.ASN > 0 {
				add(index.byASN[address.ASN])
			}
		}
	}
	return result
}
