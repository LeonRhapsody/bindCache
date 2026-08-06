import type { NsRecord } from './risk'

export interface NsDiffRow {
  key: string
  field: string
  oldValue: string
  newValue: string
  note: string
}

const UNKNOWN = '—'

function normalizeValues(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b))
}

function joined(values: string[]): string {
  const normalized = normalizeValues(values)
  return normalized.length ? normalized.join(', ') : UNKNOWN
}

function normalizedText(value: string): string {
  return value.trim() || '未知'
}

function recordMap(records: NsRecord[]): Map<string, NsRecord> {
  return new Map(records.map((record) => [record.host, record]))
}

export function nsRecordChanged(baseline: NsRecord[], current: NsRecord): boolean {
  const previous = recordMap(baseline).get(current.host)
  if (!previous) return true
  return joined(previous.ips) !== joined(current.ips)
    || normalizedText(previous.asn) !== normalizedText(current.asn)
    || normalizedText(previous.asnOrg) !== normalizedText(current.asnOrg)
    || normalizedText(previous.country) !== normalizedText(current.country)
}

export function buildNsDiffRows(baseline: NsRecord[], current: NsRecord[]): NsDiffRow[] {
  const rows: NsDiffRow[] = []
  const baselineByHost = recordMap(baseline)
  const currentByHost = recordMap(current)

  if (baseline.length !== current.length) {
    const delta = current.length - baseline.length
    rows.push({
      key: 'ns-count',
      field: 'NS 数量',
      oldValue: `${baseline.length} 台`,
      newValue: `${current.length} 台`,
      note: delta > 0
        ? `增加 ${delta} 台权威服务器`
        : `减少 ${Math.abs(delta)} 台权威服务器，冗余度可能下降`,
    })
  }

  const removedHosts = [...baselineByHost.keys()].filter((host) => !currentByHost.has(host)).sort()
  const addedHosts = [...currentByHost.keys()].filter((host) => !baselineByHost.has(host)).sort()
  if (removedHosts.length || addedHosts.length) {
    rows.push({
      key: 'ns-hosts',
      field: 'NS 主机集合',
      oldValue: removedHosts.length ? removedHosts.join(', ') : '无移除',
      newValue: addedHosts.length ? addedHosts.join(', ') : '无新增',
      note: removedHosts.length && addedHosts.length
        ? 'NS 主机发生替换'
        : removedHosts.length ? 'NS 主机被移除' : '新增 NS 主机',
    })
  }

  const commonHosts = [...currentByHost.keys()].filter((host) => baselineByHost.has(host)).sort()
  for (const host of commonHosts) {
    const previous = baselineByHost.get(host)!
    const next = currentByHost.get(host)!
    const oldIPs = joined(previous.ips)
    const newIPs = joined(next.ips)
    if (oldIPs !== newIPs) {
      rows.push({
        key: `ip:${host}`,
        field: `NS IP · ${host}`,
        oldValue: oldIPs,
        newValue: newIPs,
        note: '该 NS 的 A/AAAA 地址集合发生变化',
      })
    }

    const oldASN = `${normalizedText(previous.asn)} (${normalizedText(previous.asnOrg)})`
    const newASN = `${normalizedText(next.asn)} (${normalizedText(next.asnOrg)})`
    if (oldASN !== newASN) {
      rows.push({
        key: `asn:${host}`,
        field: `ASN · ${host}`,
        oldValue: oldASN,
        newValue: newASN,
        note: '该 NS 的托管网络归属发生变化',
      })
    }

    const oldCountry = normalizedText(previous.country)
    const newCountry = normalizedText(next.country)
    if (oldCountry !== newCountry) {
      rows.push({
        key: `country:${host}`,
        field: `国家/地区 · ${host}`,
        oldValue: oldCountry,
        newValue: newCountry,
        note: 'GeoLite 离线库在事件两侧的归属结果不同',
      })
    }
  }

  return rows
}

const CHANGE_FIELD_LABELS: Record<string, string> = {
  ns_added: '新增 NS',
  ns_removed: '移除 NS',
  ns_count_changed: 'NS 数量变化',
  ns_owner_changed: 'NS 主域变化',
  ns_ip_changed: 'NS IP 变化',
  ns_address_family_reduced: 'NS 地址族减少',
  ns_network_changed: 'ASN/国家变化',
  network_metadata_unknown: '网络归属未知',
  reserved_ns_ip: 'NS 指向保留/私网地址',
}

export function formatChangeField(value: string): string {
  return CHANGE_FIELD_LABELS[value] ?? value
}
