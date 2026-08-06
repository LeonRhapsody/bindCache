export interface NSProviderDefinition {
  id: string
  label: string
  aliases: string[]
  matches: (owner: string) => boolean
}

function exact(...domains: string[]) {
  const values = new Set(domains)
  return (owner: string) => values.has(owner)
}

function pattern(expression: RegExp, ...domains: string[]) {
  const values = new Set(domains)
  return (owner: string) => values.has(owner) || expression.test(owner)
}

export const NS_PROVIDERS: NSProviderDefinition[] = [
  { id: 'aws-route53', label: 'AWS Route 53', aliases: ['aws', 'amazon', 'route53', '亚马逊云'], matches: pattern(/^awsdns-(?:cn-)?\d+\.(?:com|net|org|co\.uk)$/, 'amazonaws.com') },
  { id: 'tencent-dnspod', label: '腾讯云 DNSPod', aliases: ['dnspod', 'tencent', '腾讯dns', '腾讯云'], matches: pattern(/^dnsv\d+\.com$/, 'dnspod.net', 'dnspod.com') },
  { id: 'aliyun-dns', label: '阿里云 DNS', aliases: ['alidns', 'aliyun', '阿里dns', '阿里云'], matches: exact('alidns.com', 'alidns.net', 'aliyundns.com', 'aliyun-dns.com') },
  { id: 'huawei-cloud-dns', label: '华为云 DNS', aliases: ['huawei', 'huaweicloud', '华为dns', '华为云'], matches: pattern(/^huaweicloud-dns\.(?:com|net|org|cn)$/, 'huawei.com', 'huawei.cn') },
  { id: 'cloudflare-dns', label: 'Cloudflare DNS', aliases: ['cloudflare', 'cf dns'], matches: exact('cloudflare.com') },
  { id: 'azure-dns', label: 'Microsoft Azure DNS', aliases: ['azure', 'microsoft dns', '微软云'], matches: pattern(/^azure-dns(?:-\d+)?\.(?:com|net|org|info|cn)$/) },
  { id: 'google-cloud-dns', label: 'Google Cloud DNS', aliases: ['google dns', 'gcp dns', '谷歌云'], matches: exact('googledomains.com', 'google.com') },
  { id: 'godaddy-dns', label: 'GoDaddy DNS', aliases: ['godaddy', 'domaincontrol'], matches: exact('domaincontrol.com') },
  { id: 'ultradns', label: 'Vercara UltraDNS', aliases: ['ultradns', 'vercara'], matches: pattern(/^ultradns2?\.(?:com|net|org|biz|info|co\.uk)$/) },
  { id: 'zdns-cloud', label: 'ZDNS Cloud', aliases: ['zdns', 'zdnscloud'], matches: pattern(/^zdnscloud\.(?:com|net|biz|info)$/) },
  { id: 'cloudns', label: 'ClouDNS', aliases: ['cloudns'], matches: pattern(/^cloudns\.(?:net|com|org|uk)$/) },
  { id: 'akamai-edgedns', label: 'Akamai Edge DNS', aliases: ['akamai', 'akam', 'edgedns'], matches: exact('akam.net', 'akadns.net', 'akamaiedge.net') },
  { id: 'ns1', label: 'IBM NS1 Connect', aliases: ['ns1', 'nsone', 'ibm dns'], matches: exact('nsone.net') },
  { id: 'namecheap-dns', label: 'Namecheap DNS', aliases: ['namecheap', 'registrar-servers'], matches: exact('registrar-servers.com') },
  { id: 'baidu-cloud-dns', label: '百度智能云 DNS', aliases: ['baidu dns', '百度云', 'bdydns'], matches: exact('bdydns.cn') },
  { id: 'sfn-dns', label: 'SFN DNS', aliases: ['sfn', 'sfndns'], matches: exact('sfn.cn', 'sfndns.cn', 'sfndns.com') },
  { id: 'ename-dns', label: 'eName DNS', aliases: ['ename', '易名'], matches: exact('ename.net') },
  { id: 'xinnet-dns', label: '新网 DNS', aliases: ['xinnet', 'xincache', '新网'], matches: exact('xincache.com') },
]

export function normalizeNSOwner(owner: string) {
  return owner.trim().toLowerCase().replace(/\.+$/, '')
}

export function classifyNSProvider(owner: string) {
  const normalized = normalizeNSOwner(owner)
  return NS_PROVIDERS.find((provider) => provider.matches(normalized))
}

export function findNSProvider(query: string) {
  const normalized = query.trim().toLowerCase()
  return NS_PROVIDERS.find((provider) => provider.label.toLowerCase().includes(normalized)
    || provider.id.includes(normalized)
    || provider.aliases.some((alias) => alias.includes(normalized) || normalized.includes(alias)))
}
