import { useEffect, useMemo, useRef, useState } from 'react'
import { Focus, Maximize2, Search } from 'lucide-react'
import type { NSOwnershipEdgeStatus, NSOwnershipResponse } from '@/domain/risk'
import { classifyNSProvider, findNSProvider, NS_PROVIDERS, normalizeNSOwner } from '@/domain/nsProvider'

type GraphFilter = 'all' | 'changed' | 'cross'
type GraphMode = 'provider' | 'owner'
type NodeKind = 'provider' | 'owner' | 'zone'
type GraphStatus = NSOwnershipEdgeStatus | 'internal'

interface GraphNode {
  id: string
  label: string
  kind: NodeKind
  status: GraphStatus
  crossDomain: boolean
  degree: number
  owner?: string
  providerID?: string
  x: number
  y: number
  vx: number
  vy: number
}

interface GraphEdge {
  id: string
  source: string
  target: string
  status: GraphStatus
}

const STATUS_COLOR: Record<GraphStatus, string> = {
  added: '#34d399',
  removed: '#f87171',
  moved_in: '#fbbf24',
  moved_out: '#fb923c',
  internal: '#38bdf8',
  unchanged: '#cbd5e1',
}

const STATUS_LABEL: Record<GraphStatus, string> = {
  added: '新增观测', removed: '不再观测', moved_in: '迁入', moved_out: '迁出', internal: '服务商内部 NS 调整', unchanged: '未变化',
}

function hashFraction(value: string) {
  let hash = 2166136261
  for (let index = 0; index < value.length; index++) {
    hash ^= value.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return (hash >>> 0) / 4294967295
}

function relationStatus(value: string, previous: string[], current: string[]): NSOwnershipEdgeStatus {
  const was = previous.includes(value)
  const is = current.includes(value)
  if (was && is) return 'unchanged'
  if (is) return previous.length > 0 ? 'moved_in' : 'added'
  return current.length > 0 ? 'moved_out' : 'removed'
}

function providerKey(owner: string) {
  const provider = classifyNSProvider(owner)
  return provider ? `provider:${provider.id}` : `owner:${normalizeNSOwner(owner)}`
}

function statusPriority(status: GraphStatus) {
  return { unchanged: 0, internal: 1, added: 2, removed: 2, moved_in: 3, moved_out: 3 }[status]
}

function buildGraph(data: NSOwnershipResponse, filter: GraphFilter, mode: GraphMode, expandedProviders: Set<string>) {
  const globalEdges = data.graph_edges?.length > 0 ? data.graph_edges : data.edges
  const byZone = new Map(globalEdges.map((edge) => [edge.zone, edge]))
  for (const edge of data.edges.slice(0, 100)) byZone.set(edge.zone, edge)
  const nodeMap = new Map<string, GraphNode>()
  const graphEdges: GraphEdge[] = []
  const edgeIDs = new Set<string>()

  function addEdge(edge: GraphEdge) {
    if (edgeIDs.has(edge.id)) return
    edgeIDs.add(edge.id)
    graphEdges.push(edge)
  }

  function ensureNode(id: string, label: string, kind: NodeKind, status: GraphStatus, crossDomain: boolean, owner?: string, providerID?: string) {
    const existing = nodeMap.get(id)
    if (existing) {
      if (statusPriority(status) > statusPriority(existing.status)) existing.status = status
      existing.crossDomain ||= crossDomain
      return existing
    }
    const angle = hashFraction(id) * Math.PI * 2
    const radius = kind === 'provider' ? 100 : kind === 'owner' ? 180 : 300 + hashFraction(id + ':radius') * 150
    const node: GraphNode = { id, label, kind, status, crossDomain, degree: 0, owner, providerID, x: Math.cos(angle) * radius, y: Math.sin(angle) * radius, vx: 0, vy: 0 }
    nodeMap.set(id, node)
    return node
  }

  for (const edge of byZone.values()) {
    const previousOwners = Array.from(new Set(edge.previous_owners.map(normalizeNSOwner))).sort()
    const currentOwners = Array.from(new Set(edge.current_owners.map(normalizeNSOwner))).sort()
    const previousGroups = Array.from(new Set(previousOwners.map(providerKey)))
    const currentGroups = Array.from(new Set(currentOwners.map(providerKey)))
    const crossDomain = mode === 'provider' ? currentGroups.length > 1 : edge.cross_domain
    const ownerChanged = edge.status !== 'unchanged' || previousOwners.join('|') !== currentOwners.join('|')
    if (filter === 'cross' && !crossDomain) continue
    if (filter === 'changed' && !ownerChanged) continue

    const zoneID = `zone:${edge.zone}`
    ensureNode(zoneID, edge.zone, 'zone', edge.status, crossDomain)
    if (mode === 'owner') {
      for (const owner of Array.from(new Set([...previousOwners, ...currentOwners]))) {
        const status = relationStatus(owner, previousOwners, currentOwners)
        ensureNode(`owner:${owner}`, owner, 'owner', status, false, owner)
        addEdge({ id: `${owner}|${edge.zone}`, source: `owner:${owner}`, target: zoneID, status })
      }
      continue
    }

    for (const groupID of Array.from(new Set([...previousGroups, ...currentGroups]))) {
      const providerID = groupID.startsWith('provider:') ? groupID.slice('provider:'.length) : undefined
      const provider = providerID ? NS_PROVIDERS.find((item) => item.id === providerID) : undefined
      const previousGroupOwners = previousOwners.filter((owner) => providerKey(owner) === groupID)
      const currentGroupOwners = currentOwners.filter((owner) => providerKey(owner) === groupID)
      let status: GraphStatus = relationStatus(groupID, previousGroups, currentGroups)
      if (status === 'unchanged' && previousGroupOwners.join('|') !== currentGroupOwners.join('|')) status = 'internal'
      ensureNode(zoneID, edge.zone, 'zone', status, crossDomain)
      if (!provider) {
        const owner = groupID.slice('owner:'.length)
        ensureNode(groupID, owner, 'owner', status, false, owner)
        addEdge({ id: `${groupID}|${edge.zone}`, source: groupID, target: zoneID, status })
        continue
      }

      ensureNode(groupID, provider.label, 'provider', status, false, undefined, provider.id)
      if (!expandedProviders.has(provider.id)) {
        addEdge({ id: `${groupID}|${edge.zone}`, source: groupID, target: zoneID, status })
        continue
      }
      for (const owner of Array.from(new Set([...previousGroupOwners, ...currentGroupOwners]))) {
        const ownerID = `owner:${owner}`
        const ownerStatus = relationStatus(owner, previousOwners, currentOwners)
        ensureNode(ownerID, owner, 'owner', ownerStatus, false, owner, provider.id)
        addEdge({ id: `${groupID}|${ownerID}`, source: groupID, target: ownerID, status: 'unchanged' })
        addEdge({ id: `${ownerID}|${edge.zone}`, source: ownerID, target: zoneID, status: ownerStatus })
      }
    }
  }

  for (const edge of graphEdges) {
    const source = nodeMap.get(edge.source)
    const target = nodeMap.get(edge.target)
    if (source) source.degree++
    if (target) target.degree++
  }
  const selectedOwnerID = mode === 'provider' ? providerKey(data.selected_owner) : `owner:${normalizeNSOwner(data.selected_owner)}`
  const selected = nodeMap.get(selectedOwnerID)
  if (selected) selected.x = selected.y = 0
  return { nodes: Array.from(nodeMap.values()), edges: graphEdges, centerID: selectedOwnerID }
}

function nodeRadius(node: GraphNode) {
  const scale = Math.min(8, Math.log2(node.degree + 1) * 1.8)
  return (node.kind === 'provider' ? 11 : node.kind === 'owner' ? 7 : 4) + scale
}

export function NSOwnershipGraph({ data, onOwner, onSearch }: { data: NSOwnershipResponse; onOwner: (owner: string) => void; onSearch: (query: string) => void }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const graphRef = useRef<{ nodes: GraphNode[]; edges: GraphEdge[]; centerID: string }>({ nodes: [], edges: [], centerID: '' })
  const viewRef = useRef({ zoom: 0.7, panX: 0, panY: 0 })
  const selectedRef = useRef('')
  const hoveredRef = useRef('')
  const animationRef = useRef(0)
  const redrawRef = useRef<() => void>(() => undefined)
  const pendingFocusRef = useRef('')
  const pendingLabelRef = useRef('')
  const [mode, setMode] = useState<GraphMode>('provider')
  const [filter, setFilter] = useState<GraphFilter>('changed')
  const [search, setSearch] = useState('')
  const [selectedID, setSelectedID] = useState('')
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(() => new Set())
  const graph = useMemo(() => buildGraph(data, filter, mode, expandedProviders), [data, expandedProviders, filter, mode])
  const observedProviders = useMemo(() => NS_PROVIDERS.filter((provider) => data.owners.some((owner) => classifyNSProvider(owner.owner)?.id === provider.id)), [data.owners])
  const suggestions = useMemo(() => Array.from(new Set([
    ...graph.nodes.map((node) => node.label),
    ...data.owners.map((owner) => owner.owner),
    ...observedProviders.flatMap((provider) => [provider.label, ...provider.aliases]),
  ])).sort(), [data.owners, graph.nodes, observedProviders])

  useEffect(() => {
    graphRef.current = graph
    const canvas = canvasRef.current
    const container = containerRef.current
    if (!canvas || !container) return
    const context = canvas.getContext('2d')
    if (!context) return
    let width = 0
    let height = 0
    let frame = 0
    let draggingNode: GraphNode | null = null
    let panning = false
    let lastX = 0
    let lastY = 0
    let didMove = false

    const resize = () => {
      const rect = container.getBoundingClientRect()
      const ratio = window.devicePixelRatio || 1
      width = Math.max(320, rect.width)
      height = Math.max(460, rect.height)
      canvas.width = Math.round(width * ratio)
      canvas.height = Math.round(height * ratio)
      canvas.style.width = `${width}px`
      canvas.style.height = `${height}px`
      context.setTransform(ratio, 0, 0, ratio, 0, 0)
    }

    const screenPoint = (node: GraphNode) => ({ x: width / 2 + viewRef.current.panX + node.x * viewRef.current.zoom, y: height / 2 + viewRef.current.panY + node.y * viewRef.current.zoom })
    const worldPoint = (x: number, y: number) => ({ x: (x - width / 2 - viewRef.current.panX) / viewRef.current.zoom, y: (y - height / 2 - viewRef.current.panY) / viewRef.current.zoom })
    const hitNode = (x: number, y: number) => {
      for (let index = graph.nodes.length - 1; index >= 0; index--) {
        const node = graph.nodes[index]
        const point = screenPoint(node)
        if (Math.hypot(point.x - x, point.y - y) <= nodeRadius(node) + 5) return node
      }
      return null
    }

    const draw = () => {
      context.clearRect(0, 0, width, height)
      const byID = new Map(graph.nodes.map((node) => [node.id, node]))
      const selected = selectedRef.current
      const neighborIDs = new Set<string>()
      if (selected) for (const edge of graph.edges) {
        if (edge.source === selected) neighborIDs.add(edge.target)
        if (edge.target === selected) neighborIDs.add(edge.source)
      }
      for (const edge of graph.edges) {
        const source = byID.get(edge.source)
        const target = byID.get(edge.target)
        if (!source || !target) continue
        const a = screenPoint(source)
        const b = screenPoint(target)
        const emphasized = !selected || edge.source === selected || edge.target === selected
        context.globalAlpha = selected ? (emphasized ? (edge.status === 'unchanged' ? 0.24 : 0.78) : 0.035) : (edge.status === 'unchanged' ? 0.07 : 0.3)
        context.strokeStyle = STATUS_COLOR[edge.status]
        context.lineWidth = emphasized && edge.status !== 'unchanged' ? 1.5 : 1
        context.beginPath()
        context.moveTo(a.x, a.y)
        context.lineTo(b.x, b.y)
        context.stroke()
      }
      context.globalAlpha = 1
      for (const node of graph.nodes) {
        const point = screenPoint(node)
        if (point.x < -40 || point.y < -40 || point.x > width + 40 || point.y > height + 40) continue
        const active = node.id === selected || neighborIDs.has(node.id)
        const muted = Boolean(selected) && !active
        const radius = nodeRadius(node)
        context.globalAlpha = muted ? 0.14 : 1
        context.fillStyle = node.crossDomain ? '#8b5cf6' : node.kind === 'provider' ? '#0e7490' : node.kind === 'owner' ? '#06b6d4' : STATUS_COLOR[node.status]
        context.beginPath()
        context.arc(point.x, point.y, radius, 0, Math.PI * 2)
        context.fill()
        if (node.id === selected || node.id === hoveredRef.current || (node.kind !== 'zone' && (node.degree >= 5 || node.kind === 'provider') && viewRef.current.zoom > 0.65)) {
          context.font = `${node.id === selected ? '600' : '500'} 11px ui-monospace, SFMono-Regular, Menlo, monospace`
          context.fillStyle = '#44403c'
          context.globalAlpha = muted ? 0.2 : 1
          context.fillText(node.label, point.x + radius + 5, point.y + 4)
        }
      }
      context.globalAlpha = 1
    }
    redrawRef.current = draw

    const simulate = () => {
      frame++
      const nodes = graph.nodes
      const byID = new Map(nodes.map((node) => [node.id, node]))
      for (let left = 0; left < nodes.length; left++) {
        for (let right = left + 1; right < nodes.length; right++) {
          const a = nodes[left]
          const b = nodes[right]
          const dx = b.x - a.x || 0.1
          const dy = b.y - a.y || 0.1
          const distanceSquared = Math.max(100, dx * dx + dy * dy)
          const hubs = a.kind !== 'zone' && b.kind !== 'zone'
          const force = (hubs ? 300 : 40) / distanceSquared
          a.vx -= dx * force
          a.vy -= dy * force
          b.vx += dx * force
          b.vy += dy * force
        }
      }
      for (const edge of graph.edges) {
        const source = byID.get(edge.source)
        const target = byID.get(edge.target)
        if (!source || !target) continue
        const dx = target.x - source.x
        const dy = target.y - source.y
        const distance = Math.max(1, Math.hypot(dx, dy))
        const desired = edge.source === graph.centerID ? 165 : source.kind === 'provider' && target.kind === 'owner' ? 70 : 105
        const force = (distance - desired) * 0.0045
        source.vx += dx / distance * force
        source.vy += dy / distance * force
        target.vx -= dx / distance * force
        target.vy -= dy / distance * force
      }
      for (const node of nodes) {
        if (node.id === graph.centerID) {
          node.x = 0
          node.y = 0
          node.vx = 0
          node.vy = 0
          continue
        }
        node.vx += -node.x * 0.0008
        node.vy += -node.y * 0.0008
        node.vx *= 0.82
        node.vy *= 0.82
        const speed = Math.hypot(node.vx, node.vy)
        if (speed > 8) {
          node.vx = node.vx / speed * 8
          node.vy = node.vy / speed * 8
        }
        if (node !== draggingNode) {
          node.x += node.vx
          node.y += node.vy
        }
      }
      draw()
      if (frame < 180 || draggingNode || panning) animationRef.current = requestAnimationFrame(simulate)
    }

    const pointer = (event: MouseEvent) => {
      const rect = canvas.getBoundingClientRect()
      return { x: event.clientX - rect.left, y: event.clientY - rect.top }
    }
    const onDown = (event: MouseEvent) => {
      const point = pointer(event)
      draggingNode = hitNode(point.x, point.y)
      panning = !draggingNode
      lastX = point.x
      lastY = point.y
      didMove = false
      canvas.style.cursor = draggingNode ? 'grabbing' : 'move'
      cancelAnimationFrame(animationRef.current)
      animationRef.current = requestAnimationFrame(simulate)
    }
    const onMove = (event: MouseEvent) => {
      const point = pointer(event)
      if (draggingNode) {
        const world = worldPoint(point.x, point.y)
        draggingNode.x = world.x
        draggingNode.y = world.y
        draggingNode.vx = draggingNode.vy = 0
      } else if (panning) {
        viewRef.current.panX += point.x - lastX
        viewRef.current.panY += point.y - lastY
      } else {
        const hovered = hitNode(point.x, point.y)?.id ?? ''
        if (hovered !== hoveredRef.current) {
          hoveredRef.current = hovered
          canvas.style.cursor = hovered ? 'pointer' : 'grab'
          draw()
        }
      }
      if ((draggingNode || panning) && Math.hypot(point.x - lastX, point.y - lastY) > 2) didMove = true
      lastX = point.x
      lastY = point.y
    }
    const onUp = (event: MouseEvent) => {
      const point = pointer(event)
      const hit = hitNode(point.x, point.y)
      if (hit && !didMove) {
        selectedRef.current = hit.id
        setSelectedID(hit.id)
        if (hit.kind === 'provider' && hit.providerID) {
          setExpandedProviders((current) => {
            const next = new Set(current)
            if (next.has(hit.providerID!)) next.delete(hit.providerID!)
            else next.add(hit.providerID!)
            return next
          })
          pendingFocusRef.current = hit.id
        } else if (hit.kind === 'owner' && hit.owner && hit.owner !== normalizeNSOwner(data.selected_owner)) {
          pendingFocusRef.current = hit.id
          onOwner(hit.owner)
        }
      }
      draggingNode = null
      panning = false
      canvas.style.cursor = 'grab'
      draw()
    }
    const onWheel = (event: WheelEvent) => {
      event.preventDefault()
      const point = pointer(event)
      const before = worldPoint(point.x, point.y)
      viewRef.current.zoom = Math.min(3.5, Math.max(0.25, viewRef.current.zoom * Math.exp(-event.deltaY * 0.001)))
      const after = worldPoint(point.x, point.y)
      viewRef.current.panX += (after.x - before.x) * viewRef.current.zoom
      viewRef.current.panY += (after.y - before.y) * viewRef.current.zoom
      draw()
    }
    const observer = new ResizeObserver(resize)
    observer.observe(container)
    resize()
    canvas.addEventListener('mousedown', onDown)
    canvas.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
    canvas.addEventListener('wheel', onWheel, { passive: false })
    cancelAnimationFrame(animationRef.current)
    animationRef.current = requestAnimationFrame(simulate)
    const focusPendingNode = (node: GraphNode) => requestAnimationFrame(() => {
      pendingFocusRef.current = ''
      pendingLabelRef.current = ''
      selectedRef.current = node.id
      setSelectedID(node.id)
      viewRef.current.zoom = 1.15
      viewRef.current.panX = node.id === graph.centerID ? 0 : -node.x * viewRef.current.zoom
      viewRef.current.panY = node.id === graph.centerID ? 0 : -node.y * viewRef.current.zoom
      draw()
    })
    if (pendingFocusRef.current) {
      const pending = graph.nodes.find((node) => node.id === pendingFocusRef.current)
      if (pending) focusPendingNode(pending)
    }
    if (pendingLabelRef.current) {
      const wanted = pendingLabelRef.current
      const pending = graph.nodes.find((node) => node.label.toLowerCase() === wanted)
        ?? graph.nodes.find((node) => node.label.toLowerCase().includes(wanted))
      if (pending) focusPendingNode(pending)
    }
    return () => {
      cancelAnimationFrame(animationRef.current)
      observer.disconnect()
      canvas.removeEventListener('mousedown', onDown)
      canvas.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
      canvas.removeEventListener('wheel', onWheel)
      redrawRef.current = () => undefined
    }
  }, [data.selected_owner, graph, onOwner])

  function focusGraphNode(node: GraphNode) {
    selectedRef.current = node.id
    setSelectedID(node.id)
    viewRef.current.zoom = Math.max(1.15, viewRef.current.zoom)
    viewRef.current.panX = -node.x * viewRef.current.zoom
    viewRef.current.panY = -node.y * viewRef.current.zoom
    redrawRef.current()
  }

  function focusNode() {
    const value = search.trim().toLowerCase()
    if (!value) return
    const node = graphRef.current.nodes.find((item) => item.label.toLowerCase() === value)
      ?? graphRef.current.nodes.find((item) => item.label.toLowerCase().includes(value))
    if (node) {
      if (node.kind === 'owner' && node.owner && node.owner !== normalizeNSOwner(data.selected_owner)) {
        pendingFocusRef.current = node.id
        onOwner(node.owner)
      } else focusGraphNode(node)
      return
    }

    const owner = data.owners.find((item) => item.owner.toLowerCase() === value)
      ?? data.owners.find((item) => item.owner.toLowerCase().includes(value))
    if (owner) {
      const ownerProvider = classifyNSProvider(owner.owner)
      if (mode === 'provider' && ownerProvider) {
        setExpandedProviders((current) => new Set(current).add(ownerProvider.id))
        pendingFocusRef.current = `owner:${normalizeNSOwner(owner.owner)}`
      } else pendingFocusRef.current = `owner:${normalizeNSOwner(owner.owner)}`
      setFilter('all')
      onOwner(owner.owner)
    } else {
      const provider = findNSProvider(value)
      if (provider && data.owners.some((item) => classifyNSProvider(item.owner)?.id === provider.id)) {
        pendingFocusRef.current = `provider:${provider.id}`
        const representative = data.owners.find((item) => classifyNSProvider(item.owner)?.id === provider.id)
        setFilter('all')
        if (representative) onSearch(representative.owner)
      } else {
        pendingLabelRef.current = value
        setFilter('all')
        onSearch(value)
      }
    }
  }

  function resetView() {
    viewRef.current = { zoom: 0.7, panX: 0, panY: 0 }
    selectedRef.current = ''
    setSelectedID('')
    redrawRef.current()
  }

  function switchMode(nextMode: GraphMode) {
    setMode(nextMode)
    setExpandedProviders(new Set())
    selectedRef.current = ''
    setSelectedID('')
    viewRef.current = { zoom: 0.7, panX: 0, panY: 0 }
  }

  const selected = graph.nodes.find((node) => node.id === selectedID)
  const related = selected ? graph.edges.filter((edge) => edge.source === selected.id || edge.target === selected.id).length : 0
  const providerCount = graph.nodes.filter((node) => node.kind === 'provider').length

  return <div className="space-y-2">
    <div className="flex flex-wrap items-center gap-2">
      <label className="relative min-w-[260px] flex-1"><Search size={13} className="absolute left-2.5 top-2.5 text-stone-400"/><input list="ns-ownership-graph-search" value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') focusNode() }} placeholder="搜索服务商、NS 主域或 zone" className="h-8 w-full rounded-md border border-stone-200 pl-8 pr-2 text-[11px] outline-none focus:border-cyan-500"/><datalist id="ns-ownership-graph-search">{suggestions.slice(0, 600).map((value) => <option key={value} value={value}/>)}</datalist></label>
      <button onClick={focusNode} className="inline-flex h-8 items-center gap-1 rounded-md border border-stone-200 px-2.5 text-[11px] text-stone-600 hover:bg-stone-50"><Focus size={13}/>定位</button>
      <div className="inline-flex rounded-md border border-stone-200 p-0.5">{([['provider', '服务商聚合'], ['owner', 'NS 主域']] as const).map(([value, label]) => <button key={value} onClick={() => switchMode(value)} className={`rounded px-2.5 py-1 text-[11px] ${mode === value ? 'bg-cyan-700 text-white' : 'text-stone-500 hover:bg-stone-50'}`}>{label}</button>)}</div>
      <div className="inline-flex rounded-md border border-stone-200 p-0.5">{([['all', '全部'], ['changed', '仅变化'], ['cross', mode === 'provider' ? '跨服务商' : '跨主域']] as const).map(([value, label]) => <button key={value} onClick={() => { selectedRef.current = ''; setSelectedID(''); setFilter(value) }} className={`rounded px-2.5 py-1 text-[11px] ${filter === value ? 'bg-cyan-700 text-white' : 'text-stone-500 hover:bg-stone-50'}`}>{label}</button>)}</div>
      <button onClick={resetView} className="inline-flex h-8 items-center gap-1 rounded-md border border-stone-200 px-2.5 text-[11px] text-stone-600 hover:bg-stone-50"><Maximize2 size={13}/>复位</button>
    </div>
    <div ref={containerRef} className="relative h-[610px] overflow-hidden rounded-md border border-stone-200 bg-[radial-gradient(circle_at_center,_#fafafa_0,_#f5f5f4_70%)]">
      <canvas ref={canvasRef} role="img" aria-label={`NS 归属关系图，共 ${graph.nodes.length} 个节点、${graph.edges.length} 条关系；可拖拽、缩放并点击节点聚焦`} className="block cursor-grab"/>
      <div className="pointer-events-none absolute bottom-2 left-2 flex flex-wrap gap-2 rounded bg-white/90 px-2 py-1 text-[10px] text-stone-500 shadow-sm">
        {mode === 'provider' && <span><i className="mr-1 inline-block h-2.5 w-2.5 rounded-full bg-cyan-700"/>DNS 服务商</span>}<span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-cyan-500"/>NS 主域</span><span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-violet-500"/>{mode === 'provider' ? '跨服务商 zone' : '跨主域 zone'}</span>{Object.entries(STATUS_LABEL).map(([status, label]) => <span key={status}><i className="mr-1 inline-block h-0.5 w-3 align-middle" style={{ background: STATUS_COLOR[status as GraphStatus] }}/>{label}</span>)}
      </div>
    </div>
    <div className="min-h-5 text-[11px] text-stone-500">{selected ? <><span className="font-medium text-stone-700">{selected.label}</span> · {selected.kind === 'provider' ? `DNS 服务商（点击${expandedProviders.has(selected.providerID ?? '') ? '折叠' : '展开'} NS 主域）` : selected.kind === 'owner' ? 'NS 主域' : selected.crossDomain ? (mode === 'provider' ? '跨服务商 zone' : '跨主域 zone') : 'zone'} · {related} 条关系 · {STATUS_LABEL[selected.status]}</> : <>{mode === 'provider' ? `当前识别 ${providerCount} 个服务商；点击服务商可展开其 NS 主域。` : '按原始 NS 主域展示。'} 拖拽空白处平移，滚轮缩放，点击节点聚焦一跳关系。</>}</div>
  </div>
}
