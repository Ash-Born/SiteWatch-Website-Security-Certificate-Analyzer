import { useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { Activity, CircleHelp, Check, X, Globe2, LockKeyhole, Network, Server, ShieldCheck, Wifi } from 'lucide-react'

const arr = value => Array.isArray(value) ? value : []
const text = value => value === null || value === undefined || value === '' ? 'Not observed' : typeof value === 'string' || typeof value === 'number' ? String(value) : JSON.stringify(value)
const STATUS_COLORS = { critical: '#ff5268', warning: '#ffad45', safe: '#48d597', unknown: '#77869a', target: '#35c8f4' }
const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 }

function strongestFinding(findings) {
  return [...findings].sort((a, b) => (severityRank[String(b.severity).toUpperCase()] || 0) - (severityRank[String(a.severity).toUpperCase()] || 0))[0]
}

function riskFromFindings(findings, observed, options = {}) {
  const severity = String(strongestFinding(findings)?.severity || '').toUpperCase()
  if (severity === 'CRITICAL' || severity === 'HIGH' || options.forceCritical) return 'critical'
  if (severity === 'MEDIUM' || severity === 'LOW' || findings.length || options.forceWarning) return 'warning'
  return observed ? 'safe' : 'unknown'
}

function findingMatches(findings, prefixes) {
  return findings.filter(item => prefixes.some(prefix => String(item.check_id || '').toLowerCase().startsWith(prefix)))
}

function buildLayers(report) {
  const checks = report?.checks || {}
  const dns = checks.dns || {}
  const tls = checks.tls || {}
  const http = checks.http || {}
  const findings = arr(report?.findings)
  const signals = arr(report?.compliance_signals || checks.compliance_signals)
  const dnsFindings = findingMatches(findings, ['dns.'])
  const tlsFindings = findingMatches(findings, ['tls.'])
  const httpFindings = findingMatches(findings, ['http.'])
  const complianceFindings = findingMatches(findings, ['compliance.'])
  const isHttpObserved = Number.isInteger(http.status_code) || Number.isInteger(http.http_status)
  const isDnsObserved = arr(dns.addresses).length > 0 || dns.dnssec_dnskey_observed !== undefined || dns.caa !== undefined || dns.spf !== undefined || dns.dmarc !== undefined
  const isTlsObserved = Boolean(tls.issuer || tls.not_after || arr(tls.supported_protocols).length || tls.chain_validated !== undefined || tls.revocation)
  const tlsUntrusted = tls.chain_validated === false && Boolean(tls.verification_error || tls.issuer)
    || tlsFindings.some(item => /untrusted|expired|revoked|self.signed/i.test(`${item.check_id} ${item.title}`))
  const tlsRisk = riskFromFindings(tlsFindings, isTlsObserved, { forceCritical: tlsUntrusted })
  const dnsRisk = riskFromFindings(dnsFindings, isDnsObserved)
  const missingCriticalHeaders = httpFindings.some(item => /no_hsts|no_csp|no_frame_protection/i.test(String(item.check_id)))
  const httpRisk = riskFromFindings(httpFindings, isHttpObserved, { forceCritical: missingCriticalHeaders })
  const missingSignals = signals.filter(signal => String(signal.status).toLowerCase() === 'missing')
  const unknownSignals = signals.length > 0 && signals.every(signal => String(signal.status).toLowerCase() === 'unknown')
  const complianceRisk = unknownSignals ? 'unknown' : riskFromFindings(complianceFindings, signals.length > 0, { forceWarning: missingSignals.length > 0, forceCritical: complianceFindings.some(f => ['CRITICAL', 'HIGH'].includes(String(f.severity).toUpperCase())) })
  const complianceStatus = signals.length ? `${signals.filter(signal => signal.status === 'detected').length}/${signals.length} detected` : 'No compliance observations'

  const headerSpecs = [
    { name: 'Strict-Transport-Security', finding: 'http.no_hsts', critical: true },
    { name: 'Content-Security-Policy', finding: 'http.no_csp', critical: true },
    { name: 'Frame protection', finding: 'http.no_frame_protection', critical: true, alternatives: ['x-frame-options', 'content-security-policy'] },
    { name: 'X-Content-Type-Options', finding: 'http.no_nosniff' },
    { name: 'Referrer-Policy', finding: 'http.no_referrer_policy' },
    { name: 'Permissions-Policy', finding: 'http.no_permissions_policy' },
  ]
  const responseHeaders = Object.fromEntries(Object.entries(http.headers || {}).map(([key, value]) => [key.toLowerCase(), value]))
  const headerRows = headerSpecs.map(spec => {
    const key = spec.name.toLowerCase()
    const found = spec.alternatives ? spec.alternatives.some(alternative => responseHeaders[alternative]) : Boolean(responseHeaders[key])
    const finding = httpFindings.find(item => String(item.check_id) === spec.finding)
    const status = found ? 'present' : finding ? 'missing' : 'unknown'
    return { name: spec.name, value: found ? (spec.alternatives ? 'Observed' : text(responseHeaders[key])) : status === 'missing' ? 'Missing' : 'Not evaluated' , status, critical: Boolean(spec.critical) }
  })
  const dnsRows = [
    { name: 'Resolved IPs', value: arr(dns.addresses).join(', ') || 'Not observed', status: arr(dns.addresses).length ? 'present' : 'unknown' },
    { name: 'CAA records', value: arr(dns.caa).join('; ') || (dns.caa === undefined ? 'Not observed' : 'No records observed'), status: arr(dns.caa).length ? 'present' : dns.caa === undefined ? 'unknown' : 'missing' },
    { name: 'DNSSEC DNSKEY', value: dns.dnssec_dnskey_observed === undefined ? 'Not observed' : dns.dnssec_dnskey_observed ? 'Observed' : 'Not observed', status: dns.dnssec_dnskey_observed === undefined ? 'unknown' : dns.dnssec_dnskey_observed ? 'present' : 'missing' },
    { name: 'DNSSEC AD bit', value: dns.dnssec_ad_bit === undefined ? 'Not observed' : dns.dnssec_ad_bit ? 'Authenticated' : 'Not authenticated', status: dns.dnssec_ad_bit === undefined ? 'unknown' : dns.dnssec_ad_bit ? 'present' : 'missing' },
    { name: 'SPF', value: arr(dns.spf).join('; ') || (dns.spf === undefined ? 'Not observed' : 'No SPF record observed'), status: arr(dns.spf).length ? 'present' : dns.spf === undefined ? 'unknown' : 'missing' },
    { name: 'DMARC', value: arr(dns.dmarc).join('; ') || (dns.dmarc === undefined ? 'Not observed' : 'No DMARC record observed'), status: arr(dns.dmarc).length ? 'present' : dns.dmarc === undefined ? 'unknown' : 'missing' },
  ]
  const tlsRows = [
    { name: 'Issuer', value: text(tls.issuer), status: tls.issuer ? 'present' : 'unknown' },
    { name: 'Valid from', value: text(tls.not_before), status: tls.not_before ? 'present' : 'unknown' },
    { name: 'Valid to', value: text(tls.not_after), status: tls.not_after ? 'present' : 'unknown' },
    { name: 'Days left', value: tls.days_until_expiry === undefined ? 'Not observed' : String(tls.days_until_expiry), status: tls.days_until_expiry === undefined ? 'unknown' : tls.days_until_expiry < 0 ? 'missing' : 'present' },
    { name: 'Supported protocols', value: arr(tls.supported_protocols).join(', ') || 'Not observed', status: arr(tls.supported_protocols).length ? 'present' : 'unknown' },
    { name: 'Revocation', value: text(tls.revocation?.status), status: tls.revocation?.status === 'revoked' ? 'missing' : tls.revocation?.status === 'good' ? 'present' : 'unknown' },
    { name: 'Chain validation', value: tls.chain_validated === undefined ? text(tls.status) : tls.chain_validated ? 'Trusted' : 'Not validated', status: tls.chain_validated === undefined ? 'unknown' : tls.chain_validated ? 'present' : 'missing' },
  ]
  const complianceItems = signals.map(signal => ({ name: signal.name, value: signal.evidence || 'No evidence returned', status: ['detected', 'missing', 'unknown'].includes(signal.status) ? signal.status : 'unknown' }))
  const rawPorts = report?.ports ?? report?.open_ports ?? checks.ports ?? checks.port_scan?.ports ?? report?.port_scan?.ports
  const ports = Array.isArray(rawPorts) ? rawPorts : Array.isArray(rawPorts?.open_ports) ? rawPorts.open_ports : null
  const portRows = ports?.map(item => ({ name: `Port ${item.port ?? 'unknown'}`, value: [item.protocol, item.service, item.banner].filter(Boolean).join(' · ') || text(item.status), status: item.status === 'open' ? 'present' : item.status === 'closed' ? 'missing' : 'unknown' })) || []
  const nodes = [
    { id: 'target', label: report?.target || 'Target', group: 'target', risk: 'target', status: 'Target', rows: [{ name: 'Assessment date', value: text(report?.observed_at), status: 'unknown' }, { name: 'Posture score', value: `${report?.score ?? 'Not scored'} · Grade ${report?.grade || 'Unknown'}`, status: 'unknown' }] },
    { id: 'dns', label: 'DNS', group: 'layer', risk: dnsRisk, status: dnsRisk, rows: dnsRows, findings: dnsFindings },
    { id: 'tls', label: 'TLS', group: 'layer', risk: tlsRisk, status: tlsRisk, rows: tlsRows, findings: tlsFindings },
    { id: 'http', label: 'HTTP', group: 'layer', risk: httpRisk, status: httpRisk, rows: [{ name: 'HTTP status', value: text(http.status_code ?? http.http_status), status: isHttpObserved ? 'present' : 'unknown' }, ...headerRows], findings: httpFindings },
    { id: 'compliance', label: 'Compliance', group: 'layer', risk: complianceRisk, status: complianceStatus, rows: complianceItems, findings: complianceFindings },
  ]
  if (ports) { const portFindings = findingMatches(findings, ['port.', 'ports.', 'service.']); nodes.push({ id: 'ports', label: 'Ports / Services', group: 'layer', risk: riskFromFindings(portFindings, true), status: `${ports.length} returned`, rows: portRows.length ? portRows : [{ name: 'Open ports', value: 'No open ports returned', status: 'present' }], findings: portFindings }) }
  return nodes
}

function DetailRows({ rows = [] }) {
  return <div className="attack-detail-list">{rows.length ? rows.map((row, index) => <div className={`attack-detail-row row-${row.status} ${row.critical ? 'row-critical' : ''}`} key={`${row.name}-${index}`}><div className="attack-detail-heading">{row.status === 'present' || row.status === 'detected' ? <Check/> : row.status === 'missing' ? <X/> : <CircleHelp/>}<strong>{row.name}</strong></div><p>{row.value}</p></div>) : <div className="attack-no-data">No data was returned for this layer.</div>}</div>
}

export default function AttackSurfaceGraph({ report }) {
  const graphRef = useRef(null)
  const containerRef = useRef(null)
  const [graphWidth, setGraphWidth] = useState(680)
  const nodes = useMemo(() => buildLayers(report), [report])
  const [selectedId, setSelectedId] = useState('target')
  const selected = nodes.find(node => node.id === selectedId) || nodes[0]
  useEffect(() => { setSelectedId('target'); const timer = window.setTimeout(() => graphRef.current?.zoomToFit(450, 70), 180); return () => window.clearTimeout(timer) }, [nodes])
  useEffect(() => { const element = containerRef.current; if (!element) return undefined; const observer = new ResizeObserver(entries => setGraphWidth(Math.max(280, Math.floor(entries[0].contentRect.width)))); observer.observe(element); return () => observer.disconnect() }, [])
  const graphData = useMemo(() => ({
    nodes: nodes.map((node, index) => ({ ...node, x: index === 0 ? 0 : Math.cos((index - 1) * 2 * Math.PI / (nodes.length - 1)) * 150, y: index === 0 ? 0 : Math.sin((index - 1) * 2 * Math.PI / (nodes.length - 1)) * 115 })),
    links: nodes.slice(1).map(node => ({ source: 'target', target: node.id, risk: node.risk })),
  }), [nodes])
  const color = node => STATUS_COLORS[node.risk] || STATUS_COLORS.unknown
  const selectedIcon = selected.id === 'target' ? <Globe2/> : selected.id === 'tls' ? <LockKeyhole/> : selected.id === 'dns' ? <Activity/> : selected.id === 'ports' ? <Server/> : selected.id === 'compliance' ? <ShieldCheck/> : <Wifi/>
  return <section className="attack-surface panel glass-panel">
    <div className="panel-title"><div><p className="eyebrow">PENETRATION TESTING VIEW</p><h2>Attack Surface Graph</h2></div><span className="muted"><Network size={14}/> Select a node to inspect evidence</span></div>
    <div className="attack-surface-body"><div className="attack-graph" ref={containerRef} role="application" aria-label="Interactive penetration testing attack surface graph"><div className="graph-grid-overlay"/><ForceGraph2D ref={graphRef} graphData={graphData} width={graphWidth} height={420} backgroundColor="rgba(0,0,0,0)" cooldownTicks={90} autoPauseRedraw={false} nodeRelSize={8} nodeVal={node => node.group === 'target' ? 19 : 11} nodeColor={color} linkColor={link => STATUS_COLORS[link.risk] || STATUS_COLORS.unknown} linkWidth={link => link.risk === 'critical' ? 2.5 : 1.6} linkDirectionalParticles={2} linkDirectionalParticleWidth={2.2} linkDirectionalParticleColor={link => STATUS_COLORS[link.risk] || STATUS_COLORS.unknown} onNodeClick={node => setSelectedId(node.id)} nodeCanvasObjectMode={() => 'replace'} nodeCanvasObject={(node, ctx, scale) => { const pulse = 1 + Math.sin(Date.now() / 350 + (node.index || 0)) * .12; const radius = (node.group === 'target' ? 12 : 9) * pulse; const nodeColor = color(node); ctx.beginPath(); ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI); ctx.fillStyle = nodeColor; ctx.shadowColor = nodeColor; ctx.shadowBlur = 16; ctx.fill(); ctx.shadowBlur = 0; ctx.lineWidth = node.id === selectedId ? 2 / scale : 1 / scale; ctx.strokeStyle = node.id === selectedId ? '#e6f7ff' : `${nodeColor}99`; ctx.stroke(); ctx.font = `600 ${12 / scale}px sans-serif`; ctx.textAlign = 'center'; ctx.textBaseline = 'top'; ctx.fillStyle = '#e4edf8'; ctx.fillText(node.label, node.x, node.y + radius + 6) }}/></div>
      <aside className="attack-node-details"><div className="attack-detail-top"><div className="attack-node-icon" style={{ '--node-color': color(selected) }}>{selectedIcon}</div><span className={`attack-status risk-${selected.risk}`}>{selected.status}</span></div><h3>{selected.label}</h3><p className="muted">Evidence and checks returned by this assessment</p><DetailRows rows={selected.rows}/>{selected.findings?.length > 0 && <div className="attack-finding-list"><h4>Findings</h4>{selected.findings.map((finding, index) => <article key={`${finding.check_id}-${index}`}><span className={`risk-chip risk-${['CRITICAL', 'HIGH'].includes(String(finding.severity).toUpperCase()) ? 'critical' : 'warning'}`}>{finding.severity}</span><strong>{finding.title}</strong><p>{finding.evidence || finding.description || 'No evidence text returned'}</p></article>)}</div>}</aside></div>
    <div className="attack-legend"><span><i className="risk-red"/>Critical / High · action needed</span><span><i className="risk-orange"/>Medium / Low · review</span><span><i className="risk-green"/>No finding · observed secure</span><span><i className="risk-gray"/>Unknown / unavailable</span><small>Risk colors reflect returned findings and observations; they are not a certification.</small></div>
  </section>
}
