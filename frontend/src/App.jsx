import { useEffect, useMemo, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { useLocation, useNavigate, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster, toast } from 'sonner'
import { Activity, ArrowUpRight, Check, X, Minus, ChevronRight, Clock3, FileDown, Globe2, KeyRound, LockKeyhole, LogOut, RefreshCw, Search, Shield, ShieldAlert, ShieldCheck, UserRound, Users, Camera, UserCog, Radar, Wifi, WifiOff, Save, Eye, EyeOff, Zap, CircleHelp, Trash2, CalendarClock } from 'lucide-react'
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import Login from './auth/Login.jsx'
import Register from './auth/Register.jsx'
import ForgotPassword, { ResetPassword } from './auth/ForgotPassword.jsx'
import AdminDashboard from './AdminDashboard.jsx'
import UserManagement from './UserManagement.jsx'
import ScanningAnimation from './ScanningAnimation.jsx'
import AttackSurfaceGraph from './AttackSurfaceGraph.jsx'
import './App.css'

const api = async (path, options = {}, token = '') => {
  const response = await fetch(path, { ...options, headers: { ...(options.body && !(options.body instanceof FormData) ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(options.headers || {}) } })
  if (response.status === 204) return null
  const data = await response.json().catch(() => ({}))
  if (!response.ok) { const error = new Error(data.detail || `Request failed (${response.status})`); error.status = response.status; throw error }
  return data
}

async function downloadReport(scanId, format) {
  const token = localStorage.getItem('token') || sessionStorage.getItem('token') || ''
  const paths = { html: 'report', pdf: 'report/pdf', json: 'report/json' }
  const fallbackNames = { html: `report_${scanId}.html`, pdf: `report_${scanId}.pdf`, json: `report_${scanId}.json` }
  try {
    const response = await fetch(`/api/v1/scans/${scanId}/${paths[format]}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!response.ok) {
      const data = await response.json().catch(() => ({}))
      throw new Error(data.detail || `Download failed (${response.status})`)
    }
    const blob = await response.blob()
    const disposition = response.headers.get('Content-Disposition') || ''
    const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1] || fallbackNames[format]
    const objectUrl = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = objectUrl
    anchor.download = filename
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000)
    toast.success(`${format.toUpperCase()} report downloaded`)
  } catch (error) {
    toast.error('Report download failed', { description: error.message })
  }
}

function NetworkBackdrop() {
  const ref = useRef(null)
  useEffect(() => {
    const canvas = ref.current, ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return undefined
    let frame, points = [], width = 0, height = 0, cursor = null
    const resize = () => {
      const scale = Math.min(window.devicePixelRatio || 1, 1.5)
      width = canvas.clientWidth; height = canvas.clientHeight
      canvas.width = width * scale; canvas.height = height * scale
      ctx.setTransform(scale, 0, 0, scale, 0, 0)
      const count = Math.min(65, Math.floor(width * height / 19000))
      points = Array.from({ length: count }, () => ({ x: Math.random() * width, y: Math.random() * height, vx: (Math.random() - .5) * .17, vy: (Math.random() - .5) * .17 }))
    }
    const draw = () => {
      ctx.clearRect(0, 0, width, height)
      points.forEach((p, i) => {
        p.x += p.vx; p.y += p.vy
        if (p.x < 0 || p.x > width) p.vx *= -1
        if (p.y < 0 || p.y > height) p.vy *= -1
        for (let j = i + 1; j < points.length; j++) {
          const q = points[j], d = Math.hypot(p.x - q.x, p.y - q.y)
          if (d < 135) { ctx.strokeStyle = `rgba(49, 166, 234, ${.12 * (1 - d / 135)})`; ctx.lineWidth = .65; ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y); ctx.stroke() }
        }
        ctx.fillStyle = 'rgba(81, 190, 245, .42)'; ctx.beginPath(); ctx.arc(p.x, p.y, 1.15, 0, Math.PI * 2); ctx.fill()
      })
      if (cursor) points.forEach(p => { const d = Math.hypot(p.x - cursor.x, p.y - cursor.y); if (d < 150) { ctx.strokeStyle = `rgba(54, 194, 245, ${.2 * (1 - d / 150)})`; ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(cursor.x, cursor.y); ctx.stroke() } })
      frame = requestAnimationFrame(draw)
    }
    const move = event => { const rect = canvas.getBoundingClientRect(); cursor = { x: event.clientX - rect.left, y: event.clientY - rect.top } }
    const leave = event => { if (!event.relatedTarget) cursor = null }
    resize(); draw(); window.addEventListener('resize', resize); window.addEventListener('pointermove', move); window.addEventListener('pointerout', leave)
    return () => { cancelAnimationFrame(frame); window.removeEventListener('resize', resize); window.removeEventListener('pointermove', move); window.removeEventListener('pointerout', leave) }
  }, [])
  return <canvas className="network-backdrop" ref={ref} aria-hidden="true" />
}

function AuthScreen({ onAuth }) {
  return <main className="auth-shell cyber-auth"><NetworkBackdrop/><Routes>
    <Route path="/login" element={<Login onAuth={onAuth}/>}/>
    <Route path="/register" element={<Register/>}/>
    <Route path="/forgot-password" element={<ForgotPassword/>}/>
    <Route path="/reset-password" element={<ResetPassword/>}/>
    <Route path="*" element={<Navigate to="/login" replace/>}/>
  </Routes></main>
}

function Stat({ icon, label, value, accent = 'blue' }) { return <motion.div className={`stat-card glass-panel accent-${accent}`} whileHover={{ y: -3, transition: { duration: .18 } }}><span className="stat-icon">{icon}</span><span className="stat-label">{label}</span><strong>{value}</strong></motion.div> }
function date(value) { return value ? new Date(value).toLocaleString() : '—' }
function severityClass(value) { return `severity ${String(value || 'info').toLowerCase()}` }
function numericScore(value) { if (value === null || value === undefined || value === '') return null; const parsed = Number(value); return Number.isFinite(parsed) ? Math.max(0, Math.min(100, parsed)) : null }

function ComplianceSignals({ signals = [], compact = false }) {
  const grouped = signals.reduce((groups, signal) => {
    const category = signal.category || 'Other'
    groups[category] = [...(groups[category] || []), signal]
    return groups
  }, {})
  const StatusIcon = ({ status }) => status === 'detected' ? <Check size={15}/> : status === 'missing' ? <X size={15}/> : <Minus size={15}/>
  return <section className={`compliance-section ${compact ? 'compliance-compact' : ''}`}>
    <div className="compliance-title"><div><p className="eyebrow">OBSERVABLE INDICATORS</p><h3>Compliance &amp; Trust</h3></div><span>Signals do not certify compliance</span></div>
    {signals.length ? Object.entries(grouped).map(([category, items]) => <div className="compliance-group" key={category}><h4>{category}</h4><div className="compliance-grid">{items.map(item => <article className={`compliance-card signal-${item.status}`} key={item.id}><div className="compliance-card-title"><span className="compliance-status"><StatusIcon status={item.status}/></span><strong>{item.name}</strong><small>{item.status}</small></div><p>{item.evidence || 'No evidence recorded'}</p></article>)}</div></div>) : <div className="empty-state compact"><CircleHelp size={20}/><strong>Signals unavailable</strong><span>This scan did not return compliance signal evidence.</span></div>}
  </section>
}

function VulnerableSoftwareVersions({ software = [] }) {
  return <section className="software-vulnerabilities panel glass-panel">
    <div className="panel-title"><div><p className="eyebrow">SERVER BANNER CORRELATION</p><h2>Vulnerable Software Versions</h2></div><span className="muted">NVD CPE matches</span></div>
    {software.length ? <div className="software-version-list">{software.map((item, index) => <article className="software-version-card" key={`${item.cpe || item.product}-${index}`}>
      <div className="software-version-heading"><div><strong>{item.product || item.software || 'Web server'}</strong><span>Version {item.version || 'unknown'}</span></div><code>{item.server_header || item.cpe}</code></div>
      <p className="software-version-note">{item.applicability_note || 'Version was inferred from the public server banner. This is an indicator for verification, not proof that the running build is vulnerable.'}</p>
      {item.cves?.length ? <div className="software-cve-list">{item.cves.map(cve => <div className="software-cve" key={cve.cve_id}>
        <span className={severityClass(cve.severity)}>{cve.severity || 'UNKNOWN'}{Number.isFinite(Number(cve.cvss_score)) ? ` · CVSS ${Number(cve.cvss_score).toFixed(1)}` : ''}</span>
        <div><a href={cve.nvd_url || `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.cve_id)}`} target="_blank" rel="noreferrer">{cve.cve_id} <ArrowUpRight size={13}/></a><p>{cve.description || 'No description is available from NVD.'}</p></div>
      </div>)}</div> : <p className="software-no-cves">{item.lookup_status === 'no_matches_or_unavailable' ? 'NVD returned no CVE matches, or its lookup was temporarily unavailable.' : 'No CVE matches were returned for this exact version CPE.'}</p>}
    </article>)}</div> : <div className="empty-state compact"><ShieldCheck size={22}/><strong>No identifiable server version was disclosed</strong><span>Servers may suppress or alter banners. This does not establish that the target has no vulnerable software.</span></div>}
  </section>
}

function LatestResult({ latestScan, onViewReport, onDownload }) {
  const score = numericScore(latestScan?.score)
  const radius = 78
  const circumference = 2 * Math.PI * radius
  const dashOffset = score === null ? circumference : circumference * (1 - score / 100)
  const grade = latestScan?.grade || (score === null ? '—' : score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F')

  return <section className="panel glass-panel chart-panel latest-result-card">
    <div className="panel-title latest-result-heading">
      <div className="latest-heading-copy"><p className="eyebrow">LATEST RESULT</p><h2>Security score</h2></div>
      {latestScan && <div className="latest-report-actions"><button type="button" className="button small quiet" onClick={() => onViewReport(latestScan.id)} disabled={!latestScan.id}>View <ArrowUpRight size={13}/></button>{['html', 'pdf', 'json'].map(format => <button type="button" className="button small quiet" key={format} onClick={() => onDownload(latestScan.id, format)} disabled={!latestScan.id}>{format.toUpperCase()}</button>)}</div>}
    </div>
    {latestScan ? <>
      <p className="latest-target" title={latestScan.target}>{latestScan.target || 'Target unavailable'}</p>
      {score !== null ? <>
        <div className="latest-gauge-wrap" aria-label={`Security score ${score} out of 100`}>
          <svg className="latest-gauge" viewBox="0 0 192 192" width="192" height="192" role="img" aria-hidden="true">
            <circle className="latest-gauge-track" cx="96" cy="96" r={radius}/>
            <circle className="latest-gauge-value" cx="96" cy="96" r={radius} stroke={score >= 75 ? '#27cb91' : score >= 50 ? '#f1bc4c' : '#ff586b'} strokeDasharray={`${circumference} ${circumference}`} strokeDashoffset={dashOffset} transform="rotate(-90 96 96)"/>
          </svg>
          <div className="latest-gauge-center"><strong>{score}</strong><span>/ 100</span><small>GRADE {grade}</small></div>
        </div>
        <div className="latest-result-meta"><span>{latestScan.num_findings ?? 0} findings</span><span>Latest saved assessment</span></div>
      </> : <div className="latest-empty-state"><span className="latest-empty-icon"><Activity size={23}/></span><strong>{grade === '—' ? 'Score unavailable' : `${grade} coverage`}</strong><span>{latestScan.num_findings ?? 0} findings · {latestScan.target || 'Latest target'}</span></div>}
    </> : <div className="latest-empty-state"><span className="latest-empty-icon"><Activity size={23}/></span><strong>No scans yet</strong><span>Your latest score and report will appear here after a scan.</span></div>}
    {latestScan && <ComplianceSignals signals={latestScan.compliance_signals || []} compact/>}
  </section>
}

function BulkScanForm({ token, scanKey, setScanKey, onCompleted }) {
  const [targetsText, setTargetsText] = useState('')
  const [job, setJob] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const running = useRef(false)
  const parseTargets = raw => raw.split(/\r?\n/).map(line => {
    const firstCell = line.match(/^\s*(?:"((?:[^"]|"")*)"|([^,;\t]+))/)
    return (firstCell ? (firstCell[1] ?? firstCell[2]) : line).replaceAll('""', '"').trim()
  }).filter(value => value && !/^(url|target(?:\s+url)?|website(?:\s+url)?|domain)$/i.test(value))
  const importCsv = async event => {
    const file = event.target.files?.[0]
    if (!file) return
    try {
      const contents = await file.text()
      setTargetsText(previous => [previous.trim(), parseTargets(contents).join('\n')].filter(Boolean).join('\n'))
      setError('')
    } catch {
      setError('Could not read this CSV file.')
    } finally {
      event.target.value = ''
    }
  }
  const startBulk = async event => {
    event.preventDefault()
    if (running.current) return
    const urls = parseTargets(targetsText)
    if (!urls.length) { setError('Paste at least one URL or upload a CSV file.'); return }
    if (urls.length > 20) { setError('A bulk job can include up to 20 targets.'); return }
    if (!scanKey) { setError('Enter the configured scan access key to run a bulk scan.'); return }
    running.current = true
    setBusy(true); setError('')
    sessionStorage.setItem('scanKey', scanKey)
    try {
      const created = await api('/api/v1/analyze/bulk', {
        method: 'POST', headers: { 'X-Scan-Key': scanKey }, body: JSON.stringify({ urls }),
      }, token)
      setJob(created)
      let current = created
      while (current.status === 'queued' || current.status === 'running') {
        await new Promise(resolve => window.setTimeout(resolve, 1400))
        current = await api(`/api/v1/analyze/bulk/${created.job_id}`, {}, token)
        setJob(current)
      }
      const successful = (current.results || []).filter(result => result.status === 'completed').length
      const failed = (current.results || []).filter(result => result.status === 'failed').length
      if (failed) toast.warning(`Bulk scan finished: ${successful} succeeded, ${failed} failed`)
      else toast.success(`Bulk scan complete: ${successful} website${successful === 1 ? '' : 's'} scanned`)
      await onCompleted?.()
    } catch (cause) {
      setError(cause.message || 'Bulk scan could not be completed.')
      toast.error('Bulk scan failed', { description: cause.message })
    } finally {
      running.current = false
      setBusy(false)
    }
  }
  const completed = job?.completed_targets || 0
  const total = job?.total_targets || 0
  const percent = total ? Math.round((completed / total) * 100) : 0
  return <>
    <p className="muted small-copy">Paste one hostname or URL per line, or upload a CSV with a target in its first column. Each successful scan is saved to your history.</p>
    <form className="bulk-scan-form" onSubmit={startBulk}>
      <label>Targets <span className="field-help">Maximum 20 websites per job</span><textarea value={targetsText} onChange={event => setTargetsText(event.target.value)} rows={7} placeholder={'example.com\nhttps://company.org'} disabled={busy}/></label>
      <label className="bulk-file-input">Import CSV<input type="file" accept=".csv,text/csv" onChange={importCsv} disabled={busy}/></label>
      <label>Scan access key<div className="target-input"><KeyRound size={17}/><input type="password" value={scanKey} onChange={event => setScanKey(event.target.value)} required autoComplete="off" placeholder="Configured scan key" disabled={busy}/></div><span className="field-help">Required for the bulk job.</span></label>
      {error && <div className="notice error"><ShieldAlert size={15}/>{error}</div>}
      <button className="button primary full" disabled={busy || !targetsText.trim()}>{busy ? <><span className="spinner"/> Scanning {completed} of {total || parseTargets(targetsText).length}…</> : <>Start bulk scan <ArrowUpRight size={16}/></>}</button>
    </form>
    {job && <div className="bulk-progress-panel"><div className="bulk-progress-copy"><strong>{busy ? `Scanning ${Math.min(completed + 1, total)} of ${total}…` : `Bulk scan ${job.status}`}</strong><span>{completed}/{total} completed</span></div><div className="bulk-progress-track"><i style={{ width: `${percent}%` }}/></div><div className="table-scroll bulk-results"><table><thead><tr><th>Target</th><th>Status</th><th>Score</th><th>Grade</th><th>Findings</th></tr></thead><tbody>{(job.results || []).map((result, index) => <tr key={`${result.target}-${index}`}><td><strong className="mono">{result.target}</strong></td><td><span className={`bulk-state ${result.status}`}>{result.status}</span>{result.error && <small className="bulk-error">{result.error}</small>}</td><td>{typeof result.score === 'number' ? `${result.score}/100` : '—'}</td><td>{result.grade || '—'}</td><td>{result.num_findings ?? '—'}</td></tr>)}</tbody></table></div></div>}
  </>
}

function Dashboard({ history, target, setTarget, scanKey, setScanKey, runAnalysis, busy, error, setView, openHistory, downloadReport, report, token, onRefreshHistory }) {
  const uniqueTargets = new Set(history.map(item => item.target).filter(Boolean)).size
  const critical = history.reduce((sum, item) => sum + (item.critical_count || 0), 0)
  const latest = history[0]
  const score = numericScore(latest?.score)
  const grades = score == null ? '—' : `${score}/100`
  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(level => ({ name: level, value: history.reduce((n, item) => n + (item.severity_counts?.[level] || 0), 0) })).filter(x => x.value > 0)
  const colors = { CRITICAL: '#ff5568', HIGH: '#ff875e', MEDIUM: '#f3c64e', LOW: '#40bdd4', INFO: '#688eff' }
  const activity = useMemo(() => Array.from({ length: 7 }, (_, index) => { const day = new Date(); day.setHours(0, 0, 0, 0); day.setDate(day.getDate() - (6 - index)); const key = day.toLocaleDateString(); return { day: day.toLocaleDateString(undefined, { weekday: 'short' }), scans: history.filter(item => new Date(item.timestamp).toLocaleDateString() === key).length } }), [history])
  const [bulkMode, setBulkMode] = useState(false)
  const [scheduleEnabled, setScheduleEnabled] = useState(false)
  const [scheduleFrequency, setScheduleFrequency] = useState(24)
  const [scheduledScans, setScheduledScans] = useState([])
  useEffect(() => { if (token) api('/api/v1/scans/scheduled', {}, token).then(setScheduledScans).catch(() => {}) }, [token])
  const submitScheduledScan = async event => {
    event.preventDefault()
    if (!scanKey) { toast.error('Enter the configured scan access key to create a schedule.'); return }
    try {
      const schedule = await api('/api/v1/scans/schedule', { method: 'POST', headers: { 'X-Scan-Key': scanKey }, body: JSON.stringify({ target_url: target.trim(), frequency_hours: Number(scheduleFrequency) }) }, token)
      setScheduledScans(previous => [schedule, ...previous])
      toast.success('Recurring scan scheduled', { description: `${schedule.target_url} · every ${schedule.frequency_hours} hours` })
    } catch (error) { toast.error('Could not schedule scan', { description: error.message }) }
  }
  const removeScheduledScan = async id => {
    try { await api(`/api/v1/scans/scheduled/${id}`, { method: 'DELETE' }, token); setScheduledScans(previous => previous.filter(item => item.id !== id)); toast.success('Schedule removed') }
    catch (error) { toast.error('Could not remove schedule', { description: error.message }) }
  }
  return <section className="page-wrap command-wrap">
    <div className="command-hero"><div><p className="eyebrow">SECURITY COMMAND CENTER</p><h1>Welcome back, Analyst</h1><p className="muted">Live view of your saved website assessments and current security posture.</p></div><button className="button primary hero-button" onClick={() => document.getElementById('target-field')?.focus()}><Zap size={17}/> Start new scan</button></div>
    <div className="stats-row command-stats"><Stat icon={<Globe2/>} label="Unique targets" value={uniqueTargets}/><Stat icon={<Activity/>} label="Total assessments" value={history.length}/><Stat icon={<ShieldAlert/>} label="Critical findings" value={critical} accent="red"/><Stat icon={<ShieldCheck/>} label="Latest score" value={grades} accent="green"/></div>
    <div className="command-grid"><section className="panel glass-panel scan-panel"><div className="panel-title bulk-panel-title"><div><p className="eyebrow">NEW ASSESSMENT</p><h2>{bulkMode ? 'Scan multiple websites' : 'Analyze a website'}</h2></div><div className="scan-mode-tabs"><button type="button" className={!bulkMode ? 'mode-tab active' : 'mode-tab'} onClick={() => setBulkMode(false)}>Single</button><button type="button" className={bulkMode ? 'mode-tab active' : 'mode-tab'} onClick={() => setBulkMode(true)}><Radar size={13}/> Bulk Scan</button></div></div>{bulkMode ? <BulkScanForm token={token} scanKey={scanKey} setScanKey={setScanKey} onCompleted={onRefreshHistory}/> : <><p className="muted small-copy">Observe public TLS, DNS records, HTTPS behavior and response security headers.</p><form onSubmit={scheduleEnabled ? submitScheduledScan : runAnalysis} className="scan-form"><label>Public domain or website URL<div className="target-input"><Globe2 size={17}/><input id="target-field" value={target} onChange={e => setTarget(e.target.value)} placeholder="your-company.com" required maxLength="2048"/></div></label><label className="schedule-switch"><input type="checkbox" checked={scheduleEnabled} onChange={event => setScheduleEnabled(event.target.checked)}/><span><CalendarClock size={15}/><b>Schedule recurring scan</b><small>Run this live assessment automatically</small></span></label>{scheduleEnabled && <label>Repeat every (hours)<div className="target-input"><CalendarClock size={16}/><input type="number" min="1" max="720" step="1" value={scheduleFrequency} onChange={event => setScheduleFrequency(event.target.value)} required/></div><span className="field-help">Choose 1–720 hours. The next run is saved in your account.</span></label>}<label>Scan access key<div className="target-input"><KeyRound size={17}/><input type="password" value={scanKey} onChange={e => setScanKey(e.target.value)} placeholder="Configured scan key" required autoComplete="off"/></div><span className="field-help">Required for every scan; held in this browser session.</span></label>{error && <div className="notice error"><ShieldAlert size={16}/>{error}</div>}<button className="button primary full" disabled={busy || !target.trim() || !scanKey}>{busy ? <><span className="spinner"/> Checking live services…</> : scheduleEnabled ? <>Create schedule <CalendarClock size={16}/></> : <>Start assessment <ArrowUpRight size={17}/></>}</button></form>{scheduleEnabled && <div className="scheduled-scan-list"><div className="scheduled-scan-title"><strong>Saved schedules</strong><span>{scheduledScans.length}</span></div>{scheduledScans.map(item => <div className="scheduled-scan-row" key={item.id}><div><strong>{item.target_url}</strong><small>Every {item.frequency_hours} hours · Next {date(item.next_run)}</small>{item.last_status && <small>Last run: {item.last_status}{item.last_error ? ` · ${item.last_error}` : ""}</small>}</div><button type="button" className="icon-button" aria-label={`Remove schedule for ${item.target_url}`} onClick={() => removeScheduledScan(item.id)}><Trash2 size={14}/></button></div>)}{!scheduledScans.length && <p className="field-help">No recurring scans scheduled for this account.</p>}</div>}<div className="check-summary"><span><Check size={14}/> TLS</span><span><Check size={14}/> DNS</span><span><Check size={14}/> HTTP</span><span className="not-included">Passive checks</span></div></>}</section><LatestResult latestScan={latest} onViewReport={openHistory} onDownload={downloadReport}/>
      <section className="panel glass-panel chart-panel"><div className="panel-title"><div><p className="eyebrow">FINDINGS</p><h2>Severity breakdown</h2></div></div>{severities.length ? <div className="severity-chart"><ResponsiveContainer width="100%" height={245}><PieChart><Pie data={severities} dataKey="value" nameKey="name" innerRadius={62} outerRadius={91} paddingAngle={3}>{severities.map(item => <Cell key={item.name} fill={colors[item.name]}/>)}</Pie><Tooltip contentStyle={{ background: '#101b29', border: '1px solid #26364b', borderRadius: 8, color: '#edf5ff' }}/></PieChart></ResponsiveContainer><div className="severity-legend">{severities.map(item => <span key={item.name}><i style={{ background: colors[item.name] }}/>{item.name}<b>{item.value}</b></span>)}</div></div> : <div className="empty-state compact"><CircleHelp size={23}/><strong>No findings recorded</strong><span>Severity distribution comes from saved live scans.</span></div>}</section>
      <section className="panel glass-panel chart-panel activity-chart"><div className="panel-title"><div><p className="eyebrow">ACTIVITY</p><h2>Scans in the last 7 days</h2></div></div><ResponsiveContainer width="100%" height={245}><AreaChart data={activity} margin={{ left: -22, right: 8, top: 12 }}><defs><linearGradient id="scanFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#24b6f2" stopOpacity={.34}/><stop offset="95%" stopColor="#24b6f2" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="#223044" vertical={false}/><XAxis dataKey="day" stroke="#73849a" tickLine={false} axisLine={false}/><YAxis allowDecimals={false} stroke="#73849a" tickLine={false} axisLine={false}/><Tooltip contentStyle={{ background: '#101b29', border: '1px solid #26364b', borderRadius: 8 }}/><Area type="monotone" dataKey="scans" stroke="#28baf1" strokeWidth={2.5} fill="url(#scanFill)"/></AreaChart></ResponsiveContainer></section></div>
    <section className="panel glass-panel recent-panel command-recent"><div className="panel-title"><div><p className="eyebrow">PERSISTED REPORTS</p><h2>Recent scans</h2></div><button className="button quiet small" onClick={() => setView('history')}>View history <ArrowUpRight size={14}/></button></div>{history.slice(0, 5).length ? <ScanTable history={history.slice(0, 5)} openHistory={openHistory} downloadReport={downloadReport}/> : <div className="empty-state compact"><div className="empty-icon"><ShieldCheck size={23}/></div><strong>Ready for your first assessment</strong><span>Saved live scan reports will appear here.</span></div>}</section>
    {report && <Report report={report} token={sessionStorage.getItem('token') || ''}/>}
  </section>
}

function ScanTable({ history, openHistory, downloadReport }) { return <div className="table-scroll"><table><thead><tr><th>Target URL</th><th>Date</th><th>Score</th><th>Grade</th><th>Findings</th><th>Report</th></tr></thead><tbody>{history.map(item => <tr key={item.id}><td><strong className="mono">{item.target}</strong></td><td>{date(item.timestamp)}</td><td>{typeof item.score === 'number' ? `${item.score}/100` : '—'}</td><td>{item.grade || 'INCOMPLETE'}</td><td>{item.num_findings}</td><td><div className="latest-report-actions"><button className="button small quiet" onClick={() => openHistory(item.id)}>View</button>{['html', 'pdf', 'json'].map(format => <button key={format} className="button small quiet" onClick={() => downloadReport(item.id, format)}>{format.toUpperCase()}</button>)}</div></td></tr>)}</tbody></table></div> }

function ProfilePage({ token, profile, setProfile }) {
  const [form, setForm] = useState({ full_name: '', email: '', webhook_url: '' }), [passwords, setPasswords] = useState({ current_password: '', new_password: '', confirm: '' }), [busy, setBusy] = useState(false), [message, setMessage] = useState(''), [error, setError] = useState(''), [showPassword, setShowPassword] = useState(false), [preview, setPreview] = useState('')
  useEffect(() => { if (profile) setForm({ full_name: profile.full_name || '', email: profile.email || '', webhook_url: profile.webhook_url || '' }) }, [profile])
  useEffect(() => { let objectUrl, cancelled = false; setPreview(''); if (!profile?.avatar_url) return undefined; fetch(profile.avatar_url, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.ok ? r.blob() : null).then(blob => { if (blob && !cancelled) { objectUrl = URL.createObjectURL(blob); setPreview(objectUrl) } }).catch(() => {}); return () => { cancelled = true; if (objectUrl) URL.revokeObjectURL(objectUrl) } }, [profile?.avatar_url, token])
  const saveProfile = async e => { e.preventDefault(); setError(''); setMessage(''); setBusy(true); try { const result = await api('/api/v1/users/me', { method: 'PUT', body: JSON.stringify({ full_name: form.full_name.trim() || null, email: form.email.trim() || null, webhook_url: form.webhook_url.trim() }) }, token); setProfile({ ...profile, ...result }); setMessage('Profile information saved.') } catch (err) { setError(err.message) } finally { setBusy(false) } }
  const uploadAvatar = async e => { const file = e.target.files?.[0]; if (!file) return; setError(''); setMessage(''); if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type) || file.size > 5 * 1024 * 1024) { setError('Choose a JPEG, PNG or WebP image under 5 MB.'); e.target.value = ''; return }; setBusy(true); try { const data = new FormData(); data.append('file', file); const result = await api('/api/v1/users/me/avatar', { method: 'POST', body: data }, token); setProfile({ ...profile, avatar_url: result.avatar_url }); setMessage('Profile picture updated.') } catch (err) { setError(err.message) } finally { setBusy(false); e.target.value = '' } }
  const savePassword = async e => { e.preventDefault(); setError(''); setMessage(''); if (passwords.new_password !== passwords.confirm) { setError('New password and confirmation do not match.'); return }; if (passwords.new_password.length < 12) { setError('Use at least 12 characters for the new password.'); return }; setBusy(true); try { const result = await api('/api/v1/users/me/password', { method: 'PUT', body: JSON.stringify({ current_password: passwords.current_password, new_password: passwords.new_password }) }, token); setMessage(result.message); setPasswords({ current_password: '', new_password: '', confirm: '' }) } catch (err) { setError(err.message) } finally { setBusy(false) } }
  return <section className="page-wrap profile-wrap"><div className="page-heading"><div><p className="eyebrow">ACCOUNT SETTINGS</p><h1>My Profile</h1><p className="muted">Manage your account identity, profile picture, and password.</p></div><span className="data-note"><LockKeyhole size={15}/> Private to your account</span></div>{error && <div className="notice error">{error}</div>}{message && <div className="notice success">{message}</div>}<div className="profile-grid"><section className="panel glass-panel avatar-panel"><p className="eyebrow">PROFILE PICTURE</p><div className="avatar-preview">{preview ? <img src={preview} alt="Profile"/> : <UserRound size={42}/>}</div><h2>{form.full_name || profile?.username}</h2><p className="muted">@{profile?.username}</p><label className="button primary upload-button"><Camera size={16}/>{busy ? 'Saving…' : 'Upload picture'}<input type="file" accept="image/png,image/jpeg,image/webp" onChange={uploadAvatar} disabled={busy}/></label><span className="field-help">JPEG, PNG or WebP · max 5 MB</span></section><section className="panel glass-panel profile-form-panel"><div className="panel-title"><div><p className="eyebrow">PERSONAL INFORMATION</p><h2>Account details</h2></div><UserCog size={19}/></div><form className="profile-form" onSubmit={saveProfile}><label>Username<input value={profile?.username || ''} disabled/></label><label>Full name<input value={form.full_name} maxLength="120" onChange={e => setForm({ ...form, full_name: e.target.value })} placeholder="Your name"/></label><label>Email address<input type="email" value={form.email} maxLength="254" onChange={e => setForm({ ...form, email: e.target.value })} placeholder="name@company.com"/></label><label className="webhook-field">Slack or Discord incoming webhook<textarea value={form.webhook_url} maxLength="2048" onChange={e => setForm({ ...form, webhook_url: e.target.value })} placeholder="https://hooks.slack.com/services/… or https://discord.com/api/webhooks/…" rows={3}/><span className="field-help">Stored privately. Only official HTTPS Slack and Discord webhook URLs are accepted. High and critical findings are sent after a scan completes.</span></label><button className="button primary" disabled={busy}><Save size={15}/> Save profile</button></form></section><section className="panel glass-panel profile-form-panel password-panel"><div className="panel-title"><div><p className="eyebrow">SECURITY</p><h2>Change password</h2></div><KeyRound size={18}/></div><form className="profile-form" onSubmit={savePassword}><label>Current password<input type="password" autoComplete="current-password" value={passwords.current_password} onChange={e => setPasswords({ ...passwords, current_password: e.target.value })} required/></label><label>New password<input type={showPassword ? 'text' : 'password'} autoComplete="new-password" value={passwords.new_password} onChange={e => setPasswords({ ...passwords, new_password: e.target.value })} required minLength="12" maxLength="128"/></label><label>Confirm new password<input type={showPassword ? 'text' : 'password'} autoComplete="new-password" value={passwords.confirm} onChange={e => setPasswords({ ...passwords, confirm: e.target.value })} required minLength="12" maxLength="128"/></label><button type="button" className="button quiet password-toggle" onClick={() => setShowPassword(!showPassword)}>{showPassword ? <EyeOff size={15}/> : <Eye size={15}/>} {showPassword ? 'Hide passwords' : 'Show passwords'}</button><button className="button primary" disabled={busy}><KeyRound size={15}/> Update password</button></form></section></div></section>
}

function Report({ report, token }) {
  const findings = report.findings || [], counts = findings.reduce((a, f) => { const s = String(f.severity || 'INFO').toUpperCase(); a[s] = (a[s] || 0) + 1; return a }, {})
  const downloadHtml = async () => { if (!report.id) return; const response = await fetch(`/api/v1/scans/${report.id}/report`, { headers: { Authorization: `Bearer ${token}` } }); if (!response.ok) return; const blob = await response.blob(), link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `website-assessment-${report.target}.html`; link.click(); URL.revokeObjectURL(link.href) }
  return <section className="report-section"><div className="report-heading"><div><p className="eyebrow">ASSESSMENT REPORT</p><h2>{report.target}</h2><p className="muted">Observed {date(report.observed_at)} · {report.data_source || 'Saved assessment'}</p></div><div className="report-actions"><button className="button quiet small" onClick={downloadHtml} disabled={!report.id}><FileDown size={15}/> Export HTML</button><div className="score-box"><strong>{report.score ?? '—'}</strong><span>POSTURE SCORE</span><b>{report.grade ? `Grade ${report.grade}` : 'INCOMPLETE'}</b></div></div></div><div className="stats-row report-stats"><Stat icon={<ShieldAlert/>} label="Findings" value={findings.length}/><Stat icon={<ShieldCheck/>} label="Critical / High" value={(counts.CRITICAL || 0) + (counts.HIGH || 0)}/><Stat icon={<Globe2/>} label="Resolved addresses" value={(report.checks?.dns?.addresses || []).length}/></div><AttackSurfaceGraph report={report}/><ComplianceSignals signals={report.compliance_signals || report.checks?.compliance_signals || []}/><VulnerableSoftwareVersions software={report.vulnerable_software || report.checks?.vulnerable_software || []}/>{report.layer_coverage && <div className="coverage-line"><strong>Assessment coverage</strong>{Object.entries(report.layer_coverage).map(([name, value]) => <span key={name} className={value === 'observed' ? 'covered' : 'uncovered'}>{name.toUpperCase()} · {value}</span>)}</div>}{report.scoring_method && <div className="score-explanation"><div><strong>How this score was calculated</strong><span>{report.scoring_method.formula}; only high-confidence observations count. This is a posture score, not CVSS.</span></div><div className="deduction-list">{report.score_breakdown.map(item => <span key={item.check_id}><code>{item.check_id}</code><b>{item.deduction ? `−${item.deduction}` : '0 points'}</b></span>)}{!report.score_breakdown.length && <span>No deductions: no scored findings were observed.</span>}</div></div>}<div className="panel glass-panel findings-panel"><div className="panel-title"><h2>Findings & mitigation plans</h2><span className="muted">Each item includes observed evidence</span></div>{findings.length ? findings.map((f, i) => <article className="finding-card" key={`${f.check_id || f.id}-${i}`}><div className="finding-top"><span className={severityClass(f.severity)}>{f.severity}</span><span className="confidence">{f.confidence || 'observed'} confidence</span></div><h3>{f.title}</h3><p>{f.description}</p><div className="evidence"><span>OBSERVED EVIDENCE</span><code>{f.evidence}</code></div><div className="mitigation"><span>MITIGATION PLAN</span><p>{f.recommendation}</p></div>{f.references?.length > 0 && <div className="reference-row">References: {f.references.map((url, j) => <a href={url} target="_blank" rel="noreferrer" key={j}>Source {j + 1} <ArrowUpRight size={12}/></a>)}</div>}</article>) : <div className="empty-state compact"><ShieldCheck size={23}/><strong>No scored findings were observed</strong><span>Checks that could not be completed stay unknown and do not lower the score.</span></div>}</div><details className="panel glass-panel technical-panel"><summary><span>Technical observations</span><span className="muted">Raw live check results</span></summary><pre>{JSON.stringify(report.checks || {}, null, 2)}</pre></details></section>
}

function App() {
  const navigate = useNavigate()
  const location = useLocation()
  const [auth, setAuth] = useState(() => ({ token: sessionStorage.getItem('token') || '', username: sessionStorage.getItem('username') || '', role: sessionStorage.getItem('role') || 'user', is_verified: sessionStorage.getItem('is_verified') === 'true' ? true : sessionStorage.getItem('is_verified') === 'false' ? false : null }))
  const [view, setView] = useState('dashboard'), [target, setTarget] = useState(''), [scanKey, setScanKey] = useState(sessionStorage.getItem('scanKey') || ''), [report, setReport] = useState(null), [history, setHistory] = useState([]), [busy, setBusy] = useState(false), [error, setError] = useState(''), [phase, setPhase] = useState('Resolving DNS…'), [progress, setProgress] = useState(0), [terminalLines, setTerminalLines] = useState([]), [loadingHistory, setLoadingHistory] = useState(false), [apiOnline, setApiOnline] = useState(false), [profile, setProfile] = useState(null)
  const scanInFlight = useRef(false)
  const headers = useMemo(() => ({ 'X-Scan-Key': scanKey }), [scanKey])
  const logout = () => { sessionStorage.clear(); setAuth({ token: '', username: '', role: 'user', is_verified: null }); setReport(null); setHistory([]); setProfile(null) }
  const navigateTo = destination => {
    const paths = { dashboard: '/', history: '/scans', profile: '/profile', admin: '/admin', admin_users: '/admin/users' }
    setView(destination)
    if (paths[destination] && location.pathname !== paths[destination]) navigate(paths[destination])
  }
  const saveAuth = data => { sessionStorage.setItem('token', data.access_token); sessionStorage.setItem('username', data.username); sessionStorage.setItem('role', data.role); sessionStorage.setItem('is_verified', String(Boolean(data.is_verified))); setAuth({ token: data.access_token, username: data.username, role: data.role, is_verified: Boolean(data.is_verified) }) }
  const loadHistory = async () => { if (!auth.token) return; setLoadingHistory(true); try { setHistory(await api('/api/v1/scans', {}, auth.token)) } catch (e) { if (e.status === 401) logout(); else setError(e.message) } finally { setLoadingHistory(false) } }
  useEffect(() => { if (!auth.token) return; loadHistory(); api('/api/v1/health').then(() => setApiOnline(true)).catch(() => setApiOnline(false)); api('/api/v1/users/me', {}, auth.token).then(data => { setProfile(data); sessionStorage.setItem('is_verified', String(Boolean(data.is_verified))); setAuth(previous => ({ ...previous, is_verified: Boolean(data.is_verified) })) }).catch(e => { if (e.status === 401) logout() }) }, [auth.token])
  useEffect(() => {
    const reportMatch = location.pathname.match(/^\/reports\/(\d+)\/?$/)
    const pathView = reportMatch ? 'report' : location.pathname.startsWith('/scans') ? 'history' : location.pathname.startsWith('/profile') ? 'profile' : location.pathname.startsWith('/admin/users') ? 'admin_users' : location.pathname.startsWith('/admin') ? 'admin' : 'dashboard'
    setView(pathView)
    if (!reportMatch || !auth.token) return undefined
    let active = true
    setReport(null)
    api(`/api/v1/scans/${reportMatch[1]}`, {}, auth.token).then(result => {
      if (!active) return
      const reportData = result.details ? { ...result.details, id: result.id, score: result.details.score ?? result.score, grade: result.details.grade ?? result.grade } : {
        id: result.id, target: result.target, findings: result.findings || [], checks: result.http_assessment?.checks || {},
        score: result.score ?? result.http_assessment?.score, grade: result.grade ?? result.http_assessment?.grade,
        observed_at: result.timestamp, data_source: result.http_assessment?.data_source,
      }
      setReport(reportData)
    }).catch(error => { if (active) toast.error('Could not open report', { description: error.message }) })
    return () => { active = false }
  }, [location.pathname, auth.token])
  const appendTerminal = (text, kind = 'info') => setTerminalLines(previous => [...previous, { time: new Date().toLocaleTimeString(), text, kind }])
  const runAnalysis = async event => {
    event.preventDefault()
    if (scanInFlight.current) return
    setError('')
    if (!scanKey) { setError('Enter the configured scan access key to run a scan.'); return }
    scanInFlight.current = true
    setBusy(true); setProgress(0); setPhase('Resolving DNS…'); setReport(null); setTerminalLines([{ time: new Date().toLocaleTimeString(), text: `Assessment request started for ${target.trim()}.`, kind: 'info' }])
    sessionStorage.setItem('scanKey', scanKey)
    const phases = ['Resolving DNS...', 'Checking TLS certificate chain...', 'Analyzing HTTP security headers...', 'Mapping attack surface...', 'Generating report...']
    let estimate = 3, ticks = 0, lastStep = -1
    const timer = window.setInterval(() => {
      ticks += 1
      estimate = Math.min(estimate + (estimate < 65 ? 2 : 1), 99)
      setProgress(estimate)
      const step = Math.min(Math.floor(ticks / 6), phases.length - 1)
      if (step !== lastStep) { lastStep = step; setPhase(phases[step]); appendTerminal(`${phases[step]} · analyzer request is still running`, 'pending') }
    }, 350)
    try {
      const result = await api('/api/v1/analyze', { method: 'POST', headers, body: JSON.stringify({ target: target.trim() }) }, auth.token)
      setProgress(100); setPhase('Scan complete'); setReport(result)
      const checks = result.checks || {}
      const addresses = checks.dns?.addresses || []
      appendTerminal(addresses.length ? `DNS response: ${addresses.join(', ')}` : 'DNS address observations were not returned.', addresses.length ? 'success' : 'unknown')
      const tls = checks.tls || {}
      appendTerminal(tls.issuer ? `TLS certificate issuer: ${tls.issuer}` : (tls.supported_protocols?.length ? `TLS protocols observed: ${tls.supported_protocols.join(', ')}` : 'TLS certificate details were not returned.'), tls.issuer || tls.supported_protocols?.length ? 'success' : 'unknown')
      const http = checks.http || {}
      appendTerminal(Number.isInteger(http.status_code) ? `HTTP response: ${http.status_code}; observed headers: ${Object.keys(http.headers || {}).join(', ') || 'none recorded'}` : 'HTTP response details were not returned.', Number.isInteger(http.status_code) ? 'success' : 'unknown')
      appendTerminal(`Report generated from ${Array.isArray(result.findings) ? result.findings.length : 0} returned finding(s).`, 'success')
      const severityCounts = (result.findings || []).reduce((counts, finding) => {
        const severity = String(finding.severity || 'INFO').toUpperCase()
        counts[severity] = (counts[severity] || 0) + 1
        return counts
      }, {})
      setHistory(previous => [{
        id: result.id, target: result.target, timestamp: result.observed_at,
        status: result.scan_status === 'completed' ? 'Completed' : result.scan_status,
        score: result.score, grade: result.grade, num_findings: (result.findings || []).length,
        severity_counts: severityCounts, critical_count: severityCounts.CRITICAL || 0,
      }, ...previous.filter(item => item.id !== result.id)])
      await loadHistory()
      navigateTo('dashboard')
      if (typeof result.score === 'number') toast.success(`Scan Complete! Score: ${result.score}/100`, { description: `${result.target} · Grade ${result.grade}` })
      else toast.success('Scan Complete!', { description: `${result.target} · Coverage: ${result.grade || 'INCOMPLETE'}` })
    } catch (e) {
      setError(e.message); setPhase('Scan request failed'); appendTerminal(`Scan failed: ${e.message}`, 'error'); toast.error('Scan failed', { description: e.message }); await new Promise(resolve => window.setTimeout(resolve, 900))
    } finally {
      window.clearInterval(timer)
      scanInFlight.current = false
      setBusy(false)
    }
  }
  const openHistory = id => { setError(''); if (id) navigate(`/reports/${id}`) }
  if (!auth.token) return <AuthScreen onAuth={saveAuth}/>
  return <div className="app-shell cyber-shell flex h-screen overflow-hidden bg-slate-900"><NetworkBackdrop/><Toaster position="top-right" theme="dark" richColors closeButton/><aside className="sidebar glass-sidebar w-64 shrink-0 flex flex-col h-full border-r border-slate-800"><div className="sidebar-brand"><div className="brand-mark small"><Shield size={18}/></div><div><strong>SiteWatch</strong><span>Security Center</span></div></div><nav className="sidebar-menu"><div className="side-label">MAIN MENU</div><button className={`side-link ${view === 'dashboard' ? 'selected' : ''}`} onClick={() => navigateTo('dashboard')}><Activity size={17}/> Dashboard</button><button className={`side-link ${view === 'history' ? 'selected' : ''}`} onClick={() => { navigateTo('history'); loadHistory() }}><Clock3 size={17}/> Scan History</button><div className="side-label settings-label">SETTINGS</div><button className={`side-link ${view === 'profile' ? 'selected' : ''}`} onClick={() => navigateTo('profile')}><UserCog size={17}/> My Profile</button>{['admin', 'company_admin'].includes(auth.role) && <><div className="side-label admin-label">ADMINISTRATION</div><button className={`side-link ${view === 'admin' ? 'selected' : ''}`} onClick={() => navigateTo('admin')}><Activity size={17}/> Admin Stats</button><button className={`side-link ${view === 'admin_users' ? 'selected' : ''}`} onClick={() => navigateTo('admin_users')}><Users size={17}/> User Management</button></>}</nav><div className="sidebar-bottom"><button className="account-card profile-shortcut" onClick={() => navigateTo('profile')}><span className="account-avatar">{profile?.avatar_url ? <AvatarImage token={auth.token} url={profile.avatar_url}/> : <UserRound size={17}/>}</span><span className="account-text"><strong>{profile?.full_name || auth.username}</strong><small>{['admin', 'company_admin'].includes(auth.role) ? auth.role.toUpperCase() : 'ANALYST'}</small></span><span role="button" className="logout-button" aria-label="Sign out" onClick={e => { e.stopPropagation(); logout() }}><LogOut size={15}/></span></button></div></aside><main className="main-area flex-1 h-full min-w-0 overflow-y-auto p-6"><header className="topbar command-topbar"><div><span className="crumb">SiteWatch</span><ChevronRight size={14}/><strong>{view === 'admin_users' ? 'User Management' : view === 'admin' ? 'Admin Stats' : view === 'history' ? 'Scan History' : view === 'profile' ? 'My Profile' : view === 'report' ? 'Scan Report' : 'Security Command Center'}</strong></div><div className="topbar-right flex items-center gap-3"><span className={`live-pill ${apiOnline ? '' : 'offline'}`}>{apiOnline ? <Wifi size={13}/> : <WifiOff size={13}/>} API {apiOnline ? 'ONLINE' : 'OFFLINE'}</span><button className="button primary top-scan" onClick={() => { navigateTo('dashboard'); window.setTimeout(() => document.getElementById('target-field')?.focus(), 50) }}><Zap size={14}/> Start scan</button></div></header>{(profile?.is_verified ?? auth.is_verified) === false && <div className="verification-warning"><ShieldAlert size={16}/><span><strong>Email verification pending.</strong> Your email address has not been verified yet.</span></div>}<AnimatePresence mode="wait"><motion.div key={view} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -5 }} transition={{ duration: .2 }}>{view === 'admin' && ['admin', 'company_admin'].includes(auth.role) ? <AdminDashboard token={auth.token} onManageUsers={() => navigateTo('admin_users')}/> : view === 'admin_users' && ['admin', 'company_admin'].includes(auth.role) ? <UserManagement token={auth.token}/> : view.startsWith('admin') ? <section className="page-wrap"><div className="notice error">Administrator access required.</div></section> : view === 'profile' ? <ProfilePage token={auth.token} profile={profile} setProfile={setProfile}/> : view === 'report' ? <section className="page-wrap"><div className="page-heading"><div><p className="eyebrow">SAVED ASSESSMENT</p><h1>Scan report</h1><p className="muted">Full evidence and mitigation details for this saved scan.</p></div><button className="button quiet" onClick={() => navigateTo('history')}><ChevronRight size={15}/> Back to history</button></div>{report ? <Report report={report} token={auth.token}/> : <div className="empty-state">Loading report…</div>}</section> : view === 'history' ? <section className="page-wrap"><div className="page-heading"><div><p className="eyebrow">ASSESSMENTS</p><h1>Scan history</h1><p className="muted">Saved live assessments linked to your account.</p></div><button className="button quiet" onClick={loadHistory}><RefreshCw size={16}/> Refresh</button></div>{loadingHistory && <div className="loading-line">Loading saved assessments…</div>}<div className="panel glass-panel history-panel">{history.length ? <ScanTable history={history} openHistory={openHistory} downloadReport={downloadReport}/> : !loadingHistory && <div className="empty-state compact"><Clock3 size={23}/><strong>No assessments saved</strong><span>Your completed live scans will appear here.</span></div>}</div></section> : <Dashboard history={history} target={target} setTarget={setTarget} scanKey={scanKey} setScanKey={setScanKey} runAnalysis={runAnalysis} busy={busy} error={error} setView={navigateTo} openHistory={openHistory} downloadReport={downloadReport} report={report} token={auth.token} onRefreshHistory={loadHistory}/>}</motion.div></AnimatePresence></main><AnimatePresence>{busy && <ScanningAnimation phase={phase} progress={progress} lines={terminalLines}/>}</AnimatePresence></div>
}

function AvatarImage({ token, url }) { const [src, setSrc] = useState(''); useEffect(() => { let objectUrl, cancelled = false; setSrc(''); fetch(url, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.ok ? r.blob() : null).then(blob => { if (blob && !cancelled) { objectUrl = URL.createObjectURL(blob); setSrc(objectUrl) } }).catch(() => {}); return () => { cancelled = true; if (objectUrl) URL.revokeObjectURL(objectUrl) } }, [url, token]); return src ? <img className="avatar-img" src={src} alt="Profile"/> : <UserRound size={17}/> }

export default App
