import { useCallback, useEffect, useState } from 'react'
import { Activity, AlertTriangle, Database, RefreshCw, ShieldCheck, Users } from 'lucide-react'
import { toast } from 'sonner'
import GlobalThreatMap from './GlobalThreatMap.jsx'

const emptyStats = { total_users: null, total_scans: null, api_status: 'unknown', uptime_human: '—', database_status: 'unknown' }
const when = value => value ? new Date(value).toLocaleString() : 'Time unavailable'

function AdminStat({ icon, label, value, detail, tone = '' }) {
  return <article className={`admin-stat-card ${tone}`}><span className="admin-stat-icon">{icon}</span><span className="admin-stat-label">{label}</span><strong>{value}</strong><small>{detail}</small></article>
}

export default function AdminDashboard({ token, onManageUsers }) {
  const [stats, setStats] = useState(emptyStats)
  const [threats, setThreats] = useState([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const request = async path => {
    const response = await fetch(path, { headers: { Authorization: `Bearer ${token}` } })
    const data = await response.json().catch(() => ({}))
    if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`)
    return data
  }
  const load = useCallback(async () => {
    setBusy(true)
    try {
      const [nextStats, nextThreats] = await Promise.all([request('/api/v1/admin/stats'), request('/api/v1/admin/recent-vulnerabilities')])
      setStats(nextStats)
      setThreats(nextThreats)
      setError('')
    } catch (err) {
      setError(err.message)
      toast.error('Admin analytics unavailable', { description: err.message })
    } finally { setBusy(false) }
  }, [token])
  useEffect(() => { load() }, [load])
  const apiState = String(stats.api_status || 'unknown').toUpperCase()
  const dbState = String(stats.database_status || 'unknown').toUpperCase()
  return <section className="page-wrap admin-dashboard">
    <div className="page-heading"><div><p className="eyebrow">ADMINISTRATOR CONSOLE</p><h1>System Health</h1><p className="muted">Live account, assessment, service, and infrastructure signals.</p></div><div className="admin-heading-actions"><button className="button quiet" onClick={load} disabled={busy}><RefreshCw size={15} className={busy ? 'spin-icon' : ''}/> Refresh</button><button className="button primary" onClick={onManageUsers}><Users size={15}/> User Management</button></div></div>
    {error && <div className="notice error" role="alert">{error}</div>}
    <div className="admin-stats-grid">
      <AdminStat icon={<Users/>} label="Total users" value={stats.total_users ?? '—'} detail="Registered accounts"/>
      <AdminStat icon={<Activity/>} label="Total scans" value={stats.total_scans ?? '—'} detail="Saved assessments"/>
      <AdminStat icon={<ShieldCheck/>} label="API status" value={apiState} detail={`Uptime ${stats.uptime_human || '—'}`} tone={apiState === 'HEALTHY' ? 'healthy' : 'unavailable'}/>
      <AdminStat icon={<Database/>} label="Database status" value={dbState} detail="Live connectivity check" tone={dbState === 'HEALTHY' ? 'healthy' : 'unavailable'}/>
    </div>
    <div className="admin-dashboard-grid">
      <GlobalThreatMap token={token}/>
      <section className="panel glass-panel recent-threats-panel"><div className="panel-title"><div><p className="eyebrow">HIGH PRIORITY</p><h2>Recent Threats</h2></div><span className="threat-count">{threats.length} / 5</span></div>
        {threats.length ? <div className="recent-threat-list">{threats.map((threat, index) => <article className="recent-threat-item" key={`${threat.scan_id}-${index}`}><span className={`threat-severity ${String(threat.severity).toLowerCase()}`}><AlertTriangle size={14}/></span><div><strong>{threat.title}</strong><span>{threat.target}</span><small>{when(threat.created_at)} · Scan #{threat.scan_id}</small></div><b>{threat.severity}</b></article>)}</div> : <div className="empty-state compact"><ShieldCheck size={22}/><strong>No recent high or critical threats</strong><span>Latest saved scan findings will appear here.</span></div>}
      </section>
    </div>
    <p className="admin-data-footnote">Map dots show approximate locations of public server IPs observed in saved assessments. They do not indicate attack origins.</p>
  </section>
}
