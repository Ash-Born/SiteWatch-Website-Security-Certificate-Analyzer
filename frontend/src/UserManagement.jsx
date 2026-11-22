import { useCallback, useEffect, useMemo, useState } from 'react'
import { RefreshCw, Search, Shield, ShieldOff, Users } from 'lucide-react'
import { toast } from 'sonner'

const date = value => value ? new Date(value).toLocaleString() : '—'

export default function UserManagement({ token }) {
  const [users, setUsers] = useState([])
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const [busyId, setBusyId] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const load = useCallback(async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/v1/admin/users', { headers: { Authorization: `Bearer ${token}` } })
      const data = await response.json().catch(() => ([]))
      if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`)
      setUsers(Array.isArray(data) ? data : [])
      setError('')
    } catch (err) { setError(err.message); toast.error('Could not load users', { description: err.message }) }
    finally { setLoading(false) }
  }, [token])
  useEffect(() => { load() }, [load])
  const visibleUsers = useMemo(() => users.filter(user => {
    const matchesQuery = [user.username, user.full_name, user.email, user.role].filter(Boolean).join(' ').toLowerCase().includes(query.trim().toLowerCase())
    return matchesQuery && (filter === 'all' || (filter === 'active' ? user.is_active : !user.is_active))
  }), [users, query, filter])
  const toggle = async user => {
    const nextActive = !user.is_active
    setBusyId(user.id)
    try {
      const response = await fetch(`/api/v1/admin/users/${user.id}/status`, { method: 'PUT', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ is_active: nextActive }) })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`)
      setUsers(previous => previous.map(item => item.id === user.id ? { ...item, is_active: data.is_active } : item))
      toast.success(nextActive ? `${user.username} reactivated` : `${user.username} suspended`)
    } catch (err) { setError(err.message); toast.error('User status update failed', { description: err.message }) }
    finally { setBusyId(null) }
  }
  return <section className="page-wrap user-management-page">
    <div className="page-heading"><div><p className="eyebrow">ADMINISTRATION</p><h1>User Management</h1><p className="muted">Review account access and suspend or reactivate user accounts.</p></div><button className="button quiet" onClick={load} disabled={loading}><RefreshCw size={15} className={loading ? 'spin-icon' : ''}/> Refresh</button></div>
    {error && <div className="notice error" role="alert">{error}</div>}
    <div className="user-management-summary"><span><Users size={17}/><strong>{users.length}</strong> total users</span><span><Shield size={17}/><strong>{users.filter(user => user.is_active).length}</strong> active</span><span><ShieldOff size={17}/><strong>{users.filter(user => !user.is_active).length}</strong> suspended</span></div>
    <section className="panel glass-panel user-management-panel"><div className="user-table-toolbar"><label className="admin-search"><Search size={15}/><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search name, username, email…" aria-label="Search users"/></label><select value={filter} onChange={event => setFilter(event.target.value)} aria-label="Filter by status"><option value="all">All statuses</option><option value="active">Active</option><option value="suspended">Suspended</option></select></div>
      <div className="table-scroll"><table><thead><tr><th>User</th><th>Email</th><th>Role</th><th>Status</th><th>Scans</th><th>Created</th><th>Access</th></tr></thead><tbody>{visibleUsers.map(user => <tr key={user.id}><td><strong>{user.full_name || user.username}</strong><small className="user-handle">@{user.username}</small></td><td>{user.email || '—'}</td><td><span className={`role-pill ${user.role}`}>{user.role}</span></td><td><span className={`state ${user.is_active ? 'active' : 'suspended'}`}>{user.is_active ? 'Active' : 'Suspended'}</span></td><td>{user.scan_count ?? 0}</td><td>{date(user.created_at)}</td><td>{['admin', 'company_admin'].includes(user.role) ? <span className="protected-admin">Protected</span> : <button className={`button small ${user.is_active ? 'danger-quiet' : 'quiet'}`} disabled={busyId === user.id} onClick={() => toggle(user)}>{busyId === user.id ? 'Saving…' : user.is_active ? 'Suspend' : 'Reactivate'}</button>}</td></tr>)}
        {!visibleUsers.length && <tr><td colSpan="7" className="empty-cell">{loading ? 'Loading users…' : 'No users match these filters.'}</td></tr>}
      </tbody></table></div>
      <p className="user-management-note">Suspended accounts are rejected at login and on authenticated API requests. Privileged administrator accounts require out-of-band administration.</p>
    </section>
  </section>
}
