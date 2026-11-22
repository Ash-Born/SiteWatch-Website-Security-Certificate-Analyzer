import { useState, useEffect } from 'react'
import { Server, Plus, Edit2, Trash2, Shield, AlertTriangle, Search, RefreshCw, X, Play } from 'lucide-react'

export default function AssetManager({ getAuthHeaders, onScanAsset }) {
  const [assets, setAssets] = useState([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [filterCriticality, setFilterCriticality] = useState('ALL')

  // Modal State
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [editingAsset, setEditingAsset] = useState(null)
  const [formData, setFormData] = useState({
    hostname: '',
    ip_address: '',
    operating_system: '',
    criticality: 'Medium',
    owner: '',
    description: ''
  })
  const [formError, setFormError] = useState(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Asset Details Modal
  const [selectedAsset, setSelectedAsset] = useState(null)

  useEffect(() => {
    fetchAssets()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const fetchAssets = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/v1/assets', {
        headers: getAuthHeaders()
      })
      if (!res.ok) {
        const errData = await res.json()
        throw new Error(errData.detail || 'Failed to fetch assets')
      }
      const data = await res.json()
      setAssets(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setIsLoading(false)
    }
  }

  const openCreateModal = () => {
    setEditingAsset(null)
    setFormData({
      hostname: '',
      ip_address: '',
      operating_system: '',
      criticality: 'Medium',
      owner: '',
      description: ''
    })
    setFormError(null)
    setIsModalOpen(true)
  }

  const openEditModal = (asset, e) => {
    e.stopPropagation()
    setEditingAsset(asset)
    setFormData({
      hostname: asset.hostname || '',
      ip_address: asset.ip_address || '',
      operating_system: asset.operating_system || '',
      criticality: asset.criticality || 'Medium',
      owner: asset.owner || '',
      description: asset.description || ''
    })
    setFormError(null)
    setIsModalOpen(true)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setFormError(null)
    if (!formData.hostname.trim() || !formData.ip_address.trim()) {
      setFormError('Hostname and IP Address / Host Target are required.')
      return
    }

    setIsSubmitting(true)
    try {
      const url = editingAsset ? `/api/v1/assets/${editingAsset.id}` : '/api/v1/assets'
      const method = editingAsset ? 'PUT' : 'POST'

      const res = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders()
        },
        body: JSON.stringify(formData)
      })

      const data = await res.json()

      if (!res.ok) {
        throw new Error(data.detail || 'Failed to save asset')
      }

      setIsModalOpen(false)
      fetchAssets()
      if (selectedAsset && editingAsset && selectedAsset.id === editingAsset.id) {
        setSelectedAsset(data)
      }
    } catch (err) {
      setFormError(err.message)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleDelete = async (assetId, e) => {
    e.stopPropagation()
    if (!window.confirm('Are you sure you want to delete this asset? All associated scan links will be unlinked.')) {
      return
    }

    try {
      const res = await fetch(`/api/v1/assets/${assetId}`, {
        method: 'DELETE',
        headers: getAuthHeaders()
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.detail || 'Failed to delete asset')
      }

      if (selectedAsset && selectedAsset.id === assetId) {
        setSelectedAsset(null)
      }
      fetchAssets()
    } catch (err) {
      alert(`Error deleting asset: ${err.message}`)
    }
  }

  const loadAssetDetails = async (assetId) => {
    try {
      const res = await fetch(`/api/v1/assets/${assetId}`, {
        headers: getAuthHeaders()
      })
      if (res.ok) {
        const data = await res.json()
        setSelectedAsset(data)
      }
    } catch (err) {
      console.error("Failed to load asset details:", err)
    }
  }

  const getCriticalityBadge = (crit) => {
    const c = (crit || '').toUpperCase()
    if (c === 'CRITICAL') return 'badge-critical'
    if (c === 'HIGH') return 'badge-high'
    if (c === 'MEDIUM') return 'badge-medium'
    if (c === 'LOW') return 'badge-low'
    return 'badge-info'
  }

  // Filtered Assets
  const filteredAssets = assets.filter(asset => {
    const matchesSearch = 
      asset.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
      asset.ip_address.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (asset.owner && asset.owner.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (asset.operating_system && asset.operating_system.toLowerCase().includes(searchQuery.toLowerCase()))
    
    const matchesCrit = filterCriticality === 'ALL' || asset.criticality.toUpperCase() === filterCriticality
    return matchesSearch && matchesCrit
  })

  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Top Header & Metrics Bar */}
      <div className="glass-card">
        <div className="glass-card-header">
          <h2 className="glass-card-title">
            <Server size={20} className="logo-icon" /> Infrastructure Asset Inventory
          </h2>
          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <button className="btn btn-secondary" onClick={fetchAssets} disabled={isLoading}>
              <RefreshCw size={14} className={isLoading ? 'btn-spin' : ''} /> Refresh
            </button>
            <button className="btn btn-primary" onClick={openCreateModal}>
              <Plus size={16} /> Register New Asset
            </button>
          </div>
        </div>

        {/* Filter and Search Controls */}
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center', marginTop: '0.5rem' }}>
          <div className="input-group" style={{ flexGrow: 1, minWidth: '240px', marginBottom: 0 }}>
            <div style={{ position: 'relative' }}>
              <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input 
                type="text"
                className="input-field"
                placeholder="Search by hostname, IP address, OS, or owner..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{ paddingLeft: '2.4rem' }}
              />
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: 500 }}>Criticality:</span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(crit => (
              <button
                key={crit}
                className={`badge ${filterCriticality === crit ? 'badge-info' : ''}`}
                style={{
                  cursor: 'pointer',
                  padding: '0.35rem 0.75rem',
                  border: filterCriticality === crit ? '1px solid var(--color-primary)' : '1px solid var(--border-color)',
                  background: filterCriticality === crit ? 'rgba(59, 130, 246, 0.2)' : 'transparent',
                  color: filterCriticality === crit ? '#93c5fd' : 'var(--text-secondary)'
                }}
                onClick={() => setFilterCriticality(crit)}
              >
                {crit}
              </button>
            ))}
          </div>
        </div>
      </div>

      {error && (
        <div className="glass-card" style={{ borderLeft: '4px solid var(--severity-critical)' }}>
          <div style={{ display: 'flex', gap: '0.5rem', color: 'var(--severity-critical)' }}>
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Main Content Layout: Table & Asset Detail Panel */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedAsset ? '1fr 380px' : '1fr', gap: '1.5rem' }}>
        
        {/* Asset Inventory Table */}
        <div className="glass-card">
          <div className="glass-card-header">
            <h3 className="glass-card-title">Assets ({filteredAssets.length})</h3>
          </div>

          {filteredAssets.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted)' }}>
              <Server size={40} style={{ opacity: 0.3, marginBottom: '0.75rem' }} />
              <p style={{ margin: 0, fontWeight: 500 }}>No infrastructure assets found.</p>
              <p style={{ fontSize: '0.85rem', marginTop: '0.25rem' }}>Add your first target server or domain to perform asset-linked vulnerability scanning.</p>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="results-table">
                <thead>
                  <tr>
                    <th>Hostname</th>
                    <th>IP / Host Target</th>
                    <th>Criticality</th>
                    <th>Owner / Team</th>
                    <th>Operating System</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAssets.map(asset => (
                    <tr 
                      key={asset.id} 
                      onClick={() => loadAssetDetails(asset.id)}
                      style={{ 
                        cursor: 'pointer',
                        background: selectedAsset?.id === asset.id ? 'rgba(59, 130, 246, 0.12)' : undefined 
                      }}
                    >
                      <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <Server size={14} style={{ color: 'var(--color-primary)' }} />
                          {asset.hostname}
                        </div>
                      </td>
                      <td>
                        <code style={{ color: 'var(--color-primary)', background: 'rgba(59,130,246,0.1)', padding: '0.15rem 0.4rem', borderRadius: '4px' }}>
                          {asset.ip_address}
                        </code>
                      </td>
                      <td>
                        <span className={`badge ${getCriticalityBadge(asset.criticality)}`}>
                          {asset.criticality}
                        </span>
                      </td>
                      <td style={{ color: asset.owner ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                        {asset.owner || '—'}
                      </td>
                      <td style={{ color: asset.operating_system ? 'var(--text-secondary)' : 'var(--text-muted)' }}>
                        {asset.operating_system || '—'}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                          <button 
                            className="btn btn-primary"
                            style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }}
                            title="Launch Scan on this Asset"
                            onClick={(e) => {
                              e.stopPropagation()
                              onScanAsset(asset)
                            }}
                          >
                            <Play size={12} /> Scan
                          </button>
                          <button 
                            className="btn btn-secondary"
                            style={{ padding: '0.25rem 0.5rem' }}
                            title="Edit Asset"
                            onClick={(e) => openEditModal(asset, e)}
                          >
                            <Edit2 size={13} />
                          </button>
                          <button 
                            className="btn btn-secondary"
                            style={{ padding: '0.25rem 0.5rem', color: 'var(--severity-critical)' }}
                            title="Delete Asset"
                            onClick={(e) => handleDelete(asset.id, e)}
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Selected Asset Details Sidebar */}
        {selectedAsset && (
          <div className="glass-card fade-in" style={{ height: 'fit-content' }}>
            <div className="glass-card-header">
              <h3 className="glass-card-title"><Shield size={16} /> Asset Specification</h3>
              <button 
                className="btn-logout" 
                style={{ padding: '0.2rem 0.4rem', border: 'none' }}
                onClick={() => setSelectedAsset(null)}
              >
                <X size={16} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <h2 style={{ margin: '0.25rem 0', fontSize: '1.4rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  {selectedAsset.hostname}
                </h2>
                <div style={{ marginTop: '0.25rem', color: 'var(--text-secondary)' }}>
                  IP: <code style={{ color: 'var(--color-primary)' }}>{selectedAsset.ip_address}</code>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', marginTop: '0.5rem' }}>
                <div className="metric-card" style={{ padding: '0.75rem' }}>
                  <span className="metric-label">Last Scan</span>
                  <span className="metric-value" style={{ fontSize: '0.9rem', marginTop: '0.25rem' }}>
                    {selectedAsset.scans && selectedAsset.scans.length > 0 
                      ? new Date(selectedAsset.scans[0].timestamp).toLocaleDateString() 
                      : 'Never'}
                  </span>
                </div>
                <div className="metric-card" style={{ padding: '0.75rem' }}>
                  <span className="metric-label">Total Scans</span>
                  <span className="metric-value" style={{ fontSize: '0.9rem', marginTop: '0.25rem' }}>
                    {selectedAsset.scans?.length || 0}
                  </span>
                </div>
                <div className="metric-card" style={{ padding: '0.75rem', gridColumn: 'span 2' }}>
                  <span className="metric-label">Highest Risk</span>
                  <span className={`metric-value`} style={{ fontSize: '1rem', marginTop: '0.25rem', color: selectedAsset.scans?.some(s => (s.host_severity || '').toUpperCase() === 'CRITICAL') ? 'var(--severity-critical)' : selectedAsset.scans?.some(s => (s.host_severity || '').toUpperCase() === 'HIGH') ? 'var(--severity-high)' : 'var(--text-primary)' }}>
                    {(() => {
                      const scans = selectedAsset.scans || []
                      if (scans.length === 0) return 'None'
                      const sevs = scans.map(s => (s.host_severity || '').toUpperCase())
                      if (sevs.includes('CRITICAL')) return 'Critical'
                      if (sevs.includes('HIGH')) return 'High'
                      if (sevs.includes('MEDIUM')) return 'Medium'
                      if (sevs.includes('LOW')) return 'Low'
                      return 'None'
                    })()}
                  </span>
                </div>
              </div>

              <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.85rem' }}>
                <div className="flex-between">
                  <span style={{ color: 'var(--text-muted)' }}>Owner / Team:</span>
                  <span style={{ fontWeight: 500 }}>{selectedAsset.owner || 'Unassigned'}</span>
                </div>
                <div className="flex-between">
                  <span style={{ color: 'var(--text-muted)' }}>OS:</span>
                  <span style={{ fontWeight: 500 }}>{selectedAsset.operating_system || 'Unspecified'}</span>
                </div>
                <div className="flex-between">
                  <span style={{ color: 'var(--text-muted)' }}>Registered:</span>
                  <span>{selectedAsset.created_at}</span>
                </div>
                <div className="flex-between">
                  <span style={{ color: 'var(--text-muted)' }}>Last Updated:</span>
                  <span>{selectedAsset.updated_at}</span>
                </div>
              </div>

              {selectedAsset.description && (
                <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem' }}>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Description & Notes:</span>
                  <p style={{ fontSize: '0.85rem', margin: 0, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                    {selectedAsset.description}
                  </p>
                </div>
              )}

              {/* Linked Scan History for this asset */}
              <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem' }}>
                <div className="flex-between" style={{ marginBottom: '0.5rem' }}>
                  <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Linked Scan History</span>
                </div>

                {selectedAsset.scans && selectedAsset.scans.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '200px', overflowY: 'auto' }}>
                    {selectedAsset.scans.map(s => (
                      <div key={s.id} className="history-item" style={{ padding: '0.5rem 0.75rem' }}>
                        <div className="flex-between">
                          <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>Scan #{s.id}</span>
                          <span className={`badge ${getCriticalityBadge(s.host_severity)}`} style={{ fontSize: '0.65rem' }}>
                            {s.host_severity}
                          </span>
                        </div>
                        <div className="flex-between" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                          <span>{s.timestamp}</span>
                          <span>Risk: {s.weighted_risk_score?.toFixed(1) || 0}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: 0 }}>No scans recorded for this asset yet.</p>
                )}
              </div>

              <button 
                className="btn btn-primary" 
                style={{ marginTop: '0.5rem' }}
                onClick={() => onScanAsset(selectedAsset)}
              >
                <Play size={16} /> Scan Asset Now
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Create / Edit Asset Modal */}
      {isModalOpen && (
        <div className="modal-overlay">
          <div className="modal-card fade-in">
            <div className="glass-card-header">
              <h3 className="glass-card-title">
                <Server size={18} /> {editingAsset ? 'Edit Infrastructure Asset' : 'Register New Infrastructure Asset'}
              </h3>
              <button className="btn-logout" style={{ border: 'none' }} onClick={() => setIsModalOpen(false)}>
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '1rem' }}>
              {formError && (
                <div className="auth-error">
                  <AlertTriangle size={16} />
                  <span>{formError}</span>
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div className="input-group">
                  <label className="input-label">Hostname / Friendly Name *</label>
                  <input 
                    type="text" 
                    className="input-field" 
                    placeholder="e.g. WEB01 or DB-MASTER" 
                    value={formData.hostname}
                    onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
                    required
                  />
                </div>

                <div className="input-group">
                  <label className="input-label">IP Address / Target Domain *</label>
                  <input 
                    type="text" 
                    className="input-field" 
                    placeholder="e.g. 192.168.1.50 or host.local" 
                    value={formData.ip_address}
                    onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
                    required
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div className="input-group">
                  <label className="input-label">Criticality Rating</label>
                  <select 
                    className="input-field"
                    value={formData.criticality}
                    onChange={(e) => setFormData({ ...formData, criticality: e.target.value })}
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>

                <div className="input-group">
                  <label className="input-label">Owner / Responsible Team</label>
                  <input 
                    type="text" 
                    className="input-field" 
                    placeholder="e.g. DevOps / Security Team" 
                    value={formData.owner}
                    onChange={(e) => setFormData({ ...formData, owner: e.target.value })}
                  />
                </div>
              </div>

              <div className="input-group">
                <label className="input-label">Operating System (Optional)</label>
                <input 
                  type="text" 
                  className="input-field" 
                  placeholder="e.g. Ubuntu 22.04 LTS / Windows Server 2022" 
                  value={formData.operating_system}
                  onChange={(e) => setFormData({ ...formData, operating_system: e.target.value })}
                />
              </div>

              <div className="input-group">
                <label className="input-label">Description / Notes</label>
                <textarea 
                  className="input-field" 
                  rows={3} 
                  placeholder="Additional context, environment info, or notes..." 
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  style={{ resize: 'vertical' }}
                />
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
                <button type="button" className="btn btn-secondary" onClick={() => setIsModalOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={isSubmitting}>
                  {isSubmitting ? 'Saving Asset...' : editingAsset ? 'Update Asset' : 'Register Asset'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
