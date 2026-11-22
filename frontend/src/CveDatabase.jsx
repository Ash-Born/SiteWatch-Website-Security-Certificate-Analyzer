import React, { useState } from 'react';
import { Search, AlertTriangle, CheckCircle, ChevronDown, ChevronRight, Layers } from 'lucide-react';

const CveDatabase = ({ token }) => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [isSearching, setIsSearching] = useState(false);
  const [error, setError] = useState(null);
  const [expandedVulns, setExpandedVulns] = useState({});

  const searchCVEs = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;

    setIsSearching(true);
    setError(null);

    try {
      // The API doesn't strictly require JWT for this, but we pass it anyway if needed.
      const response = await fetch(`/api/v1/cve/search?query=${encodeURIComponent(query.trim())}`, {
        headers: token ? { 'Authorization': `Bearer ${token}` } : {}
      });

      if (!response.ok) {
        throw new Error('Failed to fetch CVE data from database.');
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsSearching(false);
    }
  };

  const getSeverityBadgeClass = (severity) => {
    if (!severity) return 'badge-info';
    const sev = severity.toLowerCase();
    if (sev === 'critical') return 'badge-critical';
    if (sev === 'high') return 'badge-high';
    if (sev === 'medium') return 'badge-medium';
    if (sev === 'low') return 'badge-low';
    return 'badge-info';
  };

  const toggleExpand = (id) => {
    setExpandedVulns(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', flexGrow: 1, height: '100%' }}>
      <div className="glass-card">
        <div className="glass-card-header">
          <h2 className="glass-card-title"><Search size={18} className="logo-icon" /> Real-Time CVE Intelligence</h2>
        </div>
        <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem', fontSize: '0.9rem' }}>
          Query the National Vulnerability Database (NVD) in real-time for the latest security flaws, exploits, and CVE details.
        </p>

        <form onSubmit={searchCVEs} style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end' }}>
          <div className="input-group" style={{ flexGrow: 1, marginBottom: 0 }}>
            <label className="input-label" htmlFor="cve-query">Search Query (Software, CVE ID, or Keyword)</label>
            <input 
              id="cve-query"
              className="input-field" 
              type="text" 
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="e.g., OpenSSH, Apache, CVE-2024-6387"
              disabled={isSearching}
              required
            />
          </div>
          <button 
            type="submit" 
            className={`btn btn-primary ${isSearching ? 'btn-pulse' : ''}`}
            disabled={isSearching || !query.trim()}
          >
            {isSearching ? 'Searching Database...' : 'Search CVEs'}
          </button>
        </form>
      </div>

      {error && (
        <div className="glass-card fade-in" style={{ borderLeft: '4px solid var(--severity-critical)' }}>
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
            <AlertTriangle className="badge-critical" style={{ borderRadius: '50%', padding: '2px' }} size={24} />
            <div>
              <h3 style={{ margin: '0 0 0.25rem', color: 'var(--severity-critical)', fontWeight: 600 }}>Search Failed</h3>
              <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>{error}</p>
            </div>
          </div>
        </div>
      )}

      {results.length > 0 ? (
        <div className="glass-card fade-in" style={{ flexGrow: 1, overflowY: 'auto' }}>
          <div className="glass-card-header">
            <h3 className="glass-card-title"><Layers size={18} /> Search Results ({results.length})</h3>
          </div>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {results.map((cve, i) => (
              <div 
                key={cve.cve_id + i} 
                className={`vuln-item ${cve.severity.toLowerCase() === 'critical' ? 'crit' : cve.severity.toLowerCase() === 'high' ? 'high' : cve.severity.toLowerCase() === 'medium' ? 'med' : 'low'}`}
                style={{ cursor: 'pointer', transition: 'all 0.2s' }}
                onClick={() => toggleExpand(cve.cve_id + i)}
              >
                <div className="vuln-header" style={{ alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <span className="vuln-id" style={{ fontSize: '1.1rem' }}>{cve.cve_id}</span>
                    <span style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>• {cve.software}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <span className={`badge ${getSeverityBadgeClass(cve.severity)}`} style={{ padding: '0.3rem 0.6rem' }}>
                      {cve.severity} (CVSS: {cve.cvss_score.toFixed(1)})
                    </span>
                    {expandedVulns[cve.cve_id + i] ? <ChevronDown size={20} color="var(--text-secondary)" /> : <ChevronRight size={20} color="var(--text-secondary)" />}
                  </div>
                </div>
                
                {expandedVulns[cve.cve_id + i] && (
                  <div className="fade-in" style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                    <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.9rem', color: 'var(--text-primary)' }}>Description</h4>
                    <div className="vuln-desc" style={{ marginBottom: '1rem', fontSize: '0.95rem', lineHeight: '1.6' }}>
                      {cve.description}
                    </div>
                    
                    {cve.remediation && (
                      <div className="vuln-remediation">
                        <div className="vuln-remediation-title">Suggested Remediation</div>
                        {cve.remediation}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ) : (
        !isSearching && query && !error && (
          <div className="glass-card fade-in" style={{ textAlign: 'center', padding: '4rem 2rem' }}>
            <CheckCircle size={48} style={{ color: 'var(--severity-info)', marginBottom: '1rem', filter: 'drop-shadow(0 0 10px rgba(59, 130, 246, 0.3))' }} />
            <h3 style={{ margin: '0 0 0.5rem', fontSize: '1.2rem' }}>No Vulnerabilities Found</h3>
            <p style={{ color: 'var(--text-secondary)' }}>No CVEs matched your query "{query}".</p>
          </div>
        )
      )}
    </div>
  );
};

export default CveDatabase;
