import { useEffect, useState } from 'react'
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from 'react-simple-maps'
import { MapPin, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'

const WORLD_GEOJSON = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'

export default function GlobalThreatMap({ token }) {
  const [points, setPoints] = useState([])
  const [source, setSource] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const load = async () => {
    setBusy(true)
    try {
      const response = await fetch('/api/v1/admin/threat-map', { headers: { Authorization: `Bearer ${token}` } })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`)
      setPoints(data.points || [])
      setSource(data.source || '')
      setError('')
    } catch (err) {
      setError(err.message)
      toast.error('Threat map unavailable', { description: err.message })
    } finally { setBusy(false) }
  }
  useEffect(() => { load() }, [token])
  return <section className="panel glass-panel admin-map-panel">
    <div className="panel-title"><div><p className="eyebrow">OBSERVED INFRASTRUCTURE</p><h2>Global Threat Map</h2></div><button className="button quiet small" onClick={load} disabled={busy}><RefreshCw size={14} className={busy ? 'spin-icon' : ''}/> Refresh</button></div>
    <div className="admin-map-wrap">
      <ComposableMap projection="geoMercator" projectionConfig={{ scale: 120 }} width={800} height={380}>
        <ZoomableGroup center={[0, 20]} zoom={1} minZoom={1} maxZoom={4}>
          <Geographies geography={WORLD_GEOJSON}>
            {({ geographies }) => geographies.map(geo => <Geography key={geo.rsmKey} geography={geo} fill="#17283d" stroke="#2a405b" strokeWidth={0.45} style={{ hover: { fill: '#203955', outline: 'none' }, pressed: { outline: 'none' }, default: { outline: 'none' } }}/>) }
          </Geographies>
          {points.map((point, index) => <Marker key={`${point.ip}-${index}`} coordinates={[point.longitude, point.latitude]}>
            <circle r={5} fill="#43d7ff" stroke="#b8f3ff" strokeWidth={1.5} className="map-marker-pulse"/>
            <title>{`${point.target} · ${[point.city, point.country].filter(Boolean).join(', ')} · ${point.ip}`}</title>
          </Marker>)}
        </ZoomableGroup>
      </ComposableMap>
      {!points.length && !busy && <div className="map-empty"><MapPin size={18}/><span>{error ? 'Location data unavailable' : 'No geolocated scan targets yet'}</span></div>}
    </div>
    <div className="map-legend"><span><i/> {points.length} geolocated public scan IP{points.length === 1 ? '' : 's'}</span><small>{source || 'Locations are estimated from public IP geolocation and do not represent attack origins.'}</small></div>
    {!!points.length && <div className="map-target-list">{points.slice(0, 6).map((point, index) => <div key={`${point.ip}-${index}`}><span className="map-target-dot"/><strong>{point.target}</strong><small>{[point.city, point.country].filter(Boolean).join(', ') || point.ip}</small></div>)}</div>}
  </section>
}
