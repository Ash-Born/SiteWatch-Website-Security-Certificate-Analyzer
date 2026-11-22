import { useEffect, useRef } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { Activity, ShieldCheck, Terminal, Wifi } from 'lucide-react'

/**
 * Full-screen scan overlay. Progress below 100% is an estimate while the one
 * real API request is pending; the parent should set 100 only on API success.
 */
export default function ScanningAnimation({ phase, progress, lines = [] }) {
  const logRef = useRef(null)
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [lines])

  return <motion.div className="scan-overlay" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: .2 }} role="dialog" aria-modal="true" aria-label="Website security assessment in progress">
    <motion.section className="scan-modal glass-panel" initial={{ opacity: 0, y: 18, scale: .97 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 10, scale: .98 }} transition={{ duration: .24 }}>
      <header className="scan-overlay-header"><div className="scan-brand"><span><ShieldCheck size={16}/></span><div><strong>SITEWATCH</strong><small>ACTIVE ASSESSMENT</small></div></div><div className="scan-live-badge"><i/> LIVE</div></header>
      <div className="advanced-radar" aria-label={`Estimated progress ${progress}%`}>
        <div className="radar-ring radar-ring-outer"/><div className="radar-ring radar-ring-middle"/><div className="radar-ring radar-ring-inner"/>
        <div className="radar-crosshair radar-crosshair-horizontal"/><div className="radar-crosshair radar-crosshair-vertical"/>
        <div className="radar-sweep-cone"/><div className="radar-sweep-line"/>
        <i className="radar-blip radar-blip-1"/><i className="radar-blip radar-blip-2"/><i className="radar-blip radar-blip-3"/><i className="radar-blip radar-blip-4"/><i className="radar-blip radar-blip-5"/>
        <div className="radar-core"><motion.strong key={progress} initial={{ opacity: .65, y: 2 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .16 }}>{progress}<small>%</small></motion.strong><span>{progress >= 100 ? 'COMPLETE' : 'SCANNING'}</span></div>
      </div>
      <div className="scan-title-row"><div><p className="eyebrow">LIVE SECURITY ANALYSIS</p><h2>Mapping target surface</h2></div><Activity className="scan-activity-icon" size={20}/></div>
      <div className="scan-active-phase"><span className="scan-phase-pulse"/>{phase}</div>
      <div className="scan-meter"><motion.i animate={{ width: `${Math.min(progress, 99)}%` }} transition={{ ease: 'linear', duration: .25 }}/></div>
      <div className="scan-meter-caption"><span>Estimated request progress</span><strong>{progress}%</strong></div>
      <div className="scan-terminal-window">
        <div className="scan-terminal-top"><span><Terminal size={13}/> LIVE TERMINAL</span><span><Wifi size={12}/> API REQUEST ACTIVE</span></div>
        <div className="scan-terminal-lines" ref={logRef} role="log" aria-live="polite" aria-relevant="additions text">
          {lines.map((line, index) => <div className={`scan-terminal-line log-${line.kind || 'info'}`} key={`${line.time}-${index}`}><time>{line.time}</time><span>{line.text}</span></div>)}
          <div className="scan-terminal-cursor"><i/>{phase}<b>_</b></div>
        </div>
      </div>
      <p className="scan-overlay-footnote">Progress is estimated while the live analyzer runs. Results appear only after the backend responds.</p>
    </motion.section>
  </motion.div>
}
