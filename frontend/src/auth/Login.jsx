import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { ArrowRight, Eye, EyeOff, LockKeyhole, Shield } from 'lucide-react'

export default function Login({ onAuth }) {
  const navigate = useNavigate()
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message] = useState(() => window.history.state?.usr?.message || '')

  const submit = async event => {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: identifier.trim(), password }),
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(data.detail || 'Unable to sign in.')
      onAuth(data)
      navigate('/', { replace: true })
    } catch (cause) {
      setError(cause.message)
    } finally {
      setBusy(false)
    }
  }

  return <motion.section className="auth-panel glass-panel auth-modern" initial={{ opacity:  0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .28 }}>
    <div className="brand-mark"><Shield size={21}/></div>
    <p className="eyebrow">SITEWATCH · SECURITY OPERATIONS</p>
    <h1>Welcome back</h1>
    <p className="muted">Sign in to your security command center.</p>
    {message && <div className="notice success">{message}</div>}
    {error && <div className="notice error" role="alert">{error}</div>}
    <form className="auth-form" onSubmit={submit}>
      <label>Email or username<input autoComplete="username" value={identifier} onChange={event => setIdentifier(event.target.value)} required maxLength={254} placeholder="you@company.com"/></label>
      <label>Password<span className="auth-password-field"><input type={showPassword ? 'text' : 'password'} autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required maxLength={128} placeholder="Enter your password"/><button type="button" className="auth-password-toggle" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff size={16}/> : <Eye size={16}/>}</button></span></label>
      <div className="auth-forgot-row"><span><LockKeyhole size={13}/> Protected account</span><Link to="/forgot-password">Forgot password?</Link></div>
      <button className="button primary full" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}<ArrowRight size={16}/></button>
    </form>
    <p className="auth-switch">New to SiteWatch? <Link to="/register">Create an account</Link></p>
  </motion.section>
}
