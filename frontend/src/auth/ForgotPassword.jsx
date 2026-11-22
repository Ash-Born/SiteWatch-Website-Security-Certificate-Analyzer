import { useState } from 'react'
import { Link, useSearchParams, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { ArrowLeft, ArrowRight, Eye, EyeOff, KeyRound, Mail } from 'lucide-react'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [sent, setSent] = useState(false)
  const submit = async event => {
    event.preventDefault(); setBusy(true); setError('')
    try {
      const response = await fetch('/api/v1/auth/forgot-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email.trim().toLowerCase() }) })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(data.detail || 'Could not create a reset link.')
      setSent(true)
    } catch (cause) { setError(cause.message) } finally { setBusy(false) }
  }
  return <motion.section className="auth-panel glass-panel auth-modern" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .28 }}>
    <div className="brand-mark"><Mail size={21}/></div><p className="eyebrow">ACCOUNT RECOVERY</p><h1>Forgot your password?</h1>
    <p className="muted">Enter the email address associated with your account. If it exists, a reset link will be created.</p>
    {error && <div className="notice error" role="alert">{error}</div>}
    {sent ? <div className="notice success" role="status">If an account exists for that email, a reset link has been created. In this development setup, the link is printed to the backend console.</div> : <form className="auth-form" onSubmit={submit}><label>Email address<input type="email" autoComplete="email" value={email} onChange={event => setEmail(event.target.value)} required maxLength={254} placeholder="you@company.com"/></label><button className="button primary full" disabled={busy}>{busy ? 'Creating link…' : 'Create reset link'}<ArrowRight size={16}/></button></form>}
    <p className="auth-switch"><Link to="/login"><ArrowLeft size={14}/> Back to sign in</Link></p>
  </motion.section>
}

export function ResetPassword() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const token = params.get('token') || ''
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const passwordValid = password.length >= 8 && /[0-9]|[^A-Za-z0-9]/.test(password)
  const submit = async event => {
    event.preventDefault(); setError('')
    if (!token) { setError('This reset link does not contain a token. Request a new link.'); return }
    if (!passwordValid) { setError('Use at least 8 characters and include a number or special character.'); return }
    if (password !== confirm) { setError('Passwords do not match.'); return }
    setBusy(true)
    try {
      const response = await fetch('/api/v1/auth/reset-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, new_password: password }) })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(data.detail || 'Could not reset password.')
      setSuccess(true)
      window.setTimeout(() => navigate('/login', { replace: true, state: { message: 'Password reset successfully. Sign in with your new password.' } }), 1200)
    } catch (cause) { setError(cause.message) } finally { setBusy(false) }
  }
  return <motion.section className="auth-panel glass-panel auth-modern" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .28 }}>
    <div className="brand-mark"><KeyRound size={21}/></div><p className="eyebrow">ACCOUNT RECOVERY</p><h1>Set a new password</h1>
    <p className="muted">Reset links expire after 20 minutes and can only be used once.</p>
    {error && <div className="notice error" role="alert">{error}</div>}
    {success && <div className="notice success" role="status">Password updated. Redirecting to sign in…</div>}
    <form className="auth-form" onSubmit={submit}>
      <label>New password<span className="auth-password-field"><input type={showPassword ? 'text' : 'password'} autoComplete="new-password" value={password} onChange={event => setPassword(event.target.value)} required minLength={8} maxLength={72} placeholder="8+ characters"/><button type="button" className="auth-password-toggle" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff size={16}/> : <Eye size={16}/>}</button></span></label>
      <label>Confirm new password<input type={showPassword ? 'text' : 'password'} autoComplete="new-password" value={confirm} onChange={event => setConfirm(event.target.value)} required minLength={8} maxLength={72} placeholder="Re-enter password"/></label>
      <p className={passwordValid ? 'auth-field-success' : 'auth-password-hint'}>At least 8 characters and one number or special character.</p>
      <button className="button primary full" disabled={busy || success}>{busy ? 'Updating password…' : 'Reset password'}<ArrowRight size={16}/></button>
    </form>
    <p className="auth-switch"><Link to="/login"><ArrowLeft size={14}/> Back to sign in</Link></p>
  </motion.section>
}
