import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { ArrowRight, Eye, EyeOff, ShieldCheck } from 'lucide-react'

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/
const BLOCKED_DOMAINS = ['example.com', 'test.com', 'mailinator.com']

export default function Register() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ full_name: '', username: '', email: '', password: '', confirm_password: '' })
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const emailError = useMemo(() => {
    if (!form.email) return ''
    if (!EMAIL_RE.test(form.email.trim())) return 'Enter a valid email address.'
    const domain = form.email.trim().toLowerCase().split('@').pop()
    return BLOCKED_DOMAINS.some(blocked => domain === blocked || domain.endsWith(`.${blocked}`)) ? 'Use a non-temporary email address.' : ''
  }, [form.email])
  const passwordError = form.password && (form.password.length < 8 || !/[0-9]|[^A-Za-z0-9]/.test(form.password))
    ? 'Use at least 8 characters and include a number or special character.' : ''
  const confirmError = form.confirm_password && form.password !== form.confirm_password ? 'Passwords do not match.' : ''
  const update = event => setForm(current => ({ ...current, [event.target.name]: event.target.value }))

  const submit = async event => {
    event.preventDefault()
    setSubmitted(true)
    setError('')
    if (emailError || passwordError || confirmError) return
    setBusy(true)
    try {
      const response = await fetch('/api/v1/auth/register', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ full_name: form.full_name.trim(), username: form.username.trim(), email: form.email.trim().toLowerCase(), password: form.password }),
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(data.detail || 'Unable to create account.')
      navigate('/login', { replace: true, state: { message: 'Account created. Sign in to continue. Email verification is not enabled yet.' } })
    } catch (cause) {
      setError(cause.message)
    } finally {
      setBusy(false)
    }
  }

  return <motion.section className="auth-panel glass-panel auth-modern auth-register" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .28 }}>
    <div className="brand-mark"><ShieldCheck size={21}/></div>
    <p className="eyebrow">SITEWATCH · ACCOUNT ENROLLMENT</p>
    <h1>Create your account</h1>
    <p className="muted">Set up secure access to live website assessments.</p>
    {error && <div className="notice error" role="alert">{error}</div>}
    <form className="auth-form" onSubmit={submit}>
      <label>Full name<input name="full_name" autoComplete="name" value={form.full_name} onChange={update} required maxLength={120} placeholder="Your name"/></label>
      <div className="auth-register-row"><label>Username<input name="username" autoComplete="username" value={form.username} onChange={update} required minLength={3} maxLength={30} pattern="[A-Za-z0-9_.-]+" placeholder="analyst"/></label><label>Email address<input type="email" name="email" autoComplete="email" value={form.email} onChange={update} required maxLength={254} placeholder="you@company.com" aria-invalid={Boolean(emailError)}/>{emailError && <small className="auth-field-error">{emailError}</small>}</label></div>
      <label>Password<span className="auth-password-field"><input type={showPassword ? 'text' : 'password'} name="password" autoComplete="new-password" value={form.password} onChange={update} required minLength={8} maxLength={72} placeholder="8+ characters" aria-invalid={Boolean(passwordError)}/><button type="button" className="auth-password-toggle" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff size={16}/> : <Eye size={16}/>}</button></span>{passwordError && <small className="auth-field-error">{passwordError}</small>}</label>
      <label>Confirm password<input type={showPassword ? 'text' : 'password'} name="confirm_password" autoComplete="new-password" value={form.confirm_password} onChange={update} required minLength={8} maxLength={72} placeholder="Re-enter your password" aria-invalid={Boolean(confirmError)}/>{confirmError && <small className="auth-field-error">{confirmError}</small>}{submitted && !confirmError && form.confirm_password && <small className="auth-field-success">Passwords match.</small>}</label>
      <button className="button primary full" disabled={busy || Boolean(emailError || passwordError || confirmError)}>{busy ? 'Creating account…' : 'Create account'}<ArrowRight size={16}/></button>
    </form>
    <p className="auth-switch">Already registered? <Link to="/login">Sign in</Link></p>
  </motion.section>
}
