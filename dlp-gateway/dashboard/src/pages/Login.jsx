import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { login } from '../api'

export default function Login() {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const resp = await login(username, password)
      localStorage.setItem('dlp_token', resp.data.access_token)
      localStorage.setItem('dlp_role',  resp.data.role || 'admin')
      navigate('/', { replace: true })
    } catch (err) {
      setError(
        err?.response?.data?.detail || 'Login failed. Check username and password.'
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-tw-bg flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="h-12 w-12 rounded-full bg-tw-primary flex items-center justify-center shadow-card mb-3">
            <span className="text-white text-2xl font-bold">G</span>
          </div>
          <h1 className="text-xl font-bold text-tw-text">Guardrail DLP</h1>
          <p className="text-xs text-tw-textSoft mt-1">Admin Control Plane</p>
        </div>

        {/* Card */}
        <div className="bg-tw-card border border-tw-border rounded-xl2 shadow-card p-6">
          <h2 className="text-sm font-semibold text-tw-text mb-4">Sign in to your account</h2>

          {error && (
            <div className="mb-4 text-xs text-tw-danger bg-red-50 border border-red-200 rounded-lg px-3 py-2">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs text-tw-textSoft mb-1">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full border border-tw-border rounded-xl px-3 py-2 text-sm text-tw-text
                           bg-tw-bg focus:outline-none focus:border-tw-primary
                           transition-colors duration-150"
                placeholder="admin"
              />
            </div>

            <div>
              <label className="block text-xs text-tw-textSoft mb-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full border border-tw-border rounded-xl px-3 py-2 text-sm text-tw-text
                           bg-tw-bg focus:outline-none focus:border-tw-primary
                           transition-colors duration-150"
                placeholder="Enter your password"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-tw-primary text-white text-sm font-semibold py-2.5
                         rounded-xl hover:bg-blue-500 active:scale-[0.98]
                         transition-all duration-150 disabled:opacity-60"
            >
              {loading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        </div>

        <p className="text-center text-xs text-tw-textSoft mt-4">
          Secured by Guardrail DLP — DPDP Compliant
        </p>
      </div>
    </div>
  )
}
