import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  RiShieldFlashLine, RiMailLine, RiLockPasswordLine,
  RiEyeLine, RiEyeOffLine, RiArrowRightLine, RiUserLine, RiShieldUserLine,
} from 'react-icons/ri'

const DEMO_CREDS = {
  admin:    { email: 'admin@aegisai.in',    password: 'admin123',    role: 'admin',    name: 'Arjun Mehta',    title: 'Super Admin'    },
  employee: { email: 'analyst@aegisai.in',  password: 'analyst123',  role: 'employee', name: 'Analyst Kumar',  title: 'Security Analyst' },
}

export default function Login({ onLogin }) {
  const [email, setEmail]       = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw]     = useState(false)
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)
  const [tab, setTab]           = useState('employee') // 'admin' | 'employee'

  const handleLogin = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    await new Promise(r => setTimeout(r, 600))
    const cred = DEMO_CREDS[tab]
    if (email === cred.email && password === cred.password) {
      onLogin({ role: cred.role, name: cred.name, title: cred.title })
    } else {
      setError('Invalid credentials. Check the demo hints below.')
    }
    setLoading(false)
  }

  const fillDemo = () => {
    const cred = DEMO_CREDS[tab]
    setEmail(cred.email)
    setPassword(cred.password)
    setError('')
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-sky-50 to-slate-100 flex items-center justify-center p-4">
      {/* Background decoration */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-96 h-96 rounded-full bg-sky-200/30 blur-3xl" />
        <div className="absolute -bottom-40 -left-40 w-96 h-96 rounded-full bg-sky-300/20 blur-3xl" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 24, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.4, ease: [0.34, 1.1, 0.64, 1] }}
        className="w-full max-w-md relative z-10"
      >
        {/* Card */}
        <div className="bg-white rounded-2xl shadow-[0_8px_40px_rgba(0,0,0,0.10)] border border-slate-100 overflow-hidden">
          {/* Header */}
          <div className="px-8 pt-8 pb-6 text-center">
            <div className="w-14 h-14 rounded-2xl bg-sky-500 flex items-center justify-center mx-auto mb-4 shadow-lg shadow-sky-200">
              <RiShieldFlashLine className="text-white text-2xl" />
            </div>
            <h1 className="text-[22px] font-bold text-gray-900 tracking-tight">Welcome to AegisAI</h1>
            <p className="text-[13px] text-gray-400 mt-1">Enterprise AI Security Platform</p>
          </div>

          {/* Role tab switcher */}
          <div className="flex mx-8 mb-6 bg-slate-50 rounded-xl p-1 border border-slate-100">
            <button
              onClick={() => { setTab('employee'); setEmail(''); setPassword(''); setError('') }}
              className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-[13px] font-semibold transition-all ${
                tab === 'employee'
                  ? 'bg-white text-sky-600 shadow-sm border border-slate-200'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              <RiUserLine className="text-base" />
              Employee
            </button>
            <button
              onClick={() => { setTab('admin'); setEmail(''); setPassword(''); setError('') }}
              className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-[13px] font-semibold transition-all ${
                tab === 'admin'
                  ? 'bg-white text-sky-600 shadow-sm border border-slate-200'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              <RiShieldUserLine className="text-base" />
              Admin
            </button>
          </div>

          {/* Form */}
          <form onSubmit={handleLogin} className="px-8 pb-8 space-y-4">
            {/* Email */}
            <div>
              <label className="block text-[12px] font-semibold text-gray-600 mb-1.5">Email address</label>
              <div className="relative">
                <RiMailLine className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400 text-base" />
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder={`${tab}@aegisai.in`}
                  className="w-full pl-10 pr-4 py-3 border border-slate-200 rounded-xl text-[13px] text-gray-900 font-medium placeholder-gray-300 outline-none focus:border-sky-400 focus:ring-3 focus:ring-sky-100 transition-all bg-white"
                  required
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block text-[12px] font-semibold text-gray-600 mb-1.5">Password</label>
              <div className="relative">
                <RiLockPasswordLine className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400 text-base" />
                <input
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="w-full pl-10 pr-10 py-3 border border-slate-200 rounded-xl text-[13px] text-gray-900 font-medium placeholder-gray-300 outline-none focus:border-sky-400 focus:ring-3 focus:ring-sky-100 transition-all bg-white"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors"
                >
                  {showPw ? <RiEyeOffLine /> : <RiEyeLine />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <motion.p
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                className="text-[12px] font-medium text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2.5"
              >
                ⚠ {error}
              </motion.p>
            )}

            {/* Forgot */}
            <div className="flex justify-end">
              <button type="button" className="text-[12px] text-sky-500 hover:text-sky-700 font-medium transition-colors">
                Forgot password?
              </button>
            </div>

            {/* Submit */}
            <motion.button
              type="submit"
              disabled={loading}
              whileHover={!loading ? { scale: 1.01 } : {}}
              whileTap={!loading ? { scale: 0.98 } : {}}
              className="w-full py-3 bg-sky-500 hover:bg-sky-600 disabled:bg-sky-300 text-white font-semibold rounded-xl text-[14px] flex items-center justify-center gap-2 transition-all shadow-sm shadow-sky-200"
            >
              {loading ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Signing in…
                </>
              ) : (
                <>
                  Sign in as {tab === 'admin' ? 'Admin' : 'Employee'}
                  <RiArrowRightLine />
                </>
              )}
            </motion.button>

            {/* Demo hint */}
            <div className="bg-sky-50 border border-sky-100 rounded-xl p-3">
              <p className="text-[11px] font-semibold text-sky-700 mb-1.5">
                🔑 Demo {tab === 'admin' ? 'Admin' : 'Employee'} credentials
              </p>
              <div className="flex items-center justify-between">
                <div className="text-[11px] text-sky-600 font-mono space-y-0.5">
                  <p>Email: {DEMO_CREDS[tab].email}</p>
                  <p>Pass:  {DEMO_CREDS[tab].password}</p>
                </div>
                <button
                  type="button"
                  onClick={fillDemo}
                  className="text-[11px] font-semibold text-sky-600 hover:text-sky-800 bg-white border border-sky-200 hover:border-sky-400 px-2.5 py-1.5 rounded-lg transition-all"
                >
                  Auto-fill
                </button>
              </div>
            </div>
          </form>
        </div>

        {/* Footer */}
        <p className="text-center text-[11px] text-gray-400 mt-5">
          AegisAI Platform · Enterprise AI Security Suite · v2.1.0
        </p>
      </motion.div>
    </div>
  )
}
