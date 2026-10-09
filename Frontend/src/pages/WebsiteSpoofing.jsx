import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiSearchLine, RiShieldCheckLine, RiAlertLine, RiCloseCircleLine,
  RiCheckboxCircleLine, RiLoader4Line, RiLockLine, RiGlobalLine,
  RiFileTextLine, RiCodeLine, RiShieldLine, RiRobot2Line,
  RiDownloadLine, RiRefreshLine, RiInformationLine, RiArrowDownSLine,
  RiArrowUpSLine, RiCalendarLine, RiMessage2Line, RiCheckLine, RiCloseLine,
} from 'react-icons/ri'
import { PageWrapper } from '../components/ui'

// ── Helpers ────────────────────────────────────────────────────────────────────
const SCAN_STEPS = [
  { id: 'ml',     label: 'XGBoost AI Model',       icon: RiRobot2Line  },
  { id: 'ssl',    label: 'SSL Certificate Check',   icon: RiLockLine    },
  { id: 'whois',  label: 'WHOIS Domain Lookup',     icon: RiGlobalLine  },
  { id: 'cookie', label: 'Cookie Security Scan',    icon: RiShieldLine  },
  { id: 'html',   label: 'HTML Content Analysis',   icon: RiFileTextLine},
  { id: 'risk',   label: 'Risk Score Calculation',  icon: RiAlertLine   },
]

function verdictCfg(verdict) {
  if (verdict === 'DANGEROUS')  return { color: 'text-red-600',    bg: 'bg-red-50',    border: 'border-red-200',    dot: 'bg-red-500',    ring: '#DC2626', icon: '🚨', label: 'Dangerous'  }
  if (verdict === 'SUSPICIOUS') return { color: 'text-amber-600',  bg: 'bg-amber-50',  border: 'border-amber-200',  dot: 'bg-amber-500',  ring: '#D97706', icon: '⚠️', label: 'Suspicious' }
  return                               { color: 'text-emerald-600', bg: 'bg-emerald-50', border: 'border-emerald-200', dot: 'bg-emerald-500', ring: '#059669', icon: '✅', label: 'Safe'      }
}

function StatusPill({ ok, okLabel = 'VALID', badLabel = 'INVALID', warnColor = false }) {
  if (ok) return <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">{okLabel}</span>
  return <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold ${warnColor ? 'bg-amber-50 text-amber-700 border border-amber-200' : 'bg-red-50 text-red-700 border border-red-200'}`}>{badLabel}</span>
}

function CheckRow({ label, ok, warn, okText, badText }) {
  const icon = ok
    ? <RiCheckboxCircleLine className="text-emerald-500 text-base flex-shrink-0" />
    : warn
      ? <RiAlertLine className="text-amber-500 text-base flex-shrink-0" />
      : <RiCloseCircleLine className="text-red-500 text-base flex-shrink-0" />
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-slate-50 last:border-none">
      <span className="text-[12px] text-slate-500 font-medium">{label}</span>
      <div className="flex items-center gap-1.5">
        {icon}
        <span className={`text-[12px] font-semibold font-mono ${ok ? 'text-emerald-600' : warn ? 'text-amber-600' : 'text-red-600'}`}>
          {ok ? (okText || 'Clean') : (badText || 'Detected')}
        </span>
      </div>
    </div>
  )
}

function DetailCard({ icon: Icon, iconBg, title, subtitle, badge, children, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay }}
      whileHover={{ y: -2, boxShadow: '0 8px 32px rgba(0,0,0,0.08)' }}
      className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden"
    >
      <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-50 bg-slate-50/60">
        <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${iconBg}`}>
          <Icon className="text-[17px]" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-[13px] font-bold text-slate-800">{title}</p>
          {subtitle && <p className="text-[11px] text-slate-400 mt-0.5">{subtitle}</p>}
        </div>
        {badge}
      </div>
      <div className="px-5 py-4">{children}</div>
    </motion.div>
  )
}

// ── Loading Scan State ─────────────────────────────────────────────────────────
function ScanLoader({ step }) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.97 }}
      animate={{ opacity: 1, scale: 1 }}
      className="bg-white rounded-2xl border border-slate-100 shadow-sm p-8 text-center"
    >
      <div className="relative w-16 h-16 mx-auto mb-5">
        <svg className="w-16 h-16 -rotate-90" viewBox="0 0 64 64">
          <circle cx="32" cy="32" r="26" fill="none" stroke="#E2E8F0" strokeWidth="5" />
          <motion.circle
            cx="32" cy="32" r="26" fill="none"
            stroke="#3B82F6" strokeWidth="5" strokeLinecap="round"
            strokeDasharray={163}
            animate={{ strokeDashoffset: [163, 0] }}
            transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center text-2xl">🛡️</div>
      </div>
      <p className="text-[15px] font-bold text-slate-800 mb-1">Running Full Security Analysis</p>
      <p className="text-[12px] text-slate-400 mb-6">6 checks running in parallel…</p>
      <div className="inline-flex flex-col gap-2.5 text-left">
        {SCAN_STEPS.map((s, i) => {
          const done   = i < step
          const active = i === step
          return (
            <div key={s.id} className={`flex items-center gap-2.5 text-[12px] font-medium transition-colors duration-300 ${done ? 'text-emerald-600' : active ? 'text-blue-600' : 'text-slate-300'}`}>
              <motion.div
                className={`w-2 h-2 rounded-full flex-shrink-0 ${done ? 'bg-emerald-500' : active ? 'bg-blue-500' : 'bg-slate-200'}`}
                animate={active ? { scale: [1, 1.4, 1] } : {}}
                transition={{ duration: 0.8, repeat: Infinity }}
              />
              <s.icon className="text-[13px]" />
              {s.label}
            </div>
          )
        })}
      </div>
    </motion.div>
  )
}

// ── Trust Score Ring ───────────────────────────────────────────────────────────
function TrustRing({ riskScore, verdict }) {
  const trustScore = Math.round((1 - riskScore) * 100)
  const cfg  = verdictCfg(verdict)
  const circ = 2 * Math.PI * 36
  const off  = circ - (trustScore / 100) * circ
  return (
    <div className="flex flex-col items-center gap-1.5">
      <div className="relative w-20 h-20">
        <svg viewBox="0 0 84 84" width="80" height="80" className="-rotate-90">
          <circle cx="42" cy="42" r="36" fill="none" stroke="#F1F5F9" strokeWidth="7" />
          <motion.circle
            cx="42" cy="42" r="36" fill="none"
            stroke={cfg.ring} strokeWidth="7" strokeLinecap="round"
            strokeDasharray={circ}
            initial={{ strokeDashoffset: circ }}
            animate={{ strokeDashoffset: off }}
            transition={{ duration: 1.4, ease: [0.34, 1.2, 0.64, 1] }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-[19px] font-black leading-none ${cfg.color}`}>{trustScore}</span>
          <span className="text-[9px] text-slate-400 font-semibold uppercase tracking-wide">Trust</span>
        </div>
      </div>
      <span className={`text-[11px] font-bold ${cfg.color}`}>{cfg.label}</span>
    </div>
  )
}

// ── XAI Summary Parser + Display ──────────────────────────────────────────────
function parseMLSummary(summary) {
  if (!summary) return null

  // Extract number of signatures
  const sigMatch = summary.match(/analyzed\s+(\d+)\s+signature/i)
  const sigCount = sigMatch ? sigMatch[1] : '27'

  // Extract classification result and label
  const classMatch = summary.match(/Classification Result:\s*([\w\s]+?)\s*\(([^)]+)\)/i)
  const classResult = classMatch ? classMatch[1].trim() : null
  const classLabel  = classMatch ? classMatch[2].trim() : null

  // Extract confidence
  const confMatch = summary.match(/Confidence Level:\s*([\d.]+%?)/i)
  const confidence = confMatch ? confMatch[1].trim() : null

  // Extract risk / alert patterns (comma-separated after "indicating")
  const riskMatch = summary.match(/Found patterns? indicating\s+([^.]+)/i)
  const riskPatterns = riskMatch
    ? riskMatch[1].split(',').map(s => s.trim()).filter(Boolean)
    : []

  // Extract safe signatures (comma-separated after "Safe Signatures Detected:")
  const safeMatch = summary.match(/Safe Signatures? Detected:\s*([^.]+)/i)
  const safeItems = safeMatch
    ? safeMatch[1].split(',').map(s => s.trim()).filter(Boolean)
    : []

  return { sigCount, classResult, classLabel, confidence, riskPatterns, safeItems }
}

function XAIExplanation({ summary, mlPct, mlLabel, mlIsPhish, xaiOpen, setXaiOpen }) {
  const parsed = parseMLSummary(summary)

  return (
    <div>
      <button
        onClick={() => setXaiOpen(v => !v)}
        className="flex items-center gap-2 text-[12px] font-semibold text-blue-600 hover:text-blue-700 transition-colors"
      >
        <RiInformationLine className="text-[15px]" />
        AI Explanation (XAI · Feature Analysis)
        {xaiOpen ? <RiArrowUpSLine /> : <RiArrowDownSLine />}
      </button>
      <AnimatePresence>
        {xaiOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="overflow-hidden"
          >
            <div className="mt-3 rounded-xl border border-slate-100 overflow-hidden text-[12px]">

              {/* Header row */}
              <div className="flex items-center gap-3 px-4 py-3 bg-slate-50 border-b border-slate-100">
                <div className="w-8 h-8 rounded-lg bg-blue-100 flex items-center justify-center flex-shrink-0">
                  <RiRobot2Line className="text-blue-600 text-[16px]" />
                </div>
                <div>
                  <p className="font-bold text-slate-800 text-[13px]">PhishGuard XGBoost Engine</p>
                  <p className="text-slate-400 text-[11px]">
                    Analyzed <strong className="text-slate-600">{parsed?.sigCount ?? '27'} signatures</strong> across this URL
                  </p>
                </div>
              </div>

              <div className="p-4 space-y-4 bg-white">

                {/* Classification Result */}
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2">Classification Result</p>
                  <div className="flex items-center gap-3 p-3 rounded-xl bg-slate-50 border border-slate-100">
                    <span className="text-xl">{mlIsPhish ? '🚨' : '✅'}</span>
                    <div>
                      <p className={`font-black text-[15px] ${mlIsPhish ? 'text-red-600' : 'text-emerald-600'}`}>
                        {parsed?.classResult ?? (mlIsPhish ? 'PHISHING' : 'SAFE')}
                        {parsed?.classLabel && (
                          <span className="text-[11px] font-medium text-slate-400 ml-2">({parsed.classLabel})</span>
                        )}
                      </p>
                      {parsed?.confidence && (
                        <p className="text-[11px] text-slate-400 mt-0.5">
                          Confidence Level: <span className="font-bold text-slate-600">{parsed.confidence}</span>
                        </p>
                      )}
                    </div>
                    {/* Mini bar */}
                    <div className="flex-1 ml-2">
                      <div className="h-1.5 bg-slate-200 rounded-full overflow-hidden">
                        <motion.div
                          className={`h-full rounded-full ${mlIsPhish ? 'bg-red-500' : 'bg-emerald-500'}`}
                          initial={{ width: 0 }}
                          animate={{ width: `${mlPct}%` }}
                          transition={{ duration: 1, ease: [0.34, 1.2, 0.64, 1] }}
                        />
                      </div>
                      <p className="text-[10px] text-slate-400 mt-0.5 text-right">{mlPct.toFixed(1)}% phishing probability</p>
                    </div>
                  </div>
                </div>

                {/* Risk Patterns */}
                {(parsed?.riskPatterns?.length > 0) && (
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-widest text-amber-500 mb-2 flex items-center gap-1">
                      <RiAlertLine /> Security Alert Summary — Patterns Detected
                    </p>
                    <ul className="space-y-1.5">
                      {parsed.riskPatterns.map((p, i) => (
                        <motion.li
                          key={i}
                          initial={{ opacity: 0, x: -8 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.06 }}
                          className="flex items-center gap-2 p-2.5 rounded-lg bg-amber-50 border border-amber-100"
                        >
                          <span className="w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0" />
                          <span className="text-amber-800 font-medium">{p}</span>
                        </motion.li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Safe Signatures */}
                {(parsed?.safeItems?.length > 0) && (
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-widest text-emerald-600 mb-2 flex items-center gap-1">
                      <RiShieldCheckLine /> Safe Signatures Detected
                    </p>
                    <ul className="space-y-1.5">
                      {parsed.safeItems.map((item, i) => (
                        <motion.li
                          key={i}
                          initial={{ opacity: 0, x: -8 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.06 }}
                          className="flex items-center gap-2 p-2.5 rounded-lg bg-emerald-50 border border-emerald-100"
                        >
                          <RiCheckboxCircleLine className="text-emerald-500 flex-shrink-0 text-[14px]" />
                          <span className="text-emerald-800 font-medium">{item}</span>
                        </motion.li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Fallback if no parsed data */}
                {!parsed && (
                  <p className="text-slate-500 leading-relaxed">
                    The XGBoost model analysed <strong>27 URL-derived features</strong> including domain length,
                    special character counts, subdomain depth, TLD reputation, and HTTPS usage.
                    Phishing probability: <strong>{mlPct.toFixed(1)}%</strong> — classified as <strong>{mlLabel}</strong>.
                  </p>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}


// ── Feedback Section ───────────────────────────────────────────────────────────
function FeedbackSection({ scanId, url, modelVerdict }) {
  const [step,      setStep]      = useState('ask')   // 'ask' | 'correct' | 'wrong' | 'done' | 'saving'
  const [verdict,   setVerdict]   = useState(modelVerdict)
  const [notes,     setNotes]     = useState('')
  const [error,     setError]     = useState(null)

  const submit = async (correctVerdict) => {
    setStep('saving')
    setError(null)
    try {
      const res = await fetch('/api/website-spoofing/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_id:         scanId,
          url:             url,
          model_verdict:   modelVerdict,
          correct_verdict: correctVerdict,
          reviewer_id:     'user',
          notes:           notes,
        }),
      })
      if (res.ok) {
        const data = await res.json()
        setStep('done')
        setVerdict(correctVerdict)
        return data
      } else {
        setError('Feedback submission failed. Please try again.')
        setStep('wrong')
      }
    } catch (e) {
      setError('Could not reach the server. Feedback not saved.')
      setStep('wrong')
    }
  }

  const VERDICTS = ['SAFE', 'SUSPICIOUS', 'DANGEROUS']

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.6 }}
      className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden mb-4"
    >
      <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-50 bg-slate-50/60">
        <div className="w-9 h-9 rounded-xl bg-sky-50 flex items-center justify-center flex-shrink-0">
          <RiMessage2Line className="text-sky-500 text-[17px]" />
        </div>
        <div>
          <p className="text-[13px] font-bold text-slate-800">Was this result correct?</p>
          <p className="text-[11px] text-slate-400">Your feedback trains the model to improve future detections</p>
        </div>
      </div>

      <div className="px-5 py-4">
        <AnimatePresence mode="wait">

          {/* Step: ask */}
          {step === 'ask' && (
            <motion.div key="ask" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="flex items-center gap-3"
            >
              <p className="text-[13px] text-slate-600 flex-1">
                Model verdict: <span className={`font-bold ${modelVerdict === 'DANGEROUS' ? 'text-red-600' : modelVerdict === 'SUSPICIOUS' ? 'text-amber-600' : 'text-emerald-600'}`}>{modelVerdict}</span>
              </p>
              <button
                onClick={() => submit(modelVerdict)}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 text-[12px] font-semibold hover:bg-emerald-100 transition-all"
              >
                <RiCheckLine /> Yes, correct
              </button>
              <button
                onClick={() => setStep('wrong')}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-red-50 border border-red-200 text-red-700 text-[12px] font-semibold hover:bg-red-100 transition-all"
              >
                <RiCloseLine /> No, it's wrong
              </button>
            </motion.div>
          )}

          {/* Step: wrong — select correct verdict */}
          {step === 'wrong' && (
            <motion.div key="wrong" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
              className="space-y-4"
            >
              <p className="text-[12px] text-slate-600 font-medium">What is the correct verdict for this URL?</p>
              <div className="flex gap-2">
                {VERDICTS.map(v => (
                  <button
                    key={v}
                    onClick={() => setVerdict(v)}
                    className={`flex-1 py-2.5 rounded-xl text-[12px] font-semibold border-2 transition-all ${
                      verdict === v
                        ? v === 'DANGEROUS' ? 'border-red-400 bg-red-50 text-red-700'
                          : v === 'SUSPICIOUS' ? 'border-amber-400 bg-amber-50 text-amber-700'
                          : 'border-emerald-400 bg-emerald-50 text-emerald-700'
                        : 'border-slate-100 text-slate-400 hover:border-slate-200'
                    }`}
                  >
                    {v === 'DANGEROUS' ? '🚨 Dangerous' : v === 'SUSPICIOUS' ? '⚠️ Suspicious' : '✅ Safe'}
                  </button>
                ))}
              </div>
              <div>
                <label className="text-[12px] font-semibold text-slate-500 mb-1.5 block">Notes (optional)</label>
                <textarea
                  value={notes}
                  onChange={e => setNotes(e.target.value)}
                  placeholder="Why is the model wrong? Any observations about this URL..."
                  className="w-full border border-slate-200 rounded-xl px-3.5 py-2.5 text-[12px] text-slate-700 placeholder-slate-300 outline-none focus:border-sky-400 resize-none h-16 font-medium"
                />
              </div>
              {error && (
                <p className="text-[11px] text-red-600 bg-red-50 rounded-lg px-3 py-2">{error}</p>
              )}
              <div className="flex gap-2">
                <button
                  onClick={() => setStep('ask')}
                  className="px-4 py-2 rounded-xl border border-slate-200 text-slate-500 text-[12px] font-semibold hover:border-slate-300 transition-all"
                >
                  Cancel
                </button>
                <button
                  onClick={() => submit(verdict)}
                  disabled={!verdict}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-xl bg-blue-600 text-white text-[12px] font-bold hover:bg-blue-700 disabled:opacity-40 transition-all shadow-sm"
                >
                  Submit Correction → Add to Retraining Queue
                </button>
              </div>
            </motion.div>
          )}

          {/* Step: saving */}
          {step === 'saving' && (
            <motion.div key="saving" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              className="flex items-center gap-3 py-2"
            >
              <RiLoader4Line className="animate-spin text-sky-500 text-[18px]" />
              <span className="text-[13px] text-slate-500">Saving feedback…</span>
            </motion.div>
          )}

          {/* Step: done */}
          {step === 'done' && (
            <motion.div key="done" initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }}
              className="flex items-center gap-3 py-2"
            >
              <div className="w-8 h-8 rounded-full bg-emerald-50 flex items-center justify-center">
                <RiCheckLine className="text-emerald-500 text-[16px]" />
              </div>
              <div>
                <p className="text-[13px] font-semibold text-slate-800">Thank you for the feedback!</p>
                <p className="text-[11px] text-slate-400">
                  {verdict !== modelVerdict
                    ? `Correction (${modelVerdict} → ${verdict}) added to retraining queue ✓`
                    : 'Model prediction confirmed as correct ✓'}
                </p>
              </div>
            </motion.div>
          )}

        </AnimatePresence>
      </div>
    </motion.div>
  )
}


export default function WebsiteSpoofing() {
  const [url,          setUrl         ] = useState('')
  const [isAnalyzing,  setIsAnalyzing ] = useState(false)
  const [scanStep,     setScanStep    ] = useState(0)
  const [data,         setData        ] = useState(null)
  const [error,        setError       ] = useState(null)
  const [xaiOpen,      setXaiOpen     ] = useState(false)
  const [scanId,       setScanId      ] = useState(null)

  // Animate scan steps
  const runStepAnimation = () => {
    setScanStep(0)
    let i = 0
    const t = setInterval(() => {
      i++
      setScanStep(i)
      if (i >= SCAN_STEPS.length - 1) clearInterval(t)
    }, 700)
    return t
  }

  const handleAnalyze = async (targetUrl) => {
    const u = (targetUrl || url).trim()
    if (!u) return
    setUrl(u)
    setIsAnalyzing(true)
    setError(null)
    setData(null)
    setScanId(null)
    setXaiOpen(false)
    const timer = runStepAnimation()
    try {
      const res = await fetch('/api/website-spoofing/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: u }),
      })
      clearInterval(timer)
      if (!res.ok) throw new Error((await res.json()).detail || 'Analysis failed')
      const result = await res.json()
      setData(result)
      if (result.scan_id) setScanId(result.scan_id)
    } catch (e) {
      setError(e.message || 'Cannot reach the spoofing detector service.')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const handleReset = () => { setData(null); setError(null); setUrl(''); setScanId(null) }

  const handleExport = () => window.print()

  const d       = data?.details || {}
  const ml      = d.ml_model   || {}
  const ssl     = d.ssl        || {}
  const whois   = d.whois      || {}
  const cookies = d.cookies    || {}
  const enc     = d.encoding   || {}
  const html    = d.html       || {}
  const verdict = (data?.verdict || 'SAFE').toUpperCase()
  const cfg     = verdictCfg(verdict)

  const mlPct     = ml.probability   || 0
  const mlLabel   = (ml.label        || 'legitimate').toUpperCase()
  const mlIsPhish = ml.label         === 'phishing'
  const barColor  = mlIsPhish ? '#DC2626' : ml.label === 'suspicious' ? '#D97706' : '#059669'

  const sslOk  = !!ssl.valid
  const age    = whois.age_days || 0
  const whoisOk = age > 365
  const cookieIssues = cookies.issues?.length || 0
  const encOk  = !enc.risk
  const htmlClean = !(html.has_password_input || html.has_login_form || html.has_iframe || html.external_form_action || html.suspicious_scripts > 0)

  return (
    <PageWrapper>
      {/* ── Page title ── */}
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-1">
          <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-blue-600 to-sky-400 flex items-center justify-center text-white text-sm">🛡️</div>
          <h1 className="text-[22px] font-black text-slate-900 tracking-tight">Website Spoofing Detector</h1>
          <span className="ml-2 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-blue-50 text-blue-600 border border-blue-200 uppercase tracking-wide">⚡ XGBoost + 6-Layer</span>
        </div>
        <p className="text-[13px] text-slate-400 ml-10">AI-powered phishing detection — ML model · SSL · WHOIS · Cookie security · Encoding · HTML analysis</p>
      </div>

      {/* ── URL Input ── */}
      <motion.div
        layout
        className="bg-white rounded-2xl border border-slate-100 shadow-sm p-5 mb-6"
      >
        <div className="flex gap-2">
          <div className="relative flex-1">
            <RiGlobalLine className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-300 text-[16px]" />
            <input
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleAnalyze()}
              placeholder="https://example.com — paste any suspicious URL…"
              className="w-full pl-9 pr-4 py-2.5 rounded-xl border border-slate-200 text-[13px] font-mono text-slate-800 placeholder-slate-300 outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-100 transition-all bg-slate-50"
              disabled={isAnalyzing}
            />
          </div>
          <motion.button
            whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.97 }}
            onClick={() => handleAnalyze()}
            disabled={isAnalyzing || !url.trim()}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-blue-600 text-white text-[13px] font-bold shadow-md hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {isAnalyzing
              ? <><RiLoader4Line className="animate-spin text-[16px]" /> Scanning…</>
              : <><RiSearchLine className="text-[16px]" /> Analyze</>
            }
          </motion.button>
          {data && (
            <motion.button
              initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }}
              whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.97 }}
              onClick={handleReset}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl border border-slate-200 text-slate-600 text-[13px] font-semibold hover:border-blue-300 hover:text-blue-600 hover:bg-blue-50 transition-all"
            >
              <RiRefreshLine className="text-[16px]" /> New Scan
            </motion.button>
          )}
        </div>

        {/* Quick examples */}
        <div className="flex items-center gap-2 flex-wrap mt-3">
          <span className="text-[11px] text-slate-400 font-medium">Try:</span>
          {['https://google.com', 'https://example-bank.com', 'http://paypal-secure-verify.tk/login.php', 'https://github.com'].map(ex => (
            <button
              key={ex}
              onClick={() => handleAnalyze(ex)}
              disabled={isAnalyzing}
              className="px-2.5 py-1 rounded-lg bg-blue-50 border border-blue-100 text-blue-600 text-[11px] font-mono font-medium hover:bg-blue-100 hover:border-blue-300 transition-all disabled:opacity-40"
            >
              {ex.replace(/https?:\/\//,'').split('/')[0]}
            </button>
          ))}
        </div>
      </motion.div>

      {/* ── Error ── */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="mb-5 p-4 rounded-xl bg-red-50 border border-red-200 text-red-700 text-[13px] flex items-center gap-2"
          >
            <RiAlertLine className="text-[18px] flex-shrink-0" /> {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Loading ── */}
      <AnimatePresence>
        {isAnalyzing && (
          <motion.div key="loader" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <ScanLoader step={scanStep} />
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Results ── */}
      <AnimatePresence>
        {data && !isAnalyzing && (
          <motion.div key="results" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>

            {/* ── Verdict Banner ── */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4 }}
              className={`rounded-2xl border ${cfg.border} ${cfg.bg} overflow-hidden mb-5 shadow-sm`}
            >
              <div className="flex items-center gap-5 px-6 py-5">
                <div className={`w-14 h-14 rounded-2xl flex items-center justify-center text-2xl flex-shrink-0 bg-white/60`}>
                  {cfg.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <p className={`text-[11px] font-bold uppercase tracking-widest ${cfg.color} mb-0.5`}>Security Verdict</p>
                  <p className={`text-[26px] font-black tracking-tight leading-none ${cfg.color}`}>{verdict}</p>
                  <p className="text-[12px] text-slate-500 mt-1 font-mono truncate">{data.url || data.domain}</p>
                </div>
                <div className="flex items-center gap-6 flex-shrink-0">
                  <TrustRing riskScore={data.risk_score || 0} verdict={verdict} />
                  <div className="text-right hidden sm:block">
                    <p className="text-[11px] text-slate-400">Analysis time</p>
                    <p className="text-[13px] font-bold text-slate-700">⏱ {data.analysis_time_ms}ms</p>
                    <button
                      onClick={handleExport}
                      className="mt-2 flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-[11px] font-semibold text-slate-600 hover:border-blue-300 hover:text-blue-600 hover:bg-blue-50 transition-all"
                    >
                      <RiDownloadLine /> Export PDF
                    </button>
                  </div>
                </div>
              </div>

              {/* Risk reasons / summary */}
              <div className="px-6 py-3 border-t border-white/60 bg-white/30">
                <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2">
                  {data.risk_reasons?.length > 0 ? 'Risk signals detected' : 'Security summary'}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {data.risk_reasons?.length > 0
                    ? data.risk_reasons.map((r, i) => (
                        <span key={i} className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-medium ${cfg.bg} ${cfg.color} border ${cfg.border}`}>
                          ● {r}
                        </span>
                      ))
                    : (
                        <>
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200"><RiCheckboxCircleLine /> No risk signals</span>
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200"><RiCheckboxCircleLine /> No typosquatting</span>
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200"><RiCheckboxCircleLine /> No suspicious keywords</span>
                        </>
                      )
                  }
                </div>
              </div>
            </motion.div>

            {/* ── Detail Cards Grid ── */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 mb-4">

              {/* ML Model — full width */}
              <div className="md:col-span-2 xl:col-span-3">
                <DetailCard
                  icon={RiRobot2Line} iconBg="bg-blue-50 text-blue-600"
                  title="XGBoost AI Model"
                  subtitle="27-feature URL phishing classification"
                  badge={<StatusPill ok={!mlIsPhish} okLabel={mlLabel} badLabel={mlLabel} />}
                  delay={0.05}
                >
                  {/* Probability bar */}
                  <div className="mb-4">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-[12px] text-slate-400 font-medium">Phishing Probability</span>
                      <span className="text-[13px] font-black font-mono" style={{ color: barColor }}>{mlPct.toFixed(1)}%</span>
                    </div>
                    <div className="h-2.5 bg-slate-100 rounded-full overflow-hidden border border-slate-100">
                      <motion.div
                        className="h-full rounded-full"
                        style={{ background: barColor }}
                        initial={{ width: 0 }}
                        animate={{ width: `${Math.min(mlPct, 100)}%` }}
                        transition={{ duration: 1.2, ease: [0.34, 1.2, 0.64, 1] }}
                      />
                    </div>
                  </div>

                  {/* Factor chips */}
                  <div className="flex flex-wrap gap-1.5 mb-4">
                    {ml.risk_factors?.map((f, i) => (
                      <span key={i} className="px-2 py-0.5 rounded-md bg-red-50 text-red-700 border border-red-100 text-[11px] font-medium">🔴 {f}</span>
                    ))}
                    {ml.safe_factors?.map((f, i) => (
                      <span key={i} className="px-2 py-0.5 rounded-md bg-emerald-50 text-emerald-700 border border-emerald-100 text-[11px] font-medium">✅ {f}</span>
                    ))}
                  </div>

                  {/* XAI Explanation (expandable) */}
                  <XAIExplanation
                    summary={ml.summary}
                    mlPct={mlPct}
                    mlLabel={mlLabel}
                    mlIsPhish={mlIsPhish}
                    xaiOpen={xaiOpen}
                    setXaiOpen={setXaiOpen}
                  />
                </DetailCard>
              </div>

              {/* SSL Certificate */}
              <DetailCard
                icon={RiLockLine} iconBg="bg-emerald-50 text-emerald-600"
                title="SSL Certificate"
                subtitle="Certificate validity & trust chain"
                badge={<StatusPill ok={sslOk} okLabel="VALID" badLabel={ssl.status === 'unreachable' ? 'UNREACHABLE' : ssl.status === 'no_ssl' ? 'NO HTTPS' : 'INVALID'} />}
                delay={0.1}
              >
                {sslOk ? (
                  <>
                    <CheckRow label="Status"   ok={true}  okText="Valid & Trusted" />
                    <CheckRow
                      label="Expires in"
                      ok={ssl.expires_in_days > 30}
                      warn={ssl.expires_in_days <= 30}
                      okText={`${ssl.expires_in_days} days`}
                      badText={`${ssl.expires_in_days} days (expiring!)`}
                    />
                    <div className="flex items-center justify-between py-2.5 border-b border-slate-50">
                      <span className="text-[12px] text-slate-400 font-medium">Issuer</span>
                      <span className="text-[11px] font-mono text-slate-600 text-right max-w-[60%] truncate">{ssl.issuer?.substring(0, 40) || 'Unknown'}</span>
                    </div>
                  </>
                ) : (
                  <div className="p-3 rounded-xl bg-red-50 border border-red-100 text-[12px] text-red-600">
                    ❌ {ssl.error || 'SSL verification failed'}
                  </div>
                )}
              </DetailCard>

              {/* WHOIS */}
              <DetailCard
                icon={RiGlobalLine} iconBg="bg-sky-50 text-sky-600"
                title="WHOIS Lookup"
                subtitle="Domain registration & age"
                badge={
                  <StatusPill
                    ok={whoisOk}
                    okLabel="ESTABLISHED"
                    badLabel={whois.status === 'dns_failed' ? 'DNS FAILED' : age < 30 ? 'NEW DOMAIN' : 'MODERATE'}
                    warnColor={age >= 30 && age <= 365}
                  />
                }
                delay={0.15}
              >
                <CheckRow
                  label="Domain Age"
                  ok={age > 365}
                  warn={age > 30 && age <= 365}
                  okText={`${age} days`}
                  badText={age < 30 ? `🚨 ${age} days (very new)` : `⚠️ ${age} days`}
                />
                <div className="flex items-center justify-between py-2.5 border-b border-slate-50">
                  <span className="text-[12px] text-slate-400 flex items-center gap-1"><RiCalendarLine /> Registered</span>
                  <span className="text-[11px] font-mono text-slate-600">{whois.creation_date || 'Unknown'}</span>
                </div>
                <div className="flex items-center justify-between py-2.5 border-b border-slate-50">
                  <span className="text-[12px] text-slate-400 flex items-center gap-1"><RiCalendarLine /> Expires</span>
                  <span className="text-[11px] font-mono text-slate-600">{whois.expiration_date || 'Unknown'}</span>
                </div>
                <div className="flex items-center justify-between py-2.5 border-b border-slate-50">
                  <span className="text-[12px] text-slate-400">Registrar</span>
                  <span className="text-[11px] font-mono text-slate-600 text-right max-w-[55%] truncate">{(whois.registrar || 'Unknown').substring(0, 30)}</span>
                </div>
                {whois.country && (
                  <div className="flex items-center justify-between py-2.5">
                    <span className="text-[12px] text-slate-400">Country</span>
                    <span className="text-[11px] font-mono text-slate-600">{whois.country}</span>
                  </div>
                )}
              </DetailCard>

              {/* Cookie Security */}
              <DetailCard
                icon={RiShieldLine} iconBg="bg-amber-50 text-amber-600"
                title="Cookie Security"
                subtitle="Server-set cookie inspection"
                badge={
                  <StatusPill
                    ok={cookieIssues === 0}
                    okLabel="SECURE"
                    badLabel={`${cookieIssues} ISSUE${cookieIssues > 1 ? 'S' : ''}`}
                  />
                }
                delay={0.2}
              >
                <CheckRow
                  label="Cookies Found"
                  ok={true}
                  okText={`${cookies.total_cookies || 0}`}
                />
                <CheckRow
                  label="Security Issues"
                  ok={cookieIssues === 0}
                  okText="No issues detected"
                  badText={`${cookieIssues} found`}
                />
                {cookieIssues === 0 && (
                  <div className="mt-3 p-3 rounded-xl bg-emerald-50 border border-emerald-100 text-[12px] text-emerald-700 flex items-center gap-2">
                    <RiShieldCheckLine className="flex-shrink-0" /> All cookie flags are properly configured
                  </div>
                )}
                {cookies.issues?.slice(0, 3).map((issue, i) => (
                  <div key={i} className="mt-1.5 p-2.5 rounded-lg bg-amber-50 border border-amber-100 text-[11px] text-amber-700">⚠️ {issue}</div>
                ))}
              </DetailCard>

              {/* URL Encoding */}
              <DetailCard
                icon={RiCodeLine} iconBg="bg-purple-50 text-purple-600"
                title="URL Encoding"
                subtitle="Obfuscation & encoding checks"
                badge={<StatusPill ok={encOk} okLabel="CLEAN" badLabel={enc.is_double_encoded ? 'OBFUSCATED' : 'ENCODED'} />}
                delay={0.25}
              >
                <CheckRow
                  label="Percent-Encoded"
                  ok={!enc.is_encoded}
                  warn={enc.is_encoded && !enc.is_double_encoded}
                  okText="No encoding"
                  badText="⚠️ Yes"
                />
                <CheckRow
                  label="Double Encoded"
                  ok={!enc.is_double_encoded}
                  okText="No obfuscation"
                  badText="🚨 Detected!"
                />
                {enc.is_encoded && enc.decoded_url && (
                  <div className="mt-3 p-3 rounded-xl bg-slate-50 border border-slate-100">
                    <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wide mb-1">Decoded URL</p>
                    <p className="text-[11px] font-mono text-slate-600 break-all">{enc.decoded_url.substring(0, 80)}{enc.decoded_url.length > 80 ? '…' : ''}</p>
                  </div>
                )}
                {enc.issues?.map((issue, i) => (
                  <div key={i} className="mt-1.5 p-2.5 rounded-lg bg-amber-50 border border-amber-100 text-[11px] text-amber-700">⚠️ {issue}</div>
                ))}
              </DetailCard>

              {/* HTML Analysis */}
              <DetailCard
                icon={RiFileTextLine} iconBg="bg-rose-50 text-rose-600"
                title="HTML Analysis"
                subtitle="Page content phishing patterns"
                badge={
                  <StatusPill
                    ok={htmlClean}
                    okLabel="CLEAN"
                    badLabel={html.external_form_action ? 'HIGH RISK' : `${html.risk_flags?.length || 1} FLAG(S)`}
                  />
                }
                delay={0.3}
              >
                <CheckRow label="Login Form"        ok={!html.has_login_form}      okText="None"   badText="Found"   warn={html.has_login_form && !html.external_form_action} />
                <CheckRow label="Password Fields"   ok={!html.has_password_input}  okText="None"   badText="Found"   warn={html.has_password_input} />
                <CheckRow label="Suspicious Scripts"ok={!(html.suspicious_scripts > 0)} okText="None" badText={`${html.suspicious_scripts} found`} warn={html.suspicious_scripts > 0} />
                <CheckRow label="iFrames"           ok={!html.has_iframe}          okText="None"   badText="Found"   warn={html.has_iframe} />
                <CheckRow label="Ext. Form Action"  ok={!html.external_form_action} okText="Safe"  badText="🚨 Danger!" />
                {htmlClean && (
                  <div className="mt-3 p-3 rounded-xl bg-emerald-50 border border-emerald-100 text-[12px] text-emerald-700 flex items-center gap-2">
                    <RiShieldCheckLine className="flex-shrink-0" /> No malicious HTML patterns detected
                  </div>
                )}
              </DetailCard>

            </div>{/* end cards grid */}

            {/* ── Feedback Section ── */}
            <FeedbackSection
              scanId={scanId}
              url={data.url || url}
              modelVerdict={verdict}
            />

            {/* ── Action Row ── */}
            <motion.div
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 }}
              className="flex items-center justify-center gap-3 mt-2"
            >
              <button
                onClick={handleReset}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl border border-slate-200 bg-white text-slate-600 text-[13px] font-semibold hover:border-blue-300 hover:text-blue-600 hover:bg-blue-50 transition-all"
              >
                <RiRefreshLine /> Scan Another URL
              </button>
              <button
                onClick={handleExport}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-blue-600 text-white text-[13px] font-bold shadow-md hover:bg-blue-700 transition-all"
              >
                <RiDownloadLine /> Export Report (PDF)
              </button>
            </motion.div>

          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Empty state ── */}
      {!data && !isAnalyzing && !error && (
        <motion.div
          initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          className="bg-white rounded-2xl border border-dashed border-slate-200 p-12 text-center"
        >
          <div className="text-5xl mb-4">🛡️</div>
          <p className="text-[16px] font-bold text-slate-700 mb-2">Ready to scan</p>
          <p className="text-[13px] text-slate-400 max-w-sm mx-auto">Enter a URL above to run a 6-layer security analysis — XGBoost ML · SSL · WHOIS · Cookie · Encoding · HTML</p>
          <div className="flex flex-wrap justify-center gap-2 mt-6">
            {['🤖 XGBoost ML', '🔒 SSL/TLS', '🌍 WHOIS', '🍪 Cookies', '🔤 Encoding', '📄 HTML'].map(f => (
              <span key={f} className="px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-100 text-[11px] text-slate-500 font-medium">{f}</span>
            ))}
          </div>
        </motion.div>
      )}

    </PageWrapper>
  )
}

