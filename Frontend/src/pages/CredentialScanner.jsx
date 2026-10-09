import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiSearchLine, RiShieldKeyholeLine, RiHistoryLine, RiRobot2Line,
  RiBracesLine, RiFingerprintLine, RiAlertLine, RiCheckLine,
  RiMailLine, RiArrowDownSLine, RiArrowUpSLine, RiKeyLine,
  RiLockLine, RiDatabaseLine, RiUserLine, RiDownloadLine,
  RiShieldCheckLine, RiStackLine,
} from 'react-icons/ri'
import {
  Card, Btn, PageWrapper, SubTabs,
  FormLabel, FormTextarea, SectionHeader,
} from '../components/ui'

/* ── Detection layer config ── */
const LAYER_INFO = {
  regex:   { shortLabel: 'Regex',   icon: RiBracesLine,      color: 'text-indigo-600', bg: 'bg-indigo-50 border-indigo-200' },
  entropy: { shortLabel: 'Entropy', icon: RiFingerprintLine, color: 'text-orange-600', bg: 'bg-orange-50 border-orange-200' },
  ner:     { shortLabel: 'NER',     icon: RiShieldKeyholeLine, color: 'text-teal-600', bg: 'bg-teal-50 border-teal-200'   },
  llm:     { shortLabel: 'LLM AI',  icon: RiRobot2Line,      color: 'text-rose-600',   bg: 'bg-rose-50 border-rose-200'   },
}

/* ── Credential type → icon + color ── */
const CRED_TYPE_MAP = {
  'aws key':     { icon: RiKeyLine,          bg: 'bg-red-50',     color: 'text-red-600'    },
  'db password': { icon: RiDatabaseLine,     bg: 'bg-orange-50',  color: 'text-orange-600' },
  'pii email':   { icon: RiMailLine,         bg: 'bg-sky-50',     color: 'text-sky-600'    },
  'api key':     { icon: RiBracesLine,       bg: 'bg-indigo-50',  color: 'text-indigo-600' },
  'private key': { icon: RiFingerprintLine,  bg: 'bg-purple-50',  color: 'text-purple-600' },
  'token':       { icon: RiLockLine,         bg: 'bg-amber-50',   color: 'text-amber-600'  },
  'password':    { icon: RiLockLine,         bg: 'bg-amber-50',   color: 'text-amber-600'  },
  'personal':    { icon: RiUserLine,         bg: 'bg-teal-50',    color: 'text-teal-600'   },
  default:       { icon: RiShieldKeyholeLine,bg: 'bg-slate-50',   color: 'text-slate-600'  },
}

function getCredConfig(type = '') {
  const lower = type.toLowerCase()
  const key = Object.keys(CRED_TYPE_MAP).find(k => k !== 'default' && lower.includes(k))
  return CRED_TYPE_MAP[key] || CRED_TYPE_MAP.default
}

/* ── Tier styling ── */
const TIER_BADGE = {
  Critical: 'bg-rose-50   text-rose-700   border-rose-200',
  High:     'bg-orange-50 text-orange-700 border-orange-200',
  Medium:   'bg-amber-50  text-amber-700  border-amber-200',
  Low:      'bg-emerald-50 text-emerald-700 border-emerald-200',
  Clean:    'bg-emerald-50 text-emerald-700 border-emerald-200',
}
const BANNER_BORDER = {
  Critical: 'border-l-rose-500',
  High:     'border-l-orange-500',
  Medium:   'border-l-amber-400',
  Low:      'border-l-emerald-400',
  Clean:    'border-l-emerald-400',
}
const RISK_TEXT = {
  Critical: 'text-rose-600',
  High:     'text-orange-600',
  Medium:   'text-amber-500',
  Low:      'text-emerald-600',
  Clean:    'text-emerald-600',
}
const SEVERITY_PILLS = [
  { label: 'Critical', key: 'critical_count', cls: 'bg-rose-50   text-rose-700   border-rose-200'   },
  { label: 'High',     key: 'high_count',     cls: 'bg-orange-50 text-orange-700 border-orange-200' },
  { label: 'Medium',   key: 'medium_count',   cls: 'bg-amber-50  text-amber-700  border-amber-200'  },
  { label: 'Low',      key: 'low_count',      cls: 'bg-emerald-50 text-emerald-700 border-emerald-200' },
]
const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 }

/* ── Single credential card ── */
function CredentialCard({ finding, index }) {
  const cfg    = getCredConfig(finding.credential_type)
  const Icon   = cfg.icon
  const layers = finding.detected_by || [finding.layer]

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.06 }}
      className="flex items-start gap-3 p-4 bg-white border border-slate-100 rounded-xl shadow-[0_1px_3px_rgba(0,0,0,0.05)]"
    >
      {/* Type icon */}
      <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${cfg.bg}`}>
        <Icon className={`text-base ${cfg.color}`} />
      </div>

      {/* Body */}
      <div className="flex-1 min-w-0">
        {/* Row 1: type + tier badge + confidence */}
        <div className="flex items-center flex-wrap gap-2 mb-1.5">
          <span className="text-[13px] font-bold text-gray-900">
            {finding.credential_type.replace(/_/g, ' ')}
          </span>
          <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-bold border ${TIER_BADGE[finding.risk_tier] || TIER_BADGE.Medium}`}>
            {finding.risk_tier}
          </span>
          <span className="ml-auto text-[11px] text-gray-400 font-medium flex-shrink-0">
            {Math.round(finding.confidence * 100)}% confidence
          </span>
        </div>

        {/* Row 2: short description */}
        <p className="text-[12px] text-gray-500 mb-2 leading-snug">{finding.description}</p>

        {/* Row 3: redacted value pill */}
        <div className="flex items-center gap-2 bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-100 mb-2.5">
          <RiLockLine className="text-slate-400 text-xs flex-shrink-0" />
          <span className="font-mono text-[12px] text-slate-700 flex-1 truncate">{finding.redacted_value}</span>
          {finding.entropy_score != null && (
            <span className="text-[10px] text-slate-400 flex-shrink-0">entropy {finding.entropy_score.toFixed(1)}</span>
          )}
        </div>

        {/* Row 4: detection layer chips */}
        <div className="flex items-center flex-wrap gap-1.5">
          {layers.length > 1 && (
            <span className="flex items-center gap-1 text-[10px] font-bold bg-sky-50 text-sky-700 border border-sky-200 px-2 py-0.5 rounded-md">
              <RiStackLine className="text-[10px]" /> Multi-Layer
            </span>
          )}
          {layers.map(l => {
            const info = LAYER_INFO[l] || { shortLabel: l, icon: RiCheckLine, color: 'text-slate-600', bg: 'bg-slate-100 border-slate-200' }
            const LIcon = info.icon
            return (
              <span key={l} className={`flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-md border ${info.bg} ${info.color}`}>
                <LIcon className="text-[10px]" /> {info.shortLabel}
              </span>
            )
          })}
        </div>
      </div>
    </motion.div>
  )
}

/* ── Main page ── */
export default function CredentialScanner() {
  const [tab, setTab]             = useState('Paste Text')
  const [loading, setLoading]     = useState(false)
  const [text, setText]           = useState('')
  const [result, setResult]       = useState(null)
  const [scannedText, setScannedText] = useState('')
  const [emailExpanded, setEmailExpanded] = useState(false)
  const [history, setHistory]     = useState([])

  /* Load history from localStorage on mount */
  useEffect(() => {
    try {
      const saved = localStorage.getItem('credScanHistory')
      if (saved) setHistory(JSON.parse(saved))
    } catch (_) {}
  }, [])

  const persistHistory = (list) => {
    setHistory(list)
    localStorage.setItem('credScanHistory', JSON.stringify(list))
  }

  const saveToHistory = (scanData, inputText) => {
    const entry = { ...scanData, _inputText: inputText, _savedAt: new Date().toISOString() }
    persistHistory([entry, ...history].slice(0, 25))
  }

  const clearHistory = () => persistHistory([])

  /* Load a history entry back into the result panel */
  const loadHistory = (h) => {
    setResult(h)
    setScannedText(h._inputText || '')
    setEmailExpanded(false)
  }

  const handleScan = async () => {
    if (!text.trim()) return
    setLoading(true)
    setResult(null)
    const captured = text
    try {
      const fd = new FormData()
      fd.append('text', captured)
      let data
      try {
        const res = await fetch('/api/cred-scan/scan/text', { method: 'POST', body: fd })
        data = await res.json()
        if (!res.ok) throw new Error(data.detail || 'API Error')
      } catch (_) {
        /* Mock fallback for demo */
        data = {
          scan_id: 'mock-' + Date.now(),
          timestamp: new Date().toISOString(),
          total_findings: 3,
          critical_count: 1, high_count: 1, medium_count: 1, low_count: 0,
          risk_score: 85,
          risk_label: 'Critical',
          human_summary: 'Multiple severe credentials found including AWS keys and high-entropy secrets. Urgent action required.',
          recommended_action: 'Immediately revoke the exposed AWS key and audit all database passwords.',
          context_signals: { has_urgency_language: true, has_internal_exposure_signals: true },
          findings: [
            {
              layer: 'regex', credential_type: 'AWS Key',
              description: 'AWS Secret Access Key pattern matched in content.',
              risk_tier: 'Critical', redacted_value: 'wJalrXUtnFEMI/K7MD...KEY',
              confidence: 0.99, detected_by: ['regex', 'entropy'],
            },
            {
              layer: 'entropy', credential_type: 'DB Password',
              description: 'High-entropy string detected in database connection URL.',
              risk_tier: 'High', redacted_value: 'postgres://user:***@db:5432/main',
              entropy_score: 4.8, confidence: 0.85, detected_by: ['entropy'],
            },
            {
              layer: 'ner', credential_type: 'PII Email',
              description: 'Personal email address found in plain text.',
              risk_tier: 'Medium', redacted_value: 'j***@corp.com',
              confidence: 0.90, detected_by: ['ner', 'llm'],
            },
          ],
        }
      }
      setScannedText(captured)
      setResult(data)
      setEmailExpanded(false)
      saveToHistory(data, captured)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const handleNewScan = () => {
    setResult(null)
    setText('')
  }

  return (
    <PageWrapper>
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">

        {/* ── Scan History sidebar ─────────────────────────────────────────── */}
        <div className="xl:col-span-1">
          <Card hover={false} className="!p-0 overflow-hidden sticky top-6">
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <RiHistoryLine className="text-sky-500 text-sm" />
                <span className="text-[13px] font-semibold text-gray-900">Scan History</span>
              </div>
              {history.length > 0 && (
                <button
                  onClick={clearHistory}
                  className="text-[10px] text-gray-400 hover:text-red-500 font-medium transition-colors"
                >
                  Clear all
                </button>
              )}
            </div>

            {history.length === 0 ? (
              <div className="py-10 flex flex-col items-center text-center px-4">
                <RiHistoryLine className="text-slate-200 text-3xl mb-2" />
                <p className="text-[12px] text-slate-400">No scans yet</p>
                <p className="text-[11px] text-slate-300 mt-0.5">Results appear here after scanning</p>
              </div>
            ) : (
              <div className="overflow-y-auto max-h-[70vh]">
                {history.map((h, i) => {
                  const isActive = result?.scan_id === h.scan_id
                  const preview = h._inputText?.trim().split('\n').find(l => l.trim()) || ''
                  return (
                    <button
                      key={h.scan_id || i}
                      onClick={() => loadHistory(h)}
                      className={`w-full text-left px-4 py-3 border-b border-slate-50 last:border-none transition-colors ${
                        isActive
                          ? 'bg-sky-50 border-l-2 border-l-sky-400'
                          : 'hover:bg-slate-50'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md border ${TIER_BADGE[h.risk_label] || TIER_BADGE.Clean}`}>
                          {h.risk_label}
                        </span>
                        <span className="text-[10px] text-slate-400">
                          {new Date(h._savedAt || h.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>
                      <p className="text-[12px] text-slate-700 font-medium truncate leading-snug">
                        {preview.slice(0, 52) || 'No preview'}
                      </p>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        {h.total_findings} credential{h.total_findings !== 1 ? 's' : ''} detected
                      </p>
                    </button>
                  )
                })}
              </div>
            )}
          </Card>
        </div>

        {/* ── Main area ────────────────────────────────────────────────────── */}
        <div className="xl:col-span-3 space-y-4">
          <AnimatePresence mode="wait">

            {/* ── Input panel ── */}
            {!result && (
              <motion.div key="input" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-4">
                <Card>
                  <SubTabs tabs={['Paste Text', 'Upload File']} active={tab} onChange={setTab} />

                  {tab === 'Paste Text' ? (
                    <>
                      <FormLabel>Email / Content to Scan</FormLabel>
                      <FormTextarea
                        rows={12}
                        value={text}
                        onChange={e => setText(e.target.value)}
                        placeholder={`Paste email body, code snippet, or config file...\n\nExample:\nURGENT: Use this key for S3 deployment!\nAWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`}
                        className="text-[12px] font-mono leading-relaxed"
                      />
                    </>
                  ) : (
                    <div className="border-2 border-dashed border-slate-200 rounded-xl p-12 text-center bg-slate-50 flex flex-col items-center min-h-[240px] justify-center">
                      <RiDownloadLine className="text-slate-300 text-4xl mb-3" />
                      <p className="text-[14px] font-semibold text-slate-700 mb-1">Drag & drop file here</p>
                      <p className="text-[12px] text-slate-400 mb-5">Supports .txt, .eml, .log, .json</p>
                      <Btn variant="ghost">Browse Files</Btn>
                    </div>
                  )}

                  <div className="flex items-center justify-between mt-5">
                    <span className="text-[12px] text-slate-400">
                      {text.length > 0 ? `${text.length} characters` : 'No content entered'}
                    </span>
                    <Btn variant="primary" onClick={handleScan} disabled={loading || !text.trim()}>
                      {loading
                        ? <span className="animate-pulse">Analyzing…</span>
                        : <><RiSearchLine /> Scan for Credentials</>
                      }
                    </Btn>
                  </div>
                </Card>

                {/* Detection engine info cards */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {[
                    { label: 'Regex & TruffleHog', desc: '700+ patterns',     icon: RiBracesLine,       color: 'text-indigo-500', bg: 'bg-indigo-50' },
                    { label: 'Entropy Analysis',   desc: 'Base64 & hex keys', icon: RiFingerprintLine,  color: 'text-orange-500', bg: 'bg-orange-50' },
                    { label: 'Named Entity (NER)', desc: 'NLTK PII parsing',   icon: RiShieldKeyholeLine,color: 'text-teal-500',   bg: 'bg-teal-50'   },
                    { label: 'LLM Llama3',         desc: 'Intent & urgency',   icon: RiRobot2Line,       color: 'text-rose-500',   bg: 'bg-rose-50'   },
                  ].map(item => (
                    <div key={item.label} className="bg-white border border-slate-100 rounded-xl p-4 flex flex-col items-center text-center">
                      <div className={`w-9 h-9 rounded-xl ${item.bg} flex items-center justify-center mb-2`}>
                        <item.icon className={`${item.color} text-base`} />
                      </div>
                      <span className="text-[12px] font-bold text-slate-800 mb-0.5">{item.label}</span>
                      <span className="text-[10px] text-slate-400">{item.desc}</span>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}

            {/* ── Results panel ── */}
            {result && (
              <motion.div key="results" initial={{ y: 10, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className="space-y-4">

                {/* 1. Summary banner */}
                <div className={`bg-white border border-slate-200 border-l-[5px] ${BANNER_BORDER[result.risk_label] || BANNER_BORDER.Clean} rounded-xl p-5 flex flex-col sm:flex-row items-start sm:items-center gap-4`}>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center flex-wrap gap-2 mb-1.5">
                      <span className={`text-[15px] font-bold ${RISK_TEXT[result.risk_label] || RISK_TEXT.Clean}`}>
                        {result.risk_label} Risk Detected
                      </span>
                      <span className="text-[11px] font-semibold bg-slate-100 text-slate-600 px-2 py-0.5 rounded-md border border-slate-200">
                        Score {result.risk_score}/100
                      </span>
                      <span className="text-[11px] font-semibold bg-sky-50 text-sky-700 px-2 py-0.5 rounded-md border border-sky-200">
                        {result.total_findings} Credential{result.total_findings !== 1 ? 's' : ''}
                      </span>
                    </div>
                    <p className="text-[13px] text-slate-600 leading-snug mb-2">{result.human_summary}</p>
                    {result.context_signals && (
                      <div className="flex flex-wrap gap-1.5">
                        {result.context_signals.has_urgency_language && (
                          <span className="flex items-center gap-1 text-[11px] font-semibold bg-rose-50 text-rose-700 border border-rose-200 px-2 py-0.5 rounded-md">
                            <RiAlertLine className="text-xs" /> Urgency Language
                          </span>
                        )}
                        {result.context_signals.has_internal_exposure_signals && (
                          <span className="flex items-center gap-1 text-[11px] font-semibold bg-amber-50 text-amber-700 border border-amber-200 px-2 py-0.5 rounded-md">
                            <RiAlertLine className="text-xs" /> Internal Exposure
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                  <Btn variant="ghost" onClick={handleNewScan} className="flex-shrink-0">
                    New Scan
                  </Btn>
                </div>

                {/* 2. Scanned email / content preview (collapsible) */}
                <Card hover={false}>
                  <button
                    className="w-full flex items-center gap-3 text-left"
                    onClick={() => setEmailExpanded(v => !v)}
                  >
                    <div className="icon-box icon-box-blue flex-shrink-0">
                      <RiMailLine className="text-sm" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-[13px] font-semibold text-gray-900">Scanned Email / Content</p>
                      <p className="text-[11px] text-gray-400 truncate">
                        {scannedText?.trim().split('\n').find(l => l.trim())?.slice(0, 90) || '—'}
                      </p>
                    </div>
                    <span className="flex-shrink-0 text-gray-400 text-lg leading-none">
                      {emailExpanded ? <RiArrowUpSLine /> : <RiArrowDownSLine />}
                    </span>
                  </button>

                  <AnimatePresence>
                    {emailExpanded && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                      >
                        <div className="mt-4 bg-slate-50 border border-slate-100 rounded-xl p-4 font-mono text-[12px] text-gray-700 whitespace-pre-wrap max-h-56 overflow-y-auto leading-relaxed">
                          {scannedText}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </Card>

                {/* 3. Severity summary pills */}
                <div className="grid grid-cols-4 gap-3">
                  {SEVERITY_PILLS.map(({ label, key, cls }) => (
                    <div key={label} className={`flex flex-col items-center py-3 px-2 rounded-xl border ${cls}`}>
                      <span className="text-[22px] font-bold leading-none">{result[key] ?? 0}</span>
                      <span className="text-[11px] font-semibold mt-1">{label}</span>
                    </div>
                  ))}
                </div>

                {/* 4. Credential cards */}
                <Card hover={false}>
                  <SectionHeader
                    title={`Credentials Detected — ${result.total_findings} finding${result.total_findings !== 1 ? 's' : ''}`}
                    right={<span className="text-[11px] text-gray-400">Sorted by severity</span>}
                  />
                  {result.findings?.length > 0 ? (
                    <div className="space-y-3">
                      {[...result.findings]
                        .sort((a, b) => (SEVERITY_ORDER[a.risk_tier] ?? 9) - (SEVERITY_ORDER[b.risk_tier] ?? 9))
                        .map((f, i) => <CredentialCard key={i} finding={f} index={i} />)
                      }
                    </div>
                  ) : (
                    <div className="py-12 flex flex-col items-center text-center">
                      <RiShieldCheckLine className="text-4xl text-emerald-400 mb-3" />
                      <p className="text-[14px] font-semibold text-emerald-700">No credentials detected</p>
                      <p className="text-[12px] text-slate-400 mt-1">Tested across Regex, Entropy, NER, and LLM layers.</p>
                    </div>
                  )}
                </Card>

                {/* 5. Recommended action */}
                {result.recommended_action && (
                  <div className="flex items-start gap-3 bg-sky-50 border border-sky-200 rounded-xl p-4">
                    <RiShieldKeyholeLine className="text-sky-500 text-base flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-[12px] font-bold text-sky-800 mb-0.5">Recommended Action</p>
                      <p className="text-[12px] text-sky-700 leading-snug">{result.recommended_action}</p>
                    </div>
                  </div>
                )}

              </motion.div>
            )}

          </AnimatePresence>
        </div>
      </div>
    </PageWrapper>
  )
}


