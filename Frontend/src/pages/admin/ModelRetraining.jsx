import { useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, CartesianGrid, Legend,
  RadialBarChart, RadialBar,
} from 'recharts'
import {
  RiRefreshLine, RiLoader4Line, RiPlayCircleLine, RiCheckboxCircleLine,
  RiCloseCircleLine, RiDownloadLine, RiHistoryLine, RiTimeLine,
  RiMicLine, RiGlobalLine, RiMailLine, RiBarChartLine, RiDatabase2Line,
  RiPulseLine, RiAlertLine, RiFilterLine, RiArrowUpLine, RiArrowDownLine,
  RiShieldCheckLine, RiErrorWarningLine, RiBrainLine, RiEyeLine,
  RiCalendarLine, RiToggleLine, RiToggleFill, RiSettings3Line,
} from 'react-icons/ri'
import { PageWrapper, PageHeader, ProgressBar } from '../../components/ui'

const SCHEDULER_STATUS_URL  = '/api/retrain-scheduler/status'
const SCHEDULER_TRIGGER_URL = '/api/retrain-scheduler/trigger'
const SCHEDULER_UPDATE_URL  = '/api/retrain-scheduler/schedule'
const SCHEDULER_HISTORY_URL = '/api/retrain-scheduler/history'

/* ══════════════════════════════════════════════════════════════════
   Theme / palette
══════════════════════════════════════════════════════════════════ */
const SKY   = '#0EA5E9'
const SKY2  = '#38BDF8'
const SKY3  = '#7DD3FC'
const AMBER = '#F59E0B'
const RED   = '#F87171'
const EMERALD = '#34D399'
const SLATE = '#94A3B8'

/* ══════════════════════════════════════════════════════════════════
   Model config
══════════════════════════════════════════════════════════════════ */
const MODELS = [
  {
    id:          'voice',
    label:       'Deepfake Voice',
    fullLabel:   'Deepfake Voice Detector',
    description: 'MFCC CNN+BiLSTM · best_eer_v2.pt · XGBoost ensemble',
    icon:        RiMicLine,
    color:       '#8B5CF6',
    bg:          'bg-purple-50',
    text:        'text-purple-600',
    border:      'border-purple-200',
    gradient:    'from-purple-500 to-violet-600',
    statusUrl:   '/api/voice-scan/admin/retrain/status',
    retrainUrl:  '/api/voice-scan/admin/retrain',
    verdicts:    ['REAL', 'FAKE', 'REVIEW'],
  },
  {
    id:          'website',
    label:       'Website Spoofing',
    fullLabel:   'Website Spoofing Detector',
    description: 'XGBoost ML · SSL/TLS · WHOIS · HTML analysis',
    icon:        RiGlobalLine,
    color:       '#0EA5E9',
    bg:          'bg-sky-50',
    text:        'text-sky-600',
    border:      'border-sky-200',
    gradient:    'from-sky-500 to-blue-600',
    statusUrl:   '/api/website-spoofing/admin/retrain/status',
    retrainUrl:  '/api/website-spoofing/admin/retrain',
    verdicts:    ['SAFE', 'SUSPICIOUS', 'DANGEROUS'],
  },
  {
    id:          'email',
    label:       'Email Phishing',
    fullLabel:   'Email Phishing Detector',
    description: 'DistilBERT NLP · Header forensics · URL reputation',
    icon:        RiMailLine,
    color:       '#10B981',
    bg:          'bg-emerald-50',
    text:        'text-emerald-600',
    border:      'border-emerald-200',
    gradient:    'from-emerald-500 to-teal-600',
    statusUrl:   '/api/email-monitor/admin/retrain/status',
    retrainUrl:  '/api/email-monitor/admin/retrain',
    verdicts:    ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
  },
]

/* ══════════════════════════════════════════════════════════════════
   Static mock feedback data  (per model)
══════════════════════════════════════════════════════════════════ */
const FEEDBACK = {
  voice: [
    { id: 1,  ts: 'Mar 27, 09:42', content: 'ceo_voice_msg.wav',          modelVerdict: 'FAKE',    analystVerdict: 'FAKE',    correct: true,  type: 'TP', reviewer: 'AK-001', conf: 91 },
    { id: 2,  ts: 'Mar 27, 08:15', content: 'board_call_recording.wav',   modelVerdict: 'REAL',    analystVerdict: 'FAKE',    correct: false, type: 'FN', reviewer: 'SR-002', conf: 43 },
    { id: 3,  ts: 'Mar 26, 17:30', content: 'customer_complaint.mp3',     modelVerdict: 'FAKE',    analystVerdict: 'REAL',    correct: false, type: 'FP', reviewer: 'AK-001', conf: 72 },
    { id: 4,  ts: 'Mar 26, 14:10', content: 'deepfake_alert_001.wav',     modelVerdict: 'FAKE',    analystVerdict: 'FAKE',    correct: true,  type: 'TP', reviewer: 'RD-004', conf: 97 },
    { id: 5,  ts: 'Mar 25, 11:05', content: 'interview_clip.flac',        modelVerdict: 'REAL',    analystVerdict: 'REAL',    correct: true,  type: 'TN', reviewer: 'SM-003', conf: 88 },
    { id: 6,  ts: 'Mar 25, 09:20', content: 'synthetic_voice_test.wav',   modelVerdict: 'REVIEW',  analystVerdict: 'FAKE',    correct: false, type: 'FN', reviewer: 'AK-001', conf: 52 },
  ],
  website: [
    { id: 1,  ts: 'Mar 27, 10:15', content: 'paypa1-secure.com/login',    modelVerdict: 'DANGEROUS', analystVerdict: 'DANGEROUS', correct: true,  type: 'TP', reviewer: 'SM-003', conf: 96 },
    { id: 2,  ts: 'Mar 27, 09:00', content: 'examplebank-verify.xyz',         modelVerdict: 'DANGEROUS', analystVerdict: 'DANGEROUS', correct: true,  type: 'TP', reviewer: 'AK-001', conf: 94 },
    { id: 3,  ts: 'Mar 26, 16:45', content: 'google.com/maps',             modelVerdict: 'SUSPICIOUS',analystVerdict: 'SAFE',      correct: false, type: 'FP', reviewer: 'SR-002', conf: 61 },
    { id: 4,  ts: 'Mar 26, 13:20', content: 'amaz0n-deals.tk/promo',       modelVerdict: 'DANGEROUS', analystVerdict: 'DANGEROUS', correct: true,  type: 'TP', reviewer: 'RD-004', conf: 99 },
    { id: 5,  ts: 'Mar 25, 15:00', content: 'github.com/microsoft/vscode', modelVerdict: 'SAFE',      analystVerdict: 'SAFE',      correct: true,  type: 'TN', reviewer: 'AK-001', conf: 5  },
    { id: 6,  ts: 'Mar 25, 08:30', content: 'secure-banking-login.ru',     modelVerdict: 'SAFE',      analystVerdict: 'DANGEROUS', correct: false, type: 'FN', reviewer: 'SM-003', conf: 38 },
    { id: 7,  ts: 'Mar 24, 17:10', content: 'netflix-update.online/auth',  modelVerdict: 'DANGEROUS', analystVerdict: 'DANGEROUS', correct: true,  type: 'TP', reviewer: 'SR-002', conf: 92 },
  ],
  email: [
    { id: 1,  ts: 'Mar 27, 09:50', content: 'CEO wire transfer urgent',        modelVerdict: 'CRITICAL', analystVerdict: 'CRITICAL', correct: true,  type: 'TP', reviewer: 'AK-001', conf: 98 },
    { id: 2,  ts: 'Mar 27, 08:30', content: 'Monthly team newsletter',         modelVerdict: 'HIGH',     analystVerdict: 'LOW',      correct: false, type: 'FP', reviewer: 'SR-002', conf: 67 },
    { id: 3,  ts: 'Mar 26, 18:00', content: 'Verify your PayPal account now',  modelVerdict: 'CRITICAL', analystVerdict: 'CRITICAL', correct: true,  type: 'TP', reviewer: 'RD-004', conf: 97 },
    { id: 4,  ts: 'Mar 26, 14:45', content: 'Internal meeting invite - Fri',   modelVerdict: 'MEDIUM',   analystVerdict: 'LOW',      correct: false, type: 'FP', reviewer: 'AK-001', conf: 55 },
    { id: 5,  ts: 'Mar 25, 16:20', content: 'Your account has been suspended', modelVerdict: 'LOW',      analystVerdict: 'CRITICAL', correct: false, type: 'FN', reviewer: 'SM-003', conf: 22 },
    { id: 6,  ts: 'Mar 25, 11:30', content: 'Q1 Financial Report — attached',  modelVerdict: 'LOW',      analystVerdict: 'LOW',      correct: true,  type: 'TN', reviewer: 'SR-002', conf: 8  },
    { id: 7,  ts: 'Mar 24, 09:15', content: 'Congratulations! You have won',   modelVerdict: 'CRITICAL', analystVerdict: 'CRITICAL', correct: true,  type: 'TP', reviewer: 'AK-001', conf: 99 },
    { id: 8,  ts: 'Mar 23, 15:40', content: 'AWS secret key exposed in repo',  modelVerdict: 'HIGH',     analystVerdict: 'HIGH',     correct: true,  type: 'TP', reviewer: 'RD-004', conf: 89 },
  ],
}

/* accuracy trend (7 weeks) */
const ACC_TREND = [
  { week: 'W1', voice: 79, website: 91, email: 87 },
  { week: 'W2', voice: 81, website: 93, email: 88 },
  { week: 'W3', voice: 80, website: 92, email: 90 },
  { week: 'W4', voice: 83, website: 94, email: 89 },
  { week: 'W5', voice: 82, website: 95, email: 91 },
  { week: 'W6', voice: 85, website: 95, email: 92 },
  { week: 'W7', voice: 87, website: 96, email: 94 },
]

/* FP/FN per model */
const FP_FN_DATA = [
  { model: 'Voice',   fp: 1, fn: 2 },
  { model: 'Website', fp: 1, fn: 1 },
  { model: 'Email',   fp: 2, fn: 1 },
]

/* pie: overall correctness breakdown */
const PIE_DATA = [
  { name: 'True Positive',  value: 13, color: EMERALD },
  { name: 'True Negative',  value: 5,  color: SKY },
  { name: 'False Positive', value: 4,  color: AMBER },
  { name: 'False Negative', value: 4,  color: RED },
]

/* radial accuracy */
const RADIAL_DATA = [
  { name: 'Email',   accuracy: 94, fill: '#10B981' },
  { name: 'Website', accuracy: 96, fill: '#0EA5E9' },
  { name: 'Voice',   accuracy: 87, fill: '#8B5CF6' },
]

const MIN_QUEUE = 5   // demo threshold

/* ══════════════════════════════════════════════════════════════════
   Mini helpers
══════════════════════════════════════════════════════════════════ */
function VerdictChip({ verdict }) {
  const v = verdict?.toUpperCase() ?? ''
  const map = {
    FAKE:      'bg-red-100 text-red-700 border-red-200',
    DANGEROUS: 'bg-red-100 text-red-700 border-red-200',
    CRITICAL:  'bg-red-100 text-red-700 border-red-200',
    HIGH:      'bg-orange-100 text-orange-700 border-orange-200',
    SUSPICIOUS:'bg-amber-100 text-amber-700 border-amber-200',
    MEDIUM:    'bg-amber-100 text-amber-700 border-amber-200',
    REVIEW:    'bg-yellow-100 text-yellow-700 border-yellow-200',
    REAL:      'bg-emerald-100 text-emerald-700 border-emerald-200',
    SAFE:      'bg-emerald-100 text-emerald-700 border-emerald-200',
    LOW:       'bg-sky-100 text-sky-700 border-sky-200',
  }
  const cls = map[v] ?? 'bg-slate-100 text-slate-600 border-slate-200'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-bold border tracking-wide ${cls}`}>
      {verdict}
    </span>
  )
}

function TypeBadge({ type }) {
  const map = {
    TP: { label: 'TP',  cls: 'bg-emerald-50 text-emerald-700 border-emerald-200', title: 'True Positive'  },
    TN: { label: 'TN',  cls: 'bg-sky-50 text-sky-700 border-sky-200',             title: 'True Negative'  },
    FP: { label: 'FP',  cls: 'bg-amber-50 text-amber-700 border-amber-200',       title: 'False Positive' },
    FN: { label: 'FN',  cls: 'bg-red-50 text-red-700 border-red-200',             title: 'False Negative' },
  }
  const cfg = map[type] ?? map.TP
  return (
    <span title={cfg.title}
      className={`inline-flex items-center justify-center w-7 h-5 rounded text-[10px] font-black border ${cfg.cls}`}>
      {cfg.label}
    </span>
  )
}

function ConfBar({ value }) {
  const color = value >= 80 ? 'bg-sky-500' : value >= 50 ? 'bg-amber-400' : 'bg-red-400'
  return (
    <div className="flex items-center gap-2 min-w-[80px]">
      <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
        <motion.div
          className={`h-full rounded-full ${color}`}
          initial={{ width: 0 }}
          animate={{ width: `${value}%` }}
          transition={{ duration: 0.8, ease: [0.34,1.2,0.64,1] }}
        />
      </div>
      <span className="text-[10px] font-bold text-slate-500 w-7 text-right">{value}%</span>
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════
   Custom chart tooltip
══════════════════════════════════════════════════════════════════ */
function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-white/95 backdrop-blur border border-sky-100 rounded-xl shadow-xl px-3 py-2.5 text-[12px]">
      {label && <p className="font-bold text-slate-700 mb-1">{label}</p>}
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color }} className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full inline-block" style={{ background: p.color }} />
          <span className="text-slate-500">{p.name}:</span>
          <span className="font-bold">{p.value}{p.unit ?? ''}</span>
        </p>
      ))}
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════
   Stat tile
══════════════════════════════════════════════════════════════════ */
function StatTile({ icon: Icon, label, value, sub, iconCls, delay = 0, trend, trendUp }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.35 }}
      className="bg-white rounded-2xl border border-slate-100 shadow-sm p-4 flex items-start gap-3"
    >
      <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${iconCls}`}>
        <Icon className="text-[18px]" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wide mb-0.5">{label}</p>
        <p className="text-[22px] font-black text-slate-900 leading-none">{value}</p>
        {sub && <p className="text-[11px] text-slate-400 mt-0.5">{sub}</p>}
      </div>
      {trend !== undefined && (
        <div className={`flex items-center gap-0.5 text-[11px] font-bold px-2 py-1 rounded-full mt-1 ${
          trendUp ? 'bg-emerald-50 text-emerald-600' : 'bg-red-50 text-red-500'
        }`}>
          {trendUp ? <RiArrowUpLine /> : <RiArrowDownLine />}
          {trend}
        </div>
      )}
    </motion.div>
  )
}

/* ══════════════════════════════════════════════════════════════════
   Per-model feedback table
══════════════════════════════════════════════════════════════════ */
function FeedbackTable({ model }) {
  const [filter, setFilter] = useState('All')
  const rows = FEEDBACK[model.id] ?? []

  const filtered = filter === 'All' ? rows
    : filter === 'Incorrect' ? rows.filter(r => !r.correct)
    : rows.filter(r => r.correct)

  const fpCount  = rows.filter(r => r.type === 'FP').length
  const fnCount  = rows.filter(r => r.type === 'FN').length
  const accuracy = Math.round((rows.filter(r => r.correct).length / rows.length) * 100)

  return (
    <div>
      {/* Mini stats row */}
      <div className="flex flex-wrap gap-2 mb-3">
        {[
          { label: 'Total',    val: rows.length,   cls: 'bg-slate-50 text-slate-700 border-slate-200' },
          { label: 'Correct',  val: rows.filter(r=>r.correct).length, cls: 'bg-sky-50 text-sky-700 border-sky-200' },
          { label: 'False +',  val: fpCount, cls: fpCount  > 0 ? 'bg-amber-50 text-amber-700 border-amber-200' : 'bg-slate-50 text-slate-400 border-slate-100' },
          { label: 'False −',  val: fnCount, cls: fnCount  > 0 ? 'bg-red-50 text-red-700 border-red-200'       : 'bg-slate-50 text-slate-400 border-slate-100' },
          { label: 'Accuracy', val: `${accuracy}%`, cls: accuracy >= 90 ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-700 border-amber-200' },
        ].map(({ label, val, cls }) => (
          <div key={label} className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[11px] font-bold ${cls}`}>
            <span className="font-normal text-[10px] opacity-70">{label}</span>
            <span>{val}</span>
          </div>
        ))}

        {/* Filter */}
        <div className="ml-auto flex items-center gap-1">
          {['All','Correct','Incorrect'].map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-2.5 py-1 rounded-lg text-[10px] font-bold transition-all ${
                filter === f
                  ? 'bg-sky-500 text-white shadow-sm'
                  : 'bg-slate-50 text-slate-500 hover:bg-sky-50 hover:text-sky-600 border border-slate-200'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-100">
        <table className="w-full text-[11px]">
          <thead>
            <tr className="bg-gradient-to-r from-sky-50 to-slate-50 border-b border-sky-100">
              <th className="text-left px-3 py-2.5 font-bold text-slate-500 uppercase tracking-wide whitespace-nowrap">#</th>
              <th className="text-left px-3 py-2.5 font-bold text-slate-500 uppercase tracking-wide whitespace-nowrap">Timestamp</th>
              <th className="text-left px-3 py-2.5 font-bold text-slate-500 uppercase tracking-wide">Content / Subject</th>
              <th className="text-left px-3 py-2.5 font-bold text-slate-500 uppercase tracking-wide whitespace-nowrap">Model Verdict</th>
              <th className="text-left px-3 py-2.5 font-bold text-slate-500 uppercase tracking-wide whitespace-nowrap">Analyst Verdict</th>
              <th className="text-left px-3 py-2.5 font-bold text-slate-500 uppercase tracking-wide whitespace-nowrap">Type</th>
              <th className="text-left px-3 py-2.5 font-bold text-slate-500 uppercase tracking-wide">Confidence</th>
              <th className="text-left px-3 py-2.5 font-bold text-slate-500 uppercase tracking-wide whitespace-nowrap">Reviewer</th>
            </tr>
          </thead>
          <tbody>
            <AnimatePresence mode="popLayout">
              {filtered.map((r, i) => (
                <motion.tr
                  key={r.id}
                  layout
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ delay: i * 0.03 }}
                  className={`border-b border-slate-50 last:border-0 transition-colors ${
                    !r.correct
                      ? 'bg-red-50/40 hover:bg-red-50/70'
                      : 'bg-white hover:bg-sky-50/40'
                  }`}
                >
                  <td className="px-3 py-2.5 text-slate-300 font-mono">{r.id}</td>
                  <td className="px-3 py-2.5 text-slate-400 whitespace-nowrap font-mono">{r.ts}</td>
                  <td className="px-3 py-2.5 max-w-[180px]">
                    <p className="truncate font-medium text-slate-700">{r.content}</p>
                  </td>
                  <td className="px-3 py-2.5"><VerdictChip verdict={r.modelVerdict} /></td>
                  <td className="px-3 py-2.5"><VerdictChip verdict={r.analystVerdict} /></td>
                  <td className="px-3 py-2.5"><TypeBadge type={r.type} /></td>
                  <td className="px-3 py-2.5"><ConfBar value={r.conf} /></td>
                  <td className="px-3 py-2.5 font-mono text-slate-400 whitespace-nowrap">{r.reviewer}</td>
                </motion.tr>
              ))}
            </AnimatePresence>
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="text-center py-8 text-slate-400 text-[12px]">
            No entries match the selected filter.
          </div>
        )}
      </div>
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════
   Per-model accordion card with retrain button
══════════════════════════════════════════════════════════════════ */
function ModelSection({ model, index }) {
  const [open,       setOpen]       = useState(index === 0)
  const [stats,      setStats]      = useState(null)
  const [loading,    setLoading]    = useState(true)
  const [retraining, setRetraining] = useState(false)
  const [log,        setLog]        = useState([])
  const [logOpen,    setLogOpen]    = useState(false)
  const [lastRun,    setLastRun]    = useState(null)
  const [error,      setError]      = useState(null)

  const Icon = model.icon
  const rows = FEEDBACK[model.id] ?? []
  const incorrectCount = rows.filter(r => !r.correct).length
  const queueSize  = stats?.queue_size ?? incorrectCount
  const canRetrain = queueSize >= MIN_QUEUE

  const fetchStats = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const res = await fetch(model.statusUrl)
      if (res.ok) setStats(await res.json())
      else setError('Service unavailable')
    } catch { setError('Cannot reach service') }
    finally { setLoading(false) }
  }, [model.statusUrl])

  useEffect(() => { fetchStats() }, [fetchStats])

  const triggerRetrain = async () => {
    setRetraining(true); setLog([]); setLogOpen(true); setError(null)
    try {
      const res  = await fetch(model.retrainUrl, { method: 'POST' })
      const data = await res.json()
      if (res.ok) {
        setLog(data.log || [data.message || `${model.label} retraining triggered.`])
        setLastRun(new Date().toLocaleString())
        setTimeout(fetchStats, 1500)
      } else {
        setLog([data.error || 'Retraining failed.'])
        setError(data.error || 'Retraining failed.')
      }
    } catch (e) {
      setLog([`Could not reach ${model.label} service.`])
      setError('Connection error')
    } finally { setRetraining(false) }
  }

  const accuracy = stats?.accuracy
    ?? Math.round((rows.filter(r => r.correct).length / Math.max(rows.length, 1)) * 100)

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.1, duration: 0.4 }}
      className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden"
    >
      {/* ── Header bar ── */}
      <div
        className="flex items-center gap-3 px-5 py-4 cursor-pointer select-none group"
        style={{ borderTop: `3px solid ${model.color}` }}
        onClick={() => setOpen(o => !o)}
      >
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${model.bg}`}>
          <Icon className={`text-[20px] ${model.text}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-[14px] font-bold text-slate-900">{model.fullLabel}</p>
            {incorrectCount > 0 && (
              <span className="px-2 py-0.5 rounded-full text-[10px] font-black bg-red-50 text-red-600 border border-red-100">
                {incorrectCount} error{incorrectCount > 1 ? 's' : ''}
              </span>
            )}
          </div>
          <p className="text-[11px] text-slate-400 truncate">{model.description}</p>
        </div>

        {/* Quick stats chips */}
        <div className="hidden sm:flex items-center gap-2 flex-shrink-0">
          <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-[11px] font-bold ${model.bg} ${model.text} ${model.border}`}>
            <RiShieldCheckLine className="text-[12px]" />
            {accuracy}% accuracy
          </div>
          <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-[11px] font-bold ${
            canRetrain ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-50 text-slate-500 border-slate-200'
          }`}>
            <RiDatabase2Line className="text-[12px]" />
            {queueSize} queued
          </div>
        </div>

        {/* Retrain button */}
        <button
          onClick={e => { e.stopPropagation(); triggerRetrain() }}
          disabled={retraining}
          className={`flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-[12px] font-bold transition-all shadow-sm flex-shrink-0 ${
            retraining
              ? 'bg-slate-100 text-slate-400 cursor-not-allowed'
              : `bg-gradient-to-r ${model.gradient} text-white hover:opacity-90 hover:shadow-md active:scale-95`
          }`}
        >
          {retraining
            ? <><RiLoader4Line className="animate-spin text-[14px]" /> Training…</>
            : <><RiPlayCircleLine className="text-[14px]" /> Retrain</>
          }
        </button>

        {/* Chevron */}
        <motion.div
          animate={{ rotate: open ? 180 : 0 }}
          transition={{ duration: 0.2 }}
          className="text-slate-300 text-[18px] flex-shrink-0"
        >▾</motion.div>
      </div>

      {/* ── Expanded content ── */}
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="body"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 border-t border-sky-50">
              {/* Queue + accuracy row */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 my-4">
                <div className="p-3 rounded-xl bg-sky-50/60 border border-sky-100">
                  <div className="flex justify-between items-center mb-1.5">
                    <span className="text-[11px] font-semibold text-slate-500">Retraining Queue</span>
                    <span className="text-[12px] font-black font-mono text-slate-800">{queueSize}/{MIN_QUEUE}</span>
                  </div>
                  <ProgressBar value={Math.min((queueSize / MIN_QUEUE) * 100, 100)} color={canRetrain ? 'green' : 'sky'} />
                  {!canRetrain && (
                    <p className="text-[10px] text-slate-400 mt-1.5">{MIN_QUEUE - queueSize} more correction(s) needed</p>
                  )}
                  {canRetrain && (
                    <p className="text-[10px] text-emerald-600 font-semibold mt-1.5">✓ Threshold met — ready to retrain</p>
                  )}
                </div>
                <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
                  <div className="flex justify-between items-center mb-1.5">
                    <span className="text-[11px] font-semibold text-slate-500">Human-Verified Accuracy</span>
                    <span className="text-[12px] font-black font-mono" style={{ color: model.color }}>{accuracy}%</span>
                  </div>
                  <div className="h-2 bg-slate-200 rounded-full overflow-hidden">
                    <motion.div
                      className="h-full rounded-full"
                      style={{ background: model.color }}
                      initial={{ width: 0 }}
                      animate={{ width: `${accuracy}%` }}
                      transition={{ duration: 1, ease: [0.34,1.2,0.64,1] }}
                    />
                  </div>
                  {lastRun && (
                    <p className="text-[10px] text-slate-400 mt-1.5 flex items-center gap-1">
                      <RiTimeLine className="text-[11px]" /> Last run: {lastRun}
                    </p>
                  )}
                </div>
              </div>

              {/* Feedback table */}
              <FeedbackTable model={model} />
            </div>

            {/* Retrain log */}
            <AnimatePresence>
              {logOpen && log.length > 0 && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="overflow-hidden border-t border-slate-100"
                >
                  <div className="px-5 py-3 bg-slate-900">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <RiHistoryLine className="text-slate-400 text-[13px]" />
                        <span className="text-[11px] font-mono font-bold text-slate-300 uppercase tracking-wide">
                          {model.label} · Retraining Log
                        </span>
                      </div>
                      <button onClick={() => setLogOpen(false)} className="text-slate-500 hover:text-slate-300">✕</button>
                    </div>
                    <div className="space-y-1.5">
                      {log.map((line, i) => (
                        <motion.p key={i}
                          initial={{ opacity: 0, x: -4 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.08 }}
                          className="text-[11px] font-mono text-emerald-400 flex items-start gap-2"
                        >
                          <span className="text-slate-500 flex-shrink-0">{'>'}</span>{line}
                        </motion.p>
                      ))}
                      {retraining && (
                        <p className="text-[11px] font-mono text-sky-400 flex items-center gap-2">
                          <RiLoader4Line className="animate-spin text-[13px]" /> Processing…
                        </p>
                      )}
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

/* ══════════════════════════════════════════════════════════════════
   Charts section
══════════════════════════════════════════════════════════════════ */
function ChartsSection() {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-6">

      {/* 1. Accuracy Trend — Line chart */}
      <div className="lg:col-span-2 bg-white rounded-2xl border border-slate-100 shadow-sm p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <p className="text-[14px] font-bold text-slate-900">Accuracy Trend</p>
            <p className="text-[11px] text-slate-400">7-week rolling accuracy per model</p>
          </div>
          <div className="flex items-center gap-3 text-[10px] font-semibold">
            {[
              { label: 'Voice',   color: '#8B5CF6' },
              { label: 'Website', color: '#0EA5E9' },
              { label: 'Email',   color: '#10B981' },
            ].map(({ label, color }) => (
              <span key={label} className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full" style={{ background: color }} />
                <span className="text-slate-500">{label}</span>
              </span>
            ))}
          </div>
        </div>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={ACC_TREND} margin={{ top: 4, right: 8, bottom: 4, left: -20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" />
            <XAxis dataKey="week" tick={{ fontSize: 11, fill: '#94A3B8' }} axisLine={false} tickLine={false} />
            <YAxis domain={[75, 100]} tick={{ fontSize: 11, fill: '#94A3B8' }} axisLine={false} tickLine={false} unit="%" />
            <Tooltip content={<ChartTooltip />} />
            <Line dataKey="voice"   stroke="#8B5CF6" strokeWidth={2.5} dot={{ r: 3, fill: '#8B5CF6' }} activeDot={{ r: 5 }} name="Voice"   unit="%" />
            <Line dataKey="website" stroke="#0EA5E9" strokeWidth={2.5} dot={{ r: 3, fill: '#0EA5E9' }} activeDot={{ r: 5 }} name="Website" unit="%" />
            <Line dataKey="email"   stroke="#10B981" strokeWidth={2.5} dot={{ r: 3, fill: '#10B981' }} activeDot={{ r: 5 }} name="Email"   unit="%" />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* 2. Pie — Feedback type breakdown */}
      <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-5">
        <div className="mb-3">
          <p className="text-[14px] font-bold text-slate-900">Feedback Breakdown</p>
          <p className="text-[11px] text-slate-400">TP / TN / FP / FN across all models</p>
        </div>
        <div className="flex items-center gap-3">
          <ResponsiveContainer width={130} height={130}>
            <PieChart>
              <Pie data={PIE_DATA} cx="50%" cy="50%" innerRadius={34} outerRadius={54}
                dataKey="value" stroke="none">
                {PIE_DATA.map((d, i) => <Cell key={i} fill={d.color} />)}
              </Pie>
              <Tooltip content={<ChartTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-col gap-1.5 text-[11px]">
            {PIE_DATA.map(d => (
              <div key={d.name} className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ background: d.color }} />
                <span className="text-slate-500">{d.name}</span>
                <span className="ml-auto font-bold text-slate-800">{d.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 3. FP / FN bar chart */}
      <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-5">
        <div className="mb-4">
          <p className="text-[14px] font-bold text-slate-900">False Positives / Negatives</p>
          <p className="text-[11px] text-slate-400">Error distribution per model</p>
        </div>
        <ResponsiveContainer width="100%" height={160}>
          <BarChart data={FP_FN_DATA} margin={{ top: 4, right: 8, bottom: 4, left: -24 }} barSize={16} barGap={4}>
            <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" vertical={false} />
            <XAxis dataKey="model" tick={{ fontSize: 11, fill: '#94A3B8' }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fontSize: 11, fill: '#94A3B8' }} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip content={<ChartTooltip />} />
            <Bar dataKey="fp" name="False Positives" fill={AMBER} radius={[4,4,0,0]} />
            <Bar dataKey="fn" name="False Negatives" fill={RED}   radius={[4,4,0,0]} />
          </BarChart>
        </ResponsiveContainer>
        <div className="flex items-center gap-4 mt-2 text-[10px] font-semibold text-slate-400">
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-amber-400"/>&nbsp;False Positive</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-400"/>&nbsp;False Negative</span>
        </div>
      </div>

      {/* 4. Radial accuracy per model */}
      <div className="lg:col-span-2 bg-white rounded-2xl border border-slate-100 shadow-sm p-5">
        <div className="mb-3">
          <p className="text-[14px] font-bold text-slate-900">Model Accuracy Comparison</p>
          <p className="text-[11px] text-slate-400">Human-verified accuracy per detection model</p>
        </div>
        <div className="flex items-center gap-6">
          <ResponsiveContainer width={180} height={160}>
            <RadialBarChart cx="50%" cy="50%" innerRadius={20} outerRadius={70}
              data={RADIAL_DATA} startAngle={90} endAngle={-270}>
              <RadialBar dataKey="accuracy" background={{ fill: '#F1F5F9' }} cornerRadius={6} />
              <Tooltip content={<ChartTooltip />} />
            </RadialBarChart>
          </ResponsiveContainer>
          <div className="flex-1 space-y-3">
            {RADIAL_DATA.map(d => (
              <div key={d.name}>
                <div className="flex justify-between text-[12px] font-medium text-slate-500 mb-1">
                  <span>{d.name}</span>
                  <span className="font-black" style={{ color: d.fill }}>{d.accuracy}%</span>
                </div>
                <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                  <motion.div
                    className="h-full rounded-full"
                    style={{ background: d.fill }}
                    initial={{ width: 0 }}
                    animate={{ width: `${d.accuracy}%` }}
                    transition={{ duration: 1.2, ease: [0.34,1.2,0.64,1] }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════
   Nightly Scheduler Panel
══════════════════════════════════════════════════════════════════ */
function SchedulerPanel() {
  const [sched,       setSched]       = useState(null)
  const [history,     setHistory]     = useState([])
  const [loading,     setLoading]     = useState(true)
  const [triggering,  setTriggering]  = useState(false)
  const [saving,      setSaving]      = useState(false)
  const [error,       setError]       = useState(null)
  const [editHour,    setEditHour]    = useState('')
  const [editMinute,  setEditMinute]  = useState('')
  const [showHistory, setShowHistory] = useState(false)
  const [trigLog,     setTrigLog]     = useState([])
  const timerRef = useRef(null)

  const fetchStatus = useCallback(async () => {
    try {
      const [sRes, hRes] = await Promise.all([
        fetch(SCHEDULER_STATUS_URL),
        fetch(`${SCHEDULER_HISTORY_URL}?limit=5`),
      ])
      if (sRes.ok) {
        const d = await sRes.json()
        setSched(d)
        setEditHour(String(d.schedule?.hour ?? 2).padStart(2, '0'))
        setEditMinute(String(d.schedule?.minute ?? 0).padStart(2, '0'))
      }
      if (hRes.ok) setHistory((await hRes.json()).history ?? [])
      setError(null)
    } catch {
      setError('Scheduler service unreachable')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchStatus()
    timerRef.current = setInterval(fetchStatus, 30000)
    return () => clearInterval(timerRef.current)
  }, [fetchStatus])

  const toggleEnabled = async () => {
    if (!sched) return
    setSaving(true)
    try {
      const res = await fetch(SCHEDULER_UPDATE_URL, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !sched.enabled }),
      })
      if (res.ok) await fetchStatus()
    } finally { setSaving(false) }
  }

  const saveSchedule = async () => {
    const h = parseInt(editHour, 10)
    const m = parseInt(editMinute, 10)
    if (isNaN(h) || h < 0 || h > 23) return
    if (isNaN(m) || m < 0 || m > 59) return
    setSaving(true)
    try {
      const res = await fetch(SCHEDULER_UPDATE_URL, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hour: h, minute: m }),
      })
      if (res.ok) await fetchStatus()
    } finally { setSaving(false) }
  }

  const triggerNow = async () => {
    setTriggering(true)
    setTrigLog([])
    try {
      const res  = await fetch(SCHEDULER_TRIGGER_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
      const data = await res.json()
      if (res.ok && data.results) {
        const logs = Object.entries(data.results).map(([mid, r]) =>
          `${mid}: ${r.status} — ${r.message} (${r.duration_s}s)`
        )
        setTrigLog(logs)
        await fetchStatus()
      } else {
        setTrigLog([data.detail || 'Trigger failed'])
      }
    } catch {
      setTrigLog(['Could not reach scheduler service'])
    } finally { setTriggering(false) }
  }

  const fmtTime = iso => {
    if (!iso) return '—'
    try { return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) }
    catch { return iso }
  }

  const scheduleChanged =
    sched && (
      parseInt(editHour, 10) !== sched.schedule?.hour ||
      parseInt(editMinute, 10) !== sched.schedule?.minute
    )

  const MODEL_META = {
    voice:   { label: 'Voice',   color: '#8B5CF6' },
    website: { label: 'Website', color: '#0EA5E9' },
    email:   { label: 'Email',   color: '#10B981' },
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden mb-6"
    >
      {/* Header */}
      <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-50"
           style={{ borderTop: '3px solid #0EA5E9' }}>
        <div className="w-10 h-10 rounded-xl bg-sky-50 flex items-center justify-center flex-shrink-0">
          <RiCalendarLine className="text-sky-600 text-[20px]" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-[14px] font-bold text-slate-900">Nightly Auto-Retraining</p>
          <p className="text-[11px] text-slate-400">
            Automatically triggers all models at a scheduled time each night
          </p>
        </div>

        {/* Enable toggle */}
        <button
          onClick={toggleEnabled}
          disabled={saving || loading}
          title={sched?.enabled ? 'Disable scheduler' : 'Enable scheduler'}
          className="flex items-center gap-2 px-3 py-1.5 rounded-xl border text-[12px] font-semibold transition-all"
          style={sched?.enabled
            ? { background: '#EFF6FF', color: '#2563EB', borderColor: '#BFDBFE' }
            : { background: '#F8FAFC', color: '#94A3B8', borderColor: '#E2E8F0' }}
        >
          {sched?.enabled
            ? <RiToggleFill className="text-[18px] text-blue-500" />
            : <RiToggleLine className="text-[18px]" />}
          {sched?.enabled ? 'Enabled' : 'Disabled'}
        </button>

        {/* Trigger Now */}
        <button
          onClick={triggerNow}
          disabled={triggering || loading}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-[12px] font-bold transition-all shadow-sm bg-gradient-to-r from-sky-500 to-blue-600 text-white hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {triggering
            ? <><RiLoader4Line className="animate-spin text-[14px]" /> Running…</>
            : <><RiPlayCircleLine className="text-[14px]" /> Run Now</>}
        </button>

        <button onClick={fetchStatus} className="text-slate-400 hover:text-sky-500 transition-colors p-1">
          <RiRefreshLine className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      <div className="px-5 py-4">
        {error && (
          <div className="mb-4 px-4 py-2.5 rounded-xl bg-red-50 border border-red-100 text-[12px] text-red-600 font-medium flex items-center gap-2">
            <RiErrorWarningLine /> {error}
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">

          {/* Schedule time editor */}
          <div className="col-span-1 sm:col-span-2 p-4 rounded-xl bg-sky-50/60 border border-sky-100">
            <p className="text-[11px] font-semibold text-slate-500 mb-3 flex items-center gap-1.5">
              <RiSettings3Line /> Schedule Time (24-hr, UTC)
            </p>
            <div className="flex items-center gap-2">
              <input
                type="number" min="0" max="23"
                value={editHour}
                onChange={e => setEditHour(e.target.value)}
                className="w-16 text-center font-mono text-[16px] font-black text-slate-800 bg-white border border-sky-200 rounded-xl px-2 py-2 focus:outline-none focus:ring-2 focus:ring-sky-300"
              />
              <span className="text-[18px] font-black text-slate-400">:</span>
              <input
                type="number" min="0" max="59"
                value={editMinute}
                onChange={e => setEditMinute(e.target.value)}
                className="w-16 text-center font-mono text-[16px] font-black text-slate-800 bg-white border border-sky-200 rounded-xl px-2 py-2 focus:outline-none focus:ring-2 focus:ring-sky-300"
              />
              <span className="text-[12px] font-semibold text-slate-400 ml-1">UTC</span>
              {scheduleChanged && (
                <button
                  onClick={saveSchedule}
                  disabled={saving}
                  className="ml-auto flex items-center gap-1.5 px-3 py-2 rounded-xl bg-sky-500 text-white text-[11px] font-bold hover:bg-sky-600 disabled:opacity-50 transition-all"
                >
                  {saving ? <RiLoader4Line className="animate-spin" /> : <RiCheckboxCircleLine />}
                  Save
                </button>
              )}
            </div>
            <p className="text-[10px] text-slate-400 mt-2">
              Cron: <span className="font-mono font-bold">{sched?.schedule?.cron_expression ?? '0 2 * * *'}</span>
            </p>
          </div>

          {/* Next run */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-100">
            <p className="text-[11px] font-semibold text-slate-500 mb-1">Next Run</p>
            <p className="text-[13px] font-black text-slate-800">
              {loading ? '—' : fmtTime(sched?.next_run)}
            </p>
            <p className="text-[10px] text-slate-400 mt-1">
              {sched?.enabled ? '🟢 Scheduler active' : '⏸ Scheduler paused'}
            </p>
          </div>

          {/* Last run */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-100">
            <p className="text-[11px] font-semibold text-slate-500 mb-1">Last Run</p>
            <p className="text-[13px] font-black text-slate-800">
              {loading ? '—' : fmtTime(sched?.last_run)}
            </p>
            {sched?.last_run_results && Object.keys(sched.last_run_results).length > 0 && (
              <div className="flex flex-wrap gap-1 mt-2">
                {Object.entries(sched.last_run_results).map(([mid, r]) => (
                  <span key={mid}
                    className={`px-1.5 py-0.5 rounded text-[9px] font-black border ${
                      r.status === 'ok' || r.status === 'started'
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : r.status === 'skipped'
                        ? 'bg-slate-50 text-slate-500 border-slate-200'
                        : 'bg-red-50 text-red-600 border-red-200'
                    }`}
                  >
                    {MODEL_META[mid]?.label ?? mid}: {r.status}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Live trigger log */}
        <AnimatePresence>
          {trigLog.length > 0 && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden mt-4"
            >
              <div className="rounded-xl bg-slate-900 px-4 py-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] font-mono font-bold text-slate-300 uppercase tracking-wide flex items-center gap-2">
                    <RiHistoryLine className="text-slate-400" /> Trigger Log
                  </span>
                  <button onClick={() => setTrigLog([])} className="text-slate-500 hover:text-slate-300 text-[12px]">✕</button>
                </div>
                {trigLog.map((line, i) => (
                  <motion.p key={i}
                    initial={{ opacity: 0, x: -4 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.08 }}
                    className="text-[11px] font-mono text-emerald-400 flex items-start gap-2"
                  >
                    <span className="text-slate-500">›</span> {line}
                  </motion.p>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* History toggle */}
        <div className="mt-4">
          <button
            onClick={() => setShowHistory(h => !h)}
            className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-400 hover:text-sky-500 transition-colors"
          >
            <RiHistoryLine />
            {showHistory ? 'Hide' : 'Show'} run history ({history.length})
          </button>

          <AnimatePresence>
            {showHistory && history.length > 0 && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="overflow-hidden"
              >
                <div className="mt-3 space-y-2">
                  {history.map((run, i) => (
                    <div key={i} className="p-3 rounded-xl bg-slate-50 border border-slate-100 text-[11px]">
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="font-semibold text-slate-600 flex items-center gap-1.5">
                          <RiTimeLine className="text-slate-400" />
                          {fmtTime(run.run_at)}
                        </span>
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${
                          run.triggered_by === 'scheduler'
                            ? 'bg-sky-50 text-sky-600 border-sky-200'
                            : 'bg-purple-50 text-purple-600 border-purple-200'
                        }`}>
                          {run.triggered_by}
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {Object.entries(run.models ?? {}).map(([mid, r]) => (
                          <span key={mid}
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                              r.status === 'ok' || r.status === 'started'
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                : r.status === 'skipped'
                                ? 'bg-slate-100 text-slate-500 border-slate-200'
                                : 'bg-red-50 text-red-600 border-red-200'
                            }`}
                          >
                            {MODEL_META[mid]?.label ?? mid} · {r.status}
                            {r.queue_size > 0 && ` · ${r.queue_size} samples`}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
            {showHistory && history.length === 0 && (
              <motion.p
                initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                className="mt-2 text-[11px] text-slate-400"
              >
                No run history yet.
              </motion.p>
            )}
          </AnimatePresence>
        </div>
      </div>
    </motion.div>
  )
}

/* ══════════════════════════════════════════════════════════════════
   Main Page
══════════════════════════════════════════════════════════════════ */
export default function ModelRetraining() {
  const totalFeedback = Object.values(FEEDBACK).flat().length
  const totalIncorrect = Object.values(FEEDBACK).flat().filter(r => !r.correct).length
  const totalFP = Object.values(FEEDBACK).flat().filter(r => r.type === 'FP').length
  const totalFN = Object.values(FEEDBACK).flat().filter(r => r.type === 'FN').length
  const avgAcc  = Math.round(RADIAL_DATA.reduce((a, d) => a + d.accuracy, 0) / RADIAL_DATA.length)

  return (
    <PageWrapper>
      {/* Page header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-[22px] font-black text-slate-900 mb-1 flex items-center gap-2">
            <span className="w-8 h-8 rounded-xl bg-sky-500 flex items-center justify-center">
              <RiBrainLine className="text-white text-[16px]" />
            </span>
            Model Retraining Centre
          </h1>
          <p className="text-[12px] text-slate-400">Human-in-the-loop feedback pipeline · Per-model queue management · On-demand improvement</p>
        </div>
        <div className="flex items-center gap-2">
          <button className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 text-[12px] font-semibold text-slate-600 hover:bg-sky-50 hover:border-sky-200 hover:text-sky-600 transition-all">
            <RiDownloadLine className="text-[14px]" /> Export CSV
          </button>
          <button className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-sky-500 text-white text-[12px] font-semibold hover:bg-sky-600 transition-all shadow-sm">
            <RiRefreshLine className="text-[14px]" /> Refresh All
          </button>
        </div>
      </div>

      {/* ── Global stats strip ── */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 mb-6">
        <StatTile icon={RiDatabase2Line}     label="Total Feedback"  value={totalFeedback} sub="All models combined"  iconCls="bg-sky-50 text-sky-600"     delay={0}    trend="+12" trendUp />
        <StatTile icon={RiCheckboxCircleLine} label="Avg Accuracy"   value={`${avgAcc}%`}  sub="Human-verified"      iconCls="bg-emerald-50 text-emerald-600" delay={0.05} trend="+2.1%" trendUp />
        <StatTile icon={RiErrorWarningLine}  label="False Positives" value={totalFP}        sub="Flagged for review"  iconCls="bg-amber-50 text-amber-600"  delay={0.1} />
        <StatTile icon={RiAlertLine}         label="False Negatives" value={totalFN}        sub="Missed threats"      iconCls="bg-red-50 text-red-500"      delay={0.15} />
        <StatTile icon={RiPulseLine}         label="Total Errors"    value={totalIncorrect} sub="Queued for retrain"  iconCls="bg-purple-50 text-purple-600" delay={0.2} />
      </div>

      {/* ── Nightly Scheduler Panel ── */}
      <SchedulerPanel />

      {/* ── How it works banner ── */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="bg-gradient-to-r from-sky-50 via-blue-50 to-indigo-50 border border-sky-100 rounded-2xl px-5 py-4 mb-6"
      >
        <div className="flex items-start gap-3">
          <div className="w-8 h-8 rounded-xl bg-sky-100 flex items-center justify-center flex-shrink-0">
            <RiEyeLine className="text-sky-600 text-[16px]" />
          </div>
          <div className="flex-1">
            <p className="text-[13px] font-bold text-slate-800 mb-1">How Individual Model Retraining Works</p>
            <p className="text-[12px] text-slate-500 leading-relaxed">
              Each model maintains its own correction queue. Analysts submit feedback on incorrect predictions — those are logged as
              False Positives or False Negatives in the table below. The <strong className="text-sky-700">Nightly Scheduler</strong> (above)
              automatically triggers all models each night, or an admin can trigger any model on-demand once its queue reaches&nbsp;
              <strong className="text-sky-700">{MIN_QUEUE} corrections</strong>.
            </p>
            <div className="flex flex-wrap gap-4 mt-2.5 text-[11px] text-slate-400">
              <span className="flex items-center gap-1"><RiCheckboxCircleLine className="text-emerald-500 text-[13px]" /> Analyst flags incorrect prediction</span>
              <span className="flex items-center gap-1"><RiDatabase2Line className="text-sky-500 text-[13px]" /> Correction queued per-model</span>
              <span className="flex items-center gap-1"><RiPlayCircleLine className="text-purple-500 text-[13px]" /> Admin triggers individual model retraining</span>
              <span className="flex items-center gap-1"><RiBarChartLine className="text-blue-500 text-[13px]" /> Accuracy improves with each cycle</span>
            </div>
          </div>
        </div>
      </motion.div>

      {/* ── Charts ── */}
      <ChartsSection />

      {/* ── Per-model accordion sections ── */}
      <div className="mb-4 flex items-center gap-2">
        <div className="flex-1 h-px bg-gradient-to-r from-sky-100 to-transparent" />
        <p className="text-[11px] font-bold text-slate-400 uppercase tracking-widest px-2">Per-Model Feedback & Retraining</p>
        <div className="flex-1 h-px bg-gradient-to-l from-sky-100 to-transparent" />
      </div>

      <div className="space-y-4">
        {MODELS.map((model, i) => (
          <ModelSection key={model.id} model={model} index={i} />
        ))}
      </div>

      <motion.p
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.6 }}
        className="text-[11px] text-slate-400 text-center mt-6"
      >
        All retraining runs are logged and auditable. Human corrections are stored with timestamps and reviewer IDs.
        Models are fine-tuned on accumulated feedback to reduce future errors.
      </motion.p>
    </PageWrapper>
  )
}

