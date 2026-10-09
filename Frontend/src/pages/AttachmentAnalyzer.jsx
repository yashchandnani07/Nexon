import { useState, useRef, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiFolderOpenLine, RiFileDamageLine, RiCheckboxCircleLine,
  RiAlertLine, RiDownloadLine, RiLoader4Line, RiFileList3Line,
  RiArrowDownSLine, RiArrowUpSLine, RiShieldCheckLine,
  RiSearchLine, RiDatabase2Line, RiScales3Line,
  RiFileCopyLine, RiErrorWarningLine, RiInformationLine,
  RiHistoryLine, RiRefreshLine, RiFileTextLine, RiFileCodeLine,
  RiFilePdfLine, RiFileZipLine, RiFileWarningLine, RiShieldLine,
  RiTimeLine, RiHtml5Line, RiImageLine, RiKeyLine, RiQuestionLine,
  RiLightbulbLine,
} from 'react-icons/ri'
import {
  Card, Btn, RiskBadge, ScoreMeter, ResultPanel,
  PageWrapper, SectionHeader, SidebarStat, SubTabs,
} from '../components/ui'

const fileTypes = ['PDF', 'DOCX / XLSX', 'EXE / PE', 'ZIP / RAR', 'HTML / HTM', 'Images', 'JAR', 'PY / JS']

/* ── File icon by extension ──────────────────────────────────────────────── */
function FileIcon({ filename, className = 'text-base' }) {
  const ext = filename?.split('.').pop()?.toLowerCase() || ''
  if (['pdf'].includes(ext))                               return <RiFilePdfLine  className={`text-red-400 ${className}`} />
  if (['zip','rar','7z','gz','tar'].includes(ext))         return <RiFileZipLine  className={`text-amber-400 ${className}`} />
  if (['js','py','rb','pl','sh','vbs','ps1'].includes(ext))return <RiFileCodeLine className={`text-purple-400 ${className}`} />
  if (['doc','docx','xls','xlsx','ppt','pptx','docm','xlsm'].includes(ext))
                                                           return <RiFileTextLine className={`text-blue-400 ${className}`} />
  if (['exe','dll','sys','drv','msi'].includes(ext))       return <RiFileWarningLine className={`text-red-500 ${className}`} />
  if (['htm','html','xhtml','shtml','svg'].includes(ext))  return <RiHtml5Line   className={`text-orange-400 ${className}`} />
  if (['jpg','jpeg','png','gif','bmp','webp','tiff','tif','ico'].includes(ext))
                                                           return <RiImageLine   className={`text-teal-400 ${className}`} />
  return <RiFileList3Line className={`text-slate-400 ${className}`} />
}

/* ── Relative time formatter ─────────────────────────────────────────────── */
function relativeTime(isoStr) {
  if (!isoStr) return '—'
  const diff = Date.now() - new Date(isoStr).getTime()
  const secs  = Math.floor(diff / 1000)
  if (secs < 60)  return 'just now'
  const mins = Math.floor(secs / 60)
  if (mins < 60)  return `${mins}m ago`
  const hrs  = Math.floor(mins / 60)
  if (hrs  < 24)  return `${hrs}h ago`
  const days = Math.floor(hrs  / 24)
  return `${days}d ago`
}

/* ── Risk color for history rows ─────────────────────────────────────────── */
const RISK_ROW = {
  Critical: { bar: 'bg-red-500',     text: 'text-red-700',    bg: 'bg-red-50'     },
  High:     { bar: 'bg-orange-500',  text: 'text-orange-700', bg: 'bg-orange-50'  },
  Medium:   { bar: 'bg-amber-500',   text: 'text-amber-700',  bg: 'bg-amber-50'   },
  Low:      { bar: 'bg-blue-400',    text: 'text-blue-700',   bg: 'bg-blue-50'    },
  Clean:    { bar: 'bg-emerald-500', text: 'text-emerald-700',bg: 'bg-emerald-50' },
}

/* ── History row (expandable) ────────────────────────────────────────────── */
function HistoryRow({ row, index }) {
  const [open, setOpen] = useState(false)
  const cfg = RISK_ROW[row.risk_label] ?? RISK_ROW.Clean

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.03, duration: 0.2 }}
      className="rounded-xl border border-slate-100 overflow-hidden bg-white hover:shadow-sm transition-shadow"
    >
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-slate-50 transition-colors"
      >
        {/* Left accent bar */}
        <div className={`w-1 h-10 rounded-full flex-shrink-0 ${cfg.bar}`} />

        {/* File icon */}
        <FileIcon filename={row.filename} className="text-lg flex-shrink-0" />

        {/* Filename + meta */}
        <div className="flex-1 min-w-0">
          <p className="text-[13px] font-semibold text-slate-800 truncate">{row.filename}</p>
          <p className="text-[11px] text-slate-400">
            {row.file_size_kb ? `${Number(row.file_size_kb).toFixed(1)} KB` : '—'}
            {row.total_findings > 0 && ` · ${row.total_findings} indicator${row.total_findings !== 1 ? 's' : ''}`}
            {row.analysis_time_ms && ` · ${Math.round(row.analysis_time_ms)}ms`}
          </p>
        </div>

        {/* Risk label */}
        <div className={`px-2.5 py-1 rounded-full text-[11px] font-bold flex-shrink-0 ${cfg.bg} ${cfg.text}`}>
          {row.risk_label || 'Unknown'}
        </div>

        {/* Score ring (mini) */}
        <div className="flex-shrink-0 hidden sm:flex items-center justify-center w-9 h-9 rounded-full border-2 border-slate-200">
          <span className={`text-[11px] font-bold ${cfg.text}`}>{row.risk_score ?? '—'}</span>
        </div>

        {/* Severity mini-chips */}
        <div className="hidden md:flex items-center gap-1 flex-shrink-0">
          {row.critical_count > 0 && (
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-100 text-red-700">{row.critical_count}C</span>
          )}
          {row.high_count > 0 && (
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-orange-100 text-orange-700">{row.high_count}H</span>
          )}
          {row.medium_count > 0 && (
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-amber-100 text-amber-700">{row.medium_count}M</span>
          )}
        </div>

        {/* Time */}
        <div className="flex items-center gap-1 text-[11px] text-slate-400 flex-shrink-0">
          <RiTimeLine className="text-xs" />
          {relativeTime(row.scanned_at)}
        </div>

        <span className="text-slate-300 flex-shrink-0">{open ? <RiArrowUpSLine /> : <RiArrowDownSLine />}</span>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="border-t border-slate-100 bg-slate-50 px-5 py-4 space-y-2"
          >
            {row.human_summary && (
              <p className="text-[12px] text-slate-700">
                <span className="font-semibold text-slate-900">Assessment: </span>
                {row.human_summary}
              </p>
            )}
            {row.recommended_action && (
              <p className={`text-[12px] font-medium ${cfg.text}`}>
                <span className="font-semibold">Action: </span>
                {row.recommended_action}
              </p>
            )}
            <p className="text-[10px] text-slate-400">
              Scanned: {row.scanned_at ? new Date(row.scanned_at).toLocaleString() : '—'}
              {row.id && ` · ID #${row.id}`}
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

/* ── Scan History panel ───────────────────────────────────────────────────── */
function ScanHistory({ refreshTrigger }) {
  const [history, setHistory]     = useState([])
  const [loading, setLoading]     = useState(false)
  const [histError, setHistError] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)
  const [filter, setFilter]       = useState('All')

  const FILTERS = ['All', 'Critical', 'High', 'Medium', 'Low', 'Clean']

  const fetchHistory = useCallback(async () => {
    setLoading(true)
    setHistError(null)
    try {
      const res = await fetch('/api/attachment-scan/history?limit=50')
      if (res.ok) {
        const data = await res.json()
        setHistory(data.history || [])
        setLastRefresh(new Date())
      } else {
        setHistError(`Server returned ${res.status}`)
      }
    } catch (e) {
      setHistError('Could not reach scanner service — is it running?')
      console.warn('History fetch failed:', e)
    } finally {
      setLoading(false)
    }
  }, [])

  // Load on mount and whenever a new scan completes
  useEffect(() => { fetchHistory() }, [fetchHistory, refreshTrigger])

  const filtered = filter === 'All'
    ? history
    : history.filter(r => r.risk_label === filter)

  // Stats from history
  const stats = {
    total:    history.length,
    malicious: history.filter(r => r.risk_label !== 'Clean').length,
    critical:  history.filter(r => r.risk_label === 'Critical').length,
  }

  return (
    <div className="space-y-4">
      {/* Stats bar */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Total Scans',    value: stats.total,    color: 'text-slate-700 bg-slate-50 border-slate-200' },
          { label: 'Malicious',      value: stats.malicious,color: 'text-orange-700 bg-orange-50 border-orange-200' },
          { label: 'Critical Flags', value: stats.critical, color: 'text-red-700 bg-red-50 border-red-200' },
        ].map(({ label, value, color }) => (
          <div key={label} className={`p-3 rounded-xl border flex flex-col items-center text-center ${color}`}>
            <span className="text-[10px] font-semibold opacity-70 uppercase tracking-wide">{label}</span>
            <span className="text-2xl font-bold leading-tight">{value}</span>
          </div>
        ))}
      </div>

      {/* Filter + Refresh row */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-1 flex-wrap">
          {FILTERS.map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-colors ${
                filter === f
                  ? 'bg-sky-500 text-white'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
        <button
          onClick={fetchHistory}
          disabled={loading}
          className="flex items-center gap-1 text-[11px] text-slate-500 hover:text-sky-500 transition-colors disabled:opacity-40"
        >
          <motion.span animate={loading ? { rotate: 360 } : {}} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
            <RiRefreshLine />
          </motion.span>
          {lastRefresh ? `Updated ${relativeTime(lastRefresh.toISOString())}` : 'Refresh'}
        </button>
      </div>

      {/* History list */}
      {loading && history.length === 0 ? (
        <div className="flex items-center justify-center py-12 text-slate-400 gap-2">
          <motion.span animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
            <RiLoader4Line />
          </motion.span>
          Loading history...
        </div>
      ) : histError ? (
        <div className="flex items-center gap-2 p-4 rounded-xl bg-red-50 border border-red-200 text-red-700 text-[12px]">
          <RiAlertLine className="text-base flex-shrink-0" />
          <span>{histError}</span>
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-slate-400 gap-2">
          <RiHistoryLine className="text-3xl text-slate-300" />
          <p className="text-[13px] font-medium">
            {filter === 'All' ? 'No scans yet — upload a file to get started' : `No ${filter} scans in history`}
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((row, i) => <HistoryRow key={row.id ?? i} row={row} index={i} />)}
        </div>
      )}
    </div>
  )
}

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', dot: 'bg-red-500',     text: 'text-red-700',    bg: 'bg-red-50',    border: 'border-red-200'   },
  high:     { label: 'High',     dot: 'bg-orange-500',  text: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-200'},
  medium:   { label: 'Medium',   dot: 'bg-amber-500',   text: 'text-amber-700',  bg: 'bg-amber-50',  border: 'border-amber-200' },
  low:      { label: 'Low',      dot: 'bg-blue-400',    text: 'text-blue-700',   bg: 'bg-blue-50',   border: 'border-blue-200'  },
  info:     { label: 'Info',     dot: 'bg-slate-400',   text: 'text-slate-600',  bg: 'bg-slate-50',  border: 'border-slate-200' },
  clean:    { label: 'Clean',    dot: 'bg-emerald-500', text: 'text-emerald-700',bg: 'bg-emerald-50',border: 'border-emerald-200'},
}

function StatusPill({ status }) {
  const cfg = SEVERITY_CONFIG[status] ?? SEVERITY_CONFIG.info
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold ${cfg.bg} ${cfg.text} ${cfg.border} border`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  )
}

function TierBadge({ tier }) {
  const t = (tier || 'info').toLowerCase()
  const cfg = SEVERITY_CONFIG[t] ?? SEVERITY_CONFIG.info
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${cfg.bg} ${cfg.text}`}>
      {cfg.label}
    </span>
  )
}

/* ── Finding row (expandable) ────────────────────────────────────────────── */
function FindingRow({ finding, index }) {
  const [open, setOpen] = useState(false)
  const tier = (finding.risk_tier || 'Low').toLowerCase()
  const cfg  = SEVERITY_CONFIG[tier] ?? SEVERITY_CONFIG.info

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.04 }}
      className={`rounded-lg border ${cfg.border} overflow-hidden`}
    >
      <button
        onClick={() => setOpen(o => !o)}
        className={`w-full flex items-center gap-3 px-3 py-2.5 text-left ${cfg.bg} hover:opacity-90 transition-opacity`}
      >
        <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${cfg.dot}`} />
        <span className="flex-1 text-[12px] font-medium text-slate-800 leading-snug">{finding.description}</span>
        <TierBadge tier={finding.risk_tier} />
        <span className="text-slate-400 text-sm ml-1">{open ? <RiArrowUpSLine /> : <RiArrowDownSLine />}</span>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="bg-white border-t border-slate-100 px-4 py-3 space-y-2"
          >
            {finding.why_flagged && (
              <div className="flex items-start gap-2 p-2.5 rounded-lg bg-amber-50 border border-amber-200">
                <RiLightbulbLine className="text-amber-500 mt-0.5 flex-shrink-0 text-sm" />
                <p className="text-[11px] text-amber-800 leading-snug">
                  <span className="font-semibold">Why flagged: </span>{finding.why_flagged}
                </p>
              </div>
            )}
            {finding.detail && (
              <p className="text-[11px] text-slate-600"><span className="font-semibold">Detail: </span>{finding.detail}</p>
            )}
            {finding.rule && (
              <p className="text-[11px] text-slate-500 font-mono break-all"><span className="font-semibold not-mono text-slate-600">Rule: </span>{finding.rule}</p>
            )}
            {finding.category && (
              <p className="text-[11px] text-slate-500"><span className="font-semibold text-slate-600">Category: </span>{finding.category}</p>
            )}
            {finding.context && (
              <div className="mt-2 p-2 rounded bg-slate-900 text-[10px] font-mono text-green-400 overflow-x-auto whitespace-pre-wrap break-all">
                {finding.context}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

/* ── Analyzer accordion inside Phase 2 ──────────────────────────────────── */
function AnalyzerSection({ analyzer, index }) {
  const [open, setOpen] = useState(analyzer.findings_count > 0)
  const cfg = SEVERITY_CONFIG[analyzer.status] ?? SEVERITY_CONFIG.clean

  const isCredential = analyzer.name === 'Credential Exposure Scanner'
  const isHtml       = analyzer.name === 'HTML Analyzer'
  const isImage      = analyzer.name === 'Image Analyzer'
  const isDeepScan   = analyzer.name === 'ZIP Deep Scan'

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.08 }}
      className={`rounded-xl border overflow-hidden ${
        isCredential ? 'border-teal-200' : isHtml ? 'border-orange-200' : isImage ? 'border-violet-200' : isDeepScan ? 'border-amber-200' : 'border-slate-200'
      }`}
    >
      <button
        onClick={() => setOpen(o => !o)}
        className={`w-full flex items-center gap-3 px-4 py-3 text-left transition-colors ${
          isCredential ? 'bg-teal-50 hover:bg-teal-100' :
          isHtml       ? 'bg-orange-50 hover:bg-orange-100' :
          isImage      ? 'bg-violet-50 hover:bg-violet-100' :
          isDeepScan   ? 'bg-amber-50 hover:bg-amber-100' :
          'bg-slate-50 hover:bg-slate-100'
        }`}
      >
        {/* Analyzer-specific icon */}
        {isCredential && <RiKeyLine    className="text-teal-500 flex-shrink-0" />}
        {isHtml       && <RiHtml5Line  className="text-orange-500 flex-shrink-0" />}
        {isImage      && <RiImageLine  className="text-violet-500 flex-shrink-0" />}
        {isDeepScan   && <RiFileZipLine className="text-amber-500 flex-shrink-0" />}
        {!isCredential && !isHtml && !isImage && !isDeepScan && <StatusPill status={analyzer.status} />}

        <span className="flex-1 text-[13px] font-semibold text-slate-800">{analyzer.name}</span>

        {/* NEW badge for new analyzers */}
        {(isCredential || isHtml || isImage || isDeepScan) && (
          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-teal-100 text-teal-700 flex-shrink-0">NEW</span>
        )}

        <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full flex-shrink-0 ${analyzer.findings_count > 0 ? 'bg-red-100 text-red-700' : 'bg-emerald-100 text-emerald-700'}`}>
          {analyzer.findings_count} finding{analyzer.findings_count !== 1 ? 's' : ''}
        </span>
        <span className="text-slate-400">{open ? <RiArrowUpSLine /> : <RiArrowDownSLine />}</span>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            className="px-4 py-3 bg-white space-y-2"
          >
            <p className="text-[11px] text-slate-400 mb-3">{analyzer.description}</p>
            {analyzer.findings_count === 0 ? (
              <div className="flex items-center gap-2 text-emerald-600 text-[12px] py-2">
                <RiCheckboxCircleLine className="text-base" />
                No indicators found by this analyzer
              </div>
            ) : (
              <div className="space-y-2">
                {analyzer.findings.map((f, i) => <FindingRow key={i} finding={f} index={i} />)}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

/* ── Hash value row with copy ─────────────────────────────────────────────── */
function HashRow({ label, value }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard?.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <div className="flex items-center gap-2 py-1.5 border-b border-slate-50 last:border-none">
      <span className="text-[11px] font-semibold text-slate-500 w-12 flex-shrink-0">{label}</span>
      <span className="flex-1 text-[11px] font-mono text-slate-700 truncate">{value}</span>
      <button onClick={copy} className="text-slate-300 hover:text-sky-500 transition-colors flex-shrink-0" title="Copy">
        {copied ? <RiCheckboxCircleLine className="text-emerald-500" /> : <RiFileCopyLine />}
      </button>
    </div>
  )
}

/* ── Phase card container ─────────────────────────────────────────────────── */
const PHASE_ICONS = {
  fingerprint: RiShieldCheckLine,
  search:      RiSearchLine,
  hash:        RiDatabase2Line,
  verdict:     RiScales3Line,
}

function PhaseCard({ phase, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen)
  const Icon = PHASE_ICONS[phase.icon] ?? RiInformationLine
  const cfg  = SEVERITY_CONFIG[phase.status] ?? SEVERITY_CONFIG.clean

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl border border-slate-100 shadow-[0_1px_3px_rgba(0,0,0,0.06)] overflow-hidden bg-white"
    >
      {/* Phase header */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-slate-50 transition-colors"
      >
        {/* Phase number + icon */}
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${cfg.bg}`}>
          <Icon className={`text-base ${cfg.text}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-[11px] font-semibold text-slate-400">Phase {phase.id}</span>
            <StatusPill status={phase.status} />
          </div>
          <p className="text-[13px] font-bold text-slate-800">{phase.name}</p>
          <p className="text-[11px] text-slate-500 truncate mt-0.5">{phase.summary}</p>
        </div>
        <span className="text-slate-400 text-lg">{open ? <RiArrowUpSLine /> : <RiArrowDownSLine />}</span>
      </button>

      {/* Phase body */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            className="border-t border-slate-100 px-5 py-4"
          >
            {children}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

/* ── Main component ───────────────────────────────────────────────────────── */
export default function AttachmentAnalyzer() {
  const [scannedData, setScannedData] = useState(null)
  const [isScanning, setIsScanning]   = useState(false)
  const [error, setError]             = useState(null)
  const [activeTab, setActiveTab]     = useState('scan')
  const [historyTrigger, setHistoryTrigger] = useState(0)
  const fileInputRef = useRef(null)

  const handleFileUpload = async (e) => {
    const file = e.target.files[0]
    if (!file) return

    setIsScanning(true)
    setError(null)
    setScannedData(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const res = await fetch('/api/attachment-scan/analyze', {
        method: 'POST',
        body: formData,
      })
      if (!res.ok) throw new Error('Analysis request failed')
      const data = await res.json()
      setScannedData(data)
      // Refresh history after a successful scan
      setHistoryTrigger(t => t + 1)
    } catch (err) {
      setError(err.message || 'Failed to scan the attachment.')
    } finally {
      setIsScanning(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  const triggerUpload = () => fileInputRef.current?.click()

  // Helpers to pull phase data by id
  const getPhase = (id) => scannedData?.phases?.find(p => p.id === id)

  const TABS = [
    { id: 'scan',    label: 'Scan File',     icon: <RiSearchLine /> },
    { id: 'history', label: 'Scan History',  icon: <RiHistoryLine /> },
  ]

  return (
    <PageWrapper>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-[22px] font-bold text-slate-900">Malicious Attachment Analyzer</h1>
        <p className="text-[13px] text-slate-500 mt-1">
          Static analysis · YARA rules · PDF/Office/PE/ZIP · HTML phishing · Image steganography · Credential exposure · MalwareBazaar hashing
        </p>
      </div>

      {/* Main tabs */}
      <div className="flex items-center gap-1 mb-5">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-[13px] font-semibold transition-colors ${
              activeTab === tab.id
                ? 'bg-sky-500 text-white shadow-sm'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* History tab */}
      {activeTab === 'history' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          <div className="lg:col-span-2">
            <Card>
              <div className="flex items-center gap-2 mb-4">
                <RiHistoryLine className="text-sky-500 text-lg" />
                <h2 className="text-[15px] font-bold text-slate-900">Scan History</h2>
                <span className="text-[11px] text-slate-400 ml-auto">Last 50 scans</span>
              </div>
              <ScanHistory refreshTrigger={historyTrigger} />
            </Card>
          </div>
          <div className="space-y-4">
            <Card>
              <SectionHeader icon={<RiShieldLine />} title="About History" />
              <div className="space-y-2 mt-3">
                {[
                  'All file scans are automatically saved',
                  'Results are stored in PostgreSQL',
                  'History persists across sessions',
                  'Click any row for scan details',
                  'Use filters to narrow by risk level',
                ].map((tip, i) => (
                  <div key={i} className="flex items-start gap-2 text-[12px] text-slate-600">
                    <span className="mt-0.5 text-sky-400">•</span>
                    {tip}
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      )}

      {/* Scan tab */}
      {activeTab === 'scan' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 space-y-4">

          {/* Upload zone */}
          <Card>
            <div
              onClick={triggerUpload}
              className={`border-2 border-dashed rounded-xl p-10 flex flex-col items-center justify-center text-center cursor-pointer transition-colors ${
                isScanning
                  ? 'bg-slate-50 border-slate-200'
                  : 'border-sky-200 bg-sky-50 hover:bg-sky-100 hover:border-sky-300'
              }`}
            >
              <input type="file" ref={fileInputRef} onChange={handleFileUpload} className="hidden" />
              {isScanning ? (
                <div className="flex flex-col items-center text-slate-500">
                  <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
                    <RiLoader4Line className="text-4xl mb-3 text-sky-500" />
                  </motion.div>
                  <h3 className="text-sm font-bold text-slate-700">Analyzing file through 4 phases...</h3>
                  <p className="text-xs mt-1">Type detection · Deep content · HTML/Image/Credential scan · Hash check · Risk verdict</p>
                </div>
              ) : (
                <div className="flex flex-col items-center text-sky-600">
                  <RiFolderOpenLine className="text-4xl mb-3" />
                  <h3 className="text-sm font-bold text-slate-800">Drop file here or click to upload</h3>
                  <p className="text-xs text-slate-500 mt-1">PDF, DOCX, XLSX, EXE, ZIP, HTML, Images · Max 100 MB</p>
                </div>
              )}
            </div>
            {error && (
              <div className="mt-4 p-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs flex items-center gap-2">
                <RiAlertLine /> {error}
              </div>
            )}
          </Card>

          {/* 4-Phase Results */}
          <AnimatePresence>
            {scannedData && (
              <motion.div
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="space-y-3"
              >
                {/* File summary bar */}
                <div className="flex items-center justify-between px-1">
                  <div>
                    <p className="text-[14px] font-bold text-slate-800">{scannedData.filename}</p>
                    <p className="text-[11px] text-slate-400">
                      {(scannedData.file_size_kb || 0).toFixed(2)} KB
                      {scannedData.analysis_time_ms != null && ` · ${Math.round(scannedData.analysis_time_ms)}ms`}
                      {scannedData.scanned_at && ` · ${new Date(scannedData.scanned_at).toLocaleTimeString()}`}
                    </p>
                  </div>
                  <div className="flex items-center gap-3">
                    <ScoreMeter score={scannedData.risk_score || 0} size={72} />
                    <RiskBadge level={
                      scannedData.risk_label === 'Critical' ? 'critical' :
                      scannedData.risk_label === 'High'     ? 'high' :
                      scannedData.risk_label === 'Medium'   ? 'suspicious' :
                      scannedData.risk_label === 'Low'      ? 'suspicious' : 'safe'
                    } />
                  </div>
                </div>

                {/* Severity summary chips */}
                <div className="grid grid-cols-4 gap-2">
                  {[
                    { label: 'Critical', count: scannedData.critical_count, color: 'text-red-600 bg-red-50 border-red-200' },
                    { label: 'High',     count: scannedData.high_count,     color: 'text-orange-600 bg-orange-50 border-orange-200' },
                    { label: 'Medium',   count: scannedData.medium_count,   color: 'text-amber-600 bg-amber-50 border-amber-200' },
                    { label: 'Low',      count: scannedData.low_count,      color: 'text-blue-600 bg-blue-50 border-blue-200' },
                  ].map(({ label, count, color }) => (
                    <div key={label} className={`p-3 rounded-xl border flex flex-col items-center text-center ${color}`}>
                      <span className="text-[10px] font-semibold opacity-70">{label}</span>
                      <span className="text-2xl font-bold leading-tight">{count || 0}</span>
                    </div>
                  ))}
                </div>

                {/* ── Phase cards (structured output) ── */}
                {scannedData.phases ? (
                  <>
                {/* ── Phase 1: File Type Detection ── */}
                {getPhase(1) && (() => {
                  const p = getPhase(1)
                  const d = p.details || {}
                  return (
                    <PhaseCard phase={p} defaultOpen>
                      <div className="grid grid-cols-2 gap-3 text-[12px]">
                        <div className="space-y-2">
                          <InfoRow label="Declared Extension" value={d.declared_extension || 'N/A'} />
                          <InfoRow label="Detected Type"      value={d.detected_type || 'Unknown'} />
                          <InfoRow label="MIME Type"          value={d.mime_type || 'Unknown'} mono />
                        </div>
                        <div className="space-y-2">
                          <InfoRow label="Risk Level"        value={d.risk_level || 'Info'} />
                          <InfoRow label="File Size"         value={`${(d.file_size_kb || 0).toFixed(2)} KB`} />
                          <InfoRow label="Detection Method"  value={d.detection_method || 'Fallback'} />
                        </div>
                      </div>
                      {d.extension_mismatch && (
                        <div className="mt-3 flex items-start gap-2 p-3 rounded-lg bg-red-50 border border-red-200 text-red-800 text-[12px]">
                          <RiErrorWarningLine className="text-red-500 mt-0.5 flex-shrink-0" />
                          <div><strong>Extension Mismatch: </strong>{d.mismatch_desc}</div>
                        </div>
                      )}
                    </PhaseCard>
                  )
                })()}

                {/* ── Phase 2: Deep Content Analysis ── */}
                {getPhase(2) && (() => {
                  const p = getPhase(2)
                  return (
                    <PhaseCard phase={p} defaultOpen={p.total_findings > 0}>
                      {p.analyzers?.length > 0 ? (
                        <div className="space-y-3">
                          {p.analyzers.map((a, i) => (
                            <AnalyzerSection key={a.name} analyzer={a} index={i} />
                          ))}
                        </div>
                      ) : (
                        <p className="text-[12px] text-slate-400 text-center py-4">No analyzers ran for this file type.</p>
                      )}
                    </PhaseCard>
                  )
                })()}

                {/* ── Phase 3: Hash Reputation ── */}
                {getPhase(3) && (() => {
                  const p = getPhase(3)
                  const d = p.details || {}
                  return (
                    <PhaseCard phase={p} defaultOpen={!!d.known_malware}>
                      <div className="space-y-1 mb-3">
                        <HashRow label="MD5"    value={d.md5 || '—'} />
                        <HashRow label="SHA1"   value={d.sha1 || '—'} />
                        <HashRow label="SHA256" value={d.sha256 || '—'} />
                      </div>
                      <div className={`mt-3 p-3 rounded-lg border text-[12px] ${
                        d.known_malware
                          ? 'bg-red-50 border-red-200 text-red-800'
                          : 'bg-emerald-50 border-emerald-200 text-emerald-800'
                      }`}>
                        {d.known_malware ? (
                          <>
                            <div className="font-bold mb-1">⚠ Known Malware Detected</div>
                            <div><strong>Family: </strong>{d.known_malware}</div>
                            <div><strong>Source: </strong>{d.source}</div>
                            {d.malware_details?.first_seen && (
                              <div><strong>First Seen: </strong>{d.malware_details.first_seen}</div>
                            )}
                          </>
                        ) : (
                          <div className="flex items-center gap-2">
                            <RiCheckboxCircleLine className="text-emerald-500 text-base flex-shrink-0" />
                            <span><strong>Not found in threat database</strong> · {d.database_size}</span>
                          </div>
                        )}
                      </div>
                      {d.mode && (
                        <p className="text-[10px] text-slate-400 mt-2">{d.mode}</p>
                      )}
                    </PhaseCard>
                  )
                })()}

                {/* ── Phase 4: Risk Verdict ── */}
                {getPhase(4) && (() => {
                  const p = getPhase(4)
                  return (
                    <PhaseCard phase={p} defaultOpen>
                      <ResultPanel level={
                        p.status === 'clean'                        ? 'success' :
                        p.status === 'critical' || p.status === 'high' ? 'danger' : 'warning'
                      }>
                        <strong>Assessment: </strong>{p.human_summary}
                      </ResultPanel>

                      <div className="mt-3 p-3 rounded-lg bg-slate-50 border border-slate-200 text-[12px] text-slate-700">
                        <strong>Recommended Action: </strong>{p.recommended_action}
                      </div>

                      <div className="mt-4 flex gap-2">
                        {scannedData.risk_score > 0 && (
                          <Btn variant="danger"><RiFileDamageLine /> Quarantine</Btn>
                        )}
                        <Btn variant="ghost"><RiDownloadLine /> Export Report</Btn>
                      </div>
                    </PhaseCard>
                  )
                })()}
                  </>
                ) : (
                  /* ── Fallback: flat findings list (old API format) ── */
                  <FlatFindingsFallback data={scannedData} />
                )}

              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          <Card>
            <SectionHeader title="Supported File Types" />
            <div className="grid grid-cols-2 gap-2">
              {fileTypes.map((t) => (
                <div key={t} className="p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-[12px] font-semibold text-slate-600 text-center hover:bg-sky-50 hover:border-sky-200 hover:text-sky-600 transition-colors cursor-default">
                  {t}
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <SectionHeader title="Today's Scan Stats" />
            <SidebarStat value="186"   label="Files Scanned" />
            <SidebarStat value="14"    label="Malicious Detected" accent />
            <SidebarStat value="7"     label="Quarantined" accent />
            <SidebarStat value="7,241" label="YARA Signatures Active" />
          </Card>

          <Card>
            <SectionHeader title="Detection by File Type" />
            <div className="space-y-2">
              {[
                { t: 'PDF',       pct: 38 },
                { t: 'DOCX/XLSX', pct: 25 },
                { t: 'HTML',      pct: 18, isNew: true },
                { t: 'EXE',       pct: 12 },
                { t: 'Images',    pct: 7, isNew: true },
              ].map(({ t, pct, isNew }) => (
                <div key={t} className="flex items-center gap-2">
                  <span className="text-[12px] text-slate-500 w-20 flex items-center gap-1">
                    {t}
                    {isNew && <span className="text-[8px] font-bold px-1 rounded bg-teal-100 text-teal-600">NEW</span>}
                  </span>
                  <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                    <motion.div
                      className="h-full bg-gradient-to-r from-sky-400 to-sky-500 rounded-full"
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ duration: 1, ease: [0.34, 1.2, 0.64, 1] }}
                    />
                  </div>
                  <span className="text-[11px] font-bold text-slate-600 w-7 text-right">{pct}%</span>
                </div>
              ))}
            </div>
          </Card>

          {/* Analysis pipeline info */}
          <Card>
            <SectionHeader title="Analysis Pipeline" />
            <div className="space-y-2">
              {[
                { num: '1', name: 'File Type Detection',    desc: 'Magic bytes · MIME · extension spoof', color: 'bg-sky-100 text-sky-600' },
                { num: '2', name: 'Deep Content Analysis',  desc: 'PDF · Office · PE · ZIP · HTML · Image', color: 'bg-violet-100 text-violet-600' },
                { num: '2a', name: 'ZIP Recursive Deep Scan', desc: 'Extract inner files → run full analysis on each', color: 'bg-amber-100 text-amber-600', isNew: true },
                { num: '2b', name: 'Credential Exposure',   desc: 'API keys · tokens · passwords (all files)', color: 'bg-teal-100 text-teal-600', isNew: true },
                { num: '3', name: 'Hash Reputation',        desc: 'MalwareBazaar offline DB', color: 'bg-sky-100 text-sky-600' },
                { num: '4', name: 'Risk Verdict',           desc: 'Weighted scoring · FP guard', color: 'bg-sky-100 text-sky-600' },
              ].map(({ num, name, desc, color, isNew }) => (
                <div key={num} className="flex items-center gap-3">
                  <div className={`w-7 h-6 rounded-full ${color} text-[10px] font-bold flex items-center justify-center flex-shrink-0`}>
                    {num}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5">
                      <p className="text-[12px] font-semibold text-slate-700">{name}</p>
                      {isNew && <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-teal-100 text-teal-700">NEW</span>}
                    </div>
                    <p className="text-[10px] text-slate-400">{desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
      )}  {/* end scan tab */}
    </PageWrapper>
  )
}

/* ── Small helper: info row ──────────────────────────────────────────────── */
function InfoRow({ label, value, mono = false }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wide">{label}</span>
      <span className={`text-[12px] text-slate-700 break-all ${mono ? 'font-mono' : 'font-medium'}`}>{value}</span>
    </div>
  )
}

/* ── Fallback: flat findings list when phases isn't in API response ───────── */
function FlatFindingsFallback({ data }) {
  const findings = data?.all_findings || []
  const label    = data?.risk_label || 'Unknown'
  const levelMap = { Critical: 'danger', High: 'danger', Medium: 'warning', Low: 'info', Clean: 'success' }

  return (
    <div className="space-y-3">
      {/* Verdict panel */}
      <ResultPanel level={levelMap[label] || 'info'}>
        <strong>Result: {label}</strong> · {data?.human_summary || 'Scan complete.'}
        {data?.recommended_action && (
          <div className="mt-1 text-xs opacity-90"><strong>Action: </strong>{data.recommended_action}</div>
        )}
      </ResultPanel>

      {/* Findings list */}
      {findings.length > 0 ? (
        <Card>
          <SectionHeader title={`Findings (${findings.length})`} />
          <div className="space-y-2">
            {findings.map((f, i) => <FindingRow key={i} finding={f} index={i} />)}
          </div>
        </Card>
      ) : (
        <div className="flex items-center gap-2 text-emerald-600 text-[13px] p-4 bg-emerald-50 rounded-xl border border-emerald-200">
          <RiCheckboxCircleLine className="text-lg flex-shrink-0" />
          No malicious indicators found. File appears safe.
        </div>
      )}

      {/* Action buttons */}
      <div className="flex gap-2">
        {(data?.risk_score || 0) > 0 && (
          <Btn variant="danger"><RiFileDamageLine /> Quarantine</Btn>
        )}
        <Btn variant="ghost"><RiDownloadLine /> Export Report</Btn>
      </div>
    </div>
  )
}
