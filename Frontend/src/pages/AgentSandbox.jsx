import { useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiRobotLine, RiPlayLine, RiDownloadLine, RiShieldCheckLine,
  RiAlertLine, RiLockLine, RiServerLine, RiFolder3Line,
  RiGlobalLine, RiUpload2Line, RiRefreshLine,
  RiCheckLine, RiTimeLine, RiCloseCircleLine, RiFlashlightLine,
  RiDeleteBinLine, RiCpuLine, RiInformationLine, RiFileLine,
  RiTableLine,
} from 'react-icons/ri'
import {
  Card, Btn, RiskBadge, PageWrapper, PageHeader, SectionHeader, SubTabs,
} from '../components/ui'
import { downloadPDFReport, downloadCSV } from '../utils/reportExport'

const SBX_API = '/api/sandbox'

// ── Dimensions ────────────────────────────────────────────────────────────────
const DIMENSIONS = [
  { id: 'adversarial', label: 'Adversarial Inputs',  sev: 'critical' },
  { id: 'pii',         label: 'Data Leakage',        sev: 'critical' },
  { id: 'agent',       label: 'Agentic Scope',       sev: 'critical' },
  { id: 'tool_abuse',  label: 'Tool Abuse',          sev: 'critical' },
  { id: 'multiturn',   label: 'Multi-turn Attacks',  sev: 'high'     },
  { id: 'context',     label: 'Context Attacks',     sev: 'high'     },
  { id: 'consistency', label: 'Consistency',         sev: 'high'     },
  { id: 'output',      label: 'Output Exploits',     sev: 'medium'   },
]
const QUICK_DIMS = ['adversarial', 'pii', 'agent', 'tool_abuse']

const RISK_CONFIG = {
  CRITICAL: { color: 'text-red-600',    bg: 'bg-red-50',     border: 'border-red-200',    desc: 'Do NOT deploy. Multiple critical vulnerabilities confirmed.' },
  HIGH:     { color: 'text-amber-600',  bg: 'bg-amber-50',   border: 'border-amber-200',  desc: 'Deployment not recommended. Remediate high findings first.' },
  MEDIUM:   { color: 'text-sky-600',    bg: 'bg-sky-50',     border: 'border-sky-200',    desc: 'Review findings before production deployment.' },
  LOW:      { color: 'text-emerald-600',bg: 'bg-emerald-50', border: 'border-emerald-200',desc: 'Passed most tests. Review any minor findings.' },
}

const sevBg = {
  critical: 'bg-red-50 border-red-200 text-red-600',
  high:     'bg-amber-50 border-amber-200 text-amber-600',
  medium:   'bg-sky-50 border-sky-200 text-sky-600',
}

function relativeTime(isoStr) {
  if (!isoStr) return '—'
  const diff = Math.floor((Date.now() - new Date(isoStr)) / 1000)
  if (diff < 60)    return `${diff}s ago`
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return new Date(isoStr).toLocaleString()
}

function fmtBytes(b) {
  if (!b) return '—'
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB'
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  return (b / 1e3).toFixed(0) + ' KB'
}

function fmtSavedBytes(b) {
  if (b >= 1e9) return (b / 1e9).toFixed(2) + ' GB'
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  return (b / 1e3).toFixed(0) + ' KB'
}

function collectFindings(dimensions) {
  const out = []
  Object.entries(dimensions || {}).forEach(([key, dim]) => {
    if (dim.error) return
    const items = [...(dim.tests || []), ...(dim.scenarios || []), ...(dim.groups || [])]
    items.forEach(item => {
      if (!item.passed) out.push({
        dimension: (dim.dimension || key).replace(/_/g, ' ').toUpperCase(),
        id:        item.id || '—',
        name:      item.name || item.category || item.intent || '—',
        severity:  item.severity || 'medium',
        response:  item.response || '',
        reason:    item.judge_reason || item.reason || '',
        payload:   item.payload || '',
      })
    })
  })
  // Sort critical → high → medium → low
  const order = { critical: 0, high: 1, medium: 2, low: 3 }
  out.sort((a, b) => (order[a.severity] ?? 2) - (order[b.severity] ?? 2))
  return out
}

// ── Status badge ──────────────────────────────────────────────────────────────
function DimStatusBadge({ status }) {
  if (status === 'running') return <div className="w-5 h-5 rounded-full border-2 border-sky-400 border-t-transparent animate-spin flex-shrink-0" />
  if (status === 'done')    return <div className="w-5 h-5 rounded-full bg-emerald-100 flex items-center justify-center flex-shrink-0"><RiCheckLine className="text-emerald-600 text-xs" /></div>
  if (status === 'failed')  return <div className="w-5 h-5 rounded-full bg-red-100 flex items-center justify-center flex-shrink-0"><RiCloseCircleLine className="text-red-500 text-xs" /></div>
  return <div className="w-5 h-5 rounded-full bg-slate-200 flex-shrink-0" />
}

// ── Quant badge ───────────────────────────────────────────────────────────────
function QuantBadge({ quant }) {
  const q = (quant || 'latest').toLowerCase()
  const color = q.includes('q4') ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
              : q.includes('q8') ? 'bg-sky-50 text-sky-700 border-sky-200'
              : q.includes('q2') ? 'bg-amber-50 text-amber-700 border-amber-200'
              : q.includes('f16') || q.includes('f32') ? 'bg-violet-50 text-violet-700 border-violet-200'
              : 'bg-slate-50 text-slate-600 border-slate-200'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold border ${color}`}>
      {(quant || 'latest').toUpperCase()}
    </span>
  )
}

// ── Upload progress bar ───────────────────────────────────────────────────────
function UploadProgress({ phase, pct, status, savedBytes, completed, total }) {
  const isIndeterminate = pct === -1
  const displayPct = isIndeterminate ? null : pct

  let label = ''
  let sublabel = ''
  if (phase === 'validating') { label = 'Validating file…'; sublabel = '' }
  else if (phase === 'saving' || phase === 'saving_done') {
    label = phase === 'saving_done' ? 'File saved ✓' : 'Uploading to server…'
    sublabel = savedBytes ? fmtSavedBytes(savedBytes) + ' written' : ''
  }
  else if (phase === 'registering') {
    label = 'Registering with Ollama…'
    sublabel = status || ''
    if (completed && total) sublabel += ` (${fmtSavedBytes(completed)} / ${fmtSavedBytes(total)})`
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-[12px]">
        <span className="font-semibold text-slate-700">{label}</span>
        {displayPct !== null && <span className="font-mono text-sky-600 font-bold">{displayPct}%</span>}
      </div>
      <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
        {isIndeterminate ? (
          <div className="h-full w-1/3 bg-sky-400 rounded-full animate-[slide_1.5s_ease-in-out_infinite]"
            style={{ animation: 'uploadSlide 1.5s ease-in-out infinite' }} />
        ) : (
          <motion.div
            className="h-full bg-gradient-to-r from-sky-400 to-sky-500 rounded-full"
            initial={{ width: 0 }}
            animate={{ width: `${displayPct}%` }}
            transition={{ duration: 0.4 }}
          />
        )}
      </div>
      {sublabel && <p className="text-[10px] font-mono text-slate-400">{sublabel}</p>}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
export default function AgentSandbox() {
  const [tab, setTab] = useState('New Scan')

  // model selection
  const [availableModels, setAvailableModels] = useState([])
  const [modelMeta, setModelMeta]             = useState([])   // rich metadata
  const [selectedModel, setSelectedModel]     = useState('')
  const [scanProfile, setScanProfile]         = useState('all')
  const [customDims, setCustomDims]           = useState(
    Object.fromEntries(DIMENSIONS.map(d => [d.id, true]))
  )
  const [judgeEnabled, setJudgeEnabled] = useState(true)

  // upload state
  const [selectedFile, setSelectedFile]   = useState(null)
  const [dragOver, setDragOver]           = useState(false)
  const [uploadPhase, setUploadPhase]     = useState(null)   // null | phase string
  const [uploadData, setUploadData]       = useState({})
  const fileInputRef = useRef(null)
  const pollRef      = useRef(null)   // stores the setInterval ID for cleanup
  const logBoxRef    = useRef(null)   // for auto-scroll

  // scan state
  const [scanning, setScanning]         = useState(false)
  const [activeScanId, setActiveScanId] = useState(null)
  const [dimStatuses, setDimStatuses]   = useState({})
  const [logLines, setLogLines]         = useState([])
  const [scanResult, setScanResult]     = useState(null)
  const [scanPhase, setScanPhase]       = useState('idle')
  const [scanProgress, setScanProgress] = useState(0)
  const [currentDim, setCurrentDim]     = useState('')

  // history
  const [history, setHistory]         = useState([])
  const [sandboxOnline, setSandboxOnline] = useState(null)

  // deleting
  const [deletingModel, setDeletingModel] = useState(null)

  const addLog = useCallback((msg, type = 'info') => {
    const ts = new Date().toLocaleTimeString('en-GB', { hour12: false })
    setLogLines(prev => [...prev.slice(-199), { msg: `${ts}  ${msg}`, type }])
  }, [])

  // Auto-scroll log box when new lines arrive
  useEffect(() => {
    if (logBoxRef.current) logBoxRef.current.scrollTop = logBoxRef.current.scrollHeight
  }, [logLines])

  // ── Health + models ─────────────────────────────────────────────────────────
  const checkHealth = useCallback(async () => {
    try {
      const r = await fetch(`${SBX_API}/health`, { signal: AbortSignal.timeout(5000) })
      const d = await r.json()
      if (d.status === 'ok') {
        setSandboxOnline(true)
        const models = d.models_available || []
        setAvailableModels(models)
        if (models.length && !selectedModel) setSelectedModel(models[0])
      } else setSandboxOnline(false)
    } catch { setSandboxOnline(false) }
  }, [selectedModel])

  const fetchModelMeta = useCallback(async () => {
    try {
      const r = await fetch(`${SBX_API}/models`)
      if (r.ok) { const d = await r.json(); setModelMeta(d.models || []) }
    } catch {}
  }, [])

  const fetchHistory = useCallback(async () => {
    try {
      const r = await fetch(`${SBX_API}/results`)
      if (r.ok) { const d = await r.json(); setHistory(d.scans || []) }
    } catch {}
  }, [])

  useEffect(() => {
    checkHealth(); fetchHistory(); fetchModelMeta()
    const iv = setInterval(() => { checkHealth(); fetchModelMeta() }, 30000)
    return () => { clearInterval(iv); if (pollRef.current) clearInterval(pollRef.current) }
  }, [checkHealth, fetchHistory, fetchModelMeta])

  // ── File handlers ───────────────────────────────────────────────────────────
  const handleFile = (file) => { if (file) { setSelectedFile(file); setUploadPhase(null); setUploadData({}) } }
  const clearFile  = () => { setSelectedFile(null); setUploadPhase(null); setUploadData({}); if (fileInputRef.current) fileInputRef.current.value = '' }

  const getActiveDims = () => {
    if (scanProfile === 'all')   return DIMENSIONS
    if (scanProfile === 'quick') return DIMENSIONS.filter(d => QUICK_DIMS.includes(d.id))
    return DIMENSIONS.filter(d => customDims[d.id])
  }

  // ── Delete model ─────────────────────────────────────────────────────────────
  const deleteModel = async (name) => {
    if (!window.confirm(`Delete model "${name}"? This cannot be undone.`)) return
    setDeletingModel(name)
    try {
      const r = await fetch(`${SBX_API}/models/${encodeURIComponent(name)}`, { method: 'DELETE' })
      const d = await r.json()
      if (d.status === 'deleted') {
        setAvailableModels(prev => prev.filter(m => m !== name))
        setModelMeta(prev => prev.filter(m => m.name !== name))
        if (selectedModel === name) setSelectedModel('')
      } else {
        alert(`Delete failed: ${d.error || 'unknown'}`)
      }
    } catch (e) { alert(`Delete error: ${e.message}`) }
    finally { setDeletingModel(null) }
  }

  // ── Poll scan status ─────────────────────────────────────────────────────────
  const pollScanStatus = useCallback((scanId, activeDims) => {
    let lastLogLen = 0
    const iv = setInterval(async () => {
      try {
        const r = await fetch(`${SBX_API}/scan/${scanId}/status`)
        if (!r.ok) return
        const d = await r.json()

        setScanProgress(d.progress_pct || 0)
        setCurrentDim(d.current_dim || '')

        // ── Stream new server-side prompt logs into the log box ──────────────
        const srvLog = d.log || []
        if (srvLog.length > lastLogLen) {
          const newLines = srvLog.slice(lastLogLen)
          newLines.forEach(line => {
            setLogLines(prev => [...prev.slice(-199), {
              msg: line, type: 'prompt'
            }])
          })
          lastLogLen = srvLog.length
        }

        // Update dimension badges based on real done count
        const donePct   = d.progress_pct || 0
        const doneCount = Math.floor((donePct / 100) * activeDims.length)
        activeDims.forEach((dim, i) => {
          if (i < doneCount) {
            setDimStatuses(prev => {
              if (prev[dim.id]?.status === 'done' || prev[dim.id]?.status === 'failed') return prev
              return { ...prev, [dim.id]: { status: 'done', result: 'done' } }
            })
          } else if (i === doneCount) {
            setDimStatuses(prev => ({ ...prev, [dim.id]: { status: 'running', result: 'running…' } }))
          }
        })

        if (d.status === 'done' && d.result) {
          clearInterval(iv)
          pollRef.current = null
          const data = d.result
          activeDims.forEach(dim => {
            const dimData = data.dimensions?.[dim.id]
            if (dimData && !dimData.error) {
              const pct = Math.round(dimData.pass_rate ?? 0)
              setDimStatuses(prev => ({
                ...prev,
                [dim.id]: { status: dimData.failed > 0 ? 'failed' : 'done', result: `${pct}%` }
              }))
              addLog(`DONE  ${dim.label}: ${dimData.passed}/${dimData.total} passed (${pct}%)`, dimData.failed > 0 ? 'err' : 'ok')
            }
          })
          addLog(`SCAN  complete — score=${data.risk_score?.score}/100 rating=${data.risk_score?.rating}`, 'ok')
          setScanResult(data)
          setScanPhase('results')
          setScanning(false)
          setActiveScanId(null)
          clearFile()
          fetchHistory()
        } else if (d.status === 'error') {
          clearInterval(iv)
          pollRef.current = null
          addLog('ERROR  server-side scan failure', 'err')
          setScanPhase('error')
          setScanning(false)
          setActiveScanId(null)
        }
      } catch {}
    }, 1500)   // poll every 1.5 s for fast feedback
    return iv
  }, [addLog, fetchHistory])

  // ── Start scan ───────────────────────────────────────────────────────────────
  const startScan = async () => {
    let modelName = selectedFile ? null : selectedModel
    if (!modelName && !selectedFile) { alert('Select or upload a model first.'); return }

    setScanning(true)
    setScanResult(null)
    setLogLines([])
    setScanProgress(0)
    setCurrentDim('')
    const activeDims = getActiveDims()
    setDimStatuses(Object.fromEntries(activeDims.map(d => [d.id, { status: 'waiting', result: 'waiting' }])))

    // ── Step 1: SSE upload if file provided ───────────────────────────────────
    if (selectedFile) {
      setScanPhase('uploading')
      addLog(`UPLOAD  ${selectedFile.name} (${fmtBytes(selectedFile.size)})`, 'info')
      setUploadPhase('validating')

      try {
        const form = new FormData()
        form.append('file', selectedFile)
        const upRes = await fetch(`${SBX_API}/upload`, { method: 'POST', body: form })
        const reader = upRes.body.getReader()
        const decoder = new TextDecoder()
        let buf = ''

        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })
          const lines = buf.split('\n')
          buf = lines.pop()
          for (const line of lines) {
            if (!line.startsWith('data: ')) continue
            try {
              const evt = JSON.parse(line.slice(6))
              setUploadPhase(evt.phase)
              setUploadData(evt)
              if (evt.phase === 'error') {
                addLog(`ERR   upload: ${evt.error}`, 'err')
                setScanPhase('error'); setScanning(false); return
              }
              if (evt.phase === 'saving') addLog(`SAVE  ${fmtSavedBytes(evt.saved_bytes)} written`, 'info')
              if (evt.phase === 'saving_done') addLog(`SAVE  complete — ${fmtSavedBytes(evt.saved_bytes)}`, 'ok')
              if (evt.phase === 'registering') addLog(`REG   ${evt.status}${evt.pct >= 0 ? ` ${evt.pct}%` : ''}`, 'info')
              if (evt.phase === 'ready') {
                modelName = evt.model_name
                addLog(`READY model="${modelName}"`, 'ok')
                setAvailableModels(prev => [...new Set([...prev, modelName])])
                setSelectedModel(modelName)
                await fetchModelMeta()
              }
            } catch { }
          }
        }
        if (!modelName) { setScanPhase('error'); setScanning(false); return }
      } catch (e) {
      addLog(`ERR   upload exception: ${e.message}`, 'err')
        setScanPhase('error'); setScanning(false); return
      }
      setUploadPhase(null)
    }

    // ── Step 2: Start background scan ─────────────────────────────────────────
    setScanPhase('scanning')
    addLog(`SCAN  model="${modelName}" profile=${scanProfile} dims=${activeDims.length}`, 'info')
    addLog(`JUDGE tinyllama (offline)  concurrency=6`, 'info')

    // Mark all dims as running/waiting
    activeDims.forEach((d, i) => {
      setTimeout(() => {
        setDimStatuses(prev => ({ ...prev, [d.id]: { status: 'running', result: 'running…' } }))
      }, i * 80)
    })

    const dimsPayload = scanProfile === 'all'   ? ['all']
                      : scanProfile === 'quick' ? QUICK_DIMS
                      : activeDims.map(d => d.id)
    try {
      const res = await fetch(`${SBX_API}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model_name: modelName, dimensions: dimsPayload, judge_enabled: judgeEnabled }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const { scan_id } = await res.json()
      setActiveScanId(scan_id)
      addLog(`SCAN  id=${scan_id.slice(0, 8)}… status=queued`, 'info')
      addLog(`POLL  interval=1.5s — waiting for results…`, 'info')
      if (pollRef.current) clearInterval(pollRef.current)
      pollRef.current = pollScanStatus(scan_id, activeDims)
    } catch (e) {
      addLog(`ERR   failed to start scan: ${e.message}`, 'err')
      activeDims.forEach(d => setDimStatuses(prev => ({ ...prev, [d.id]: { status: 'failed', result: 'error' } })))
      setScanPhase('error'); setScanning(false)
    }
  }

  // ── Download report ──────────────────────────────────────────────────────────
  const [downloading, setDownloading]     = useState(false)
  const [generatingPdf, setGeneratingPdf] = useState(false)
  const [generatingCsv, setGeneratingCsv] = useState(false)

  const downloadReport = async (scanId) => {
    setDownloading(true)
    try {
      const r = await fetch(`${SBX_API}/report/${scanId}`)
      if (!r.ok) {
        let msg = `HTTP ${r.status}`
        try { const j = await r.json(); msg = j.error || msg } catch {}
        alert(`Report not ready: ${msg}`)
        return
      }
      const html = await r.text()
      const blob = new Blob([html], { type: 'text/html' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `security_report_${scanId.slice(0, 8)}.html`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      setTimeout(() => URL.revokeObjectURL(url), 5000)
    } catch (e) { alert('Report download failed: ' + e.message) }
    finally { setDownloading(false) }
  }

  const handleDownloadPDF = async (result) => {
    setGeneratingPdf(true)
    try {
      await new Promise(r => setTimeout(r, 60)) // allow UI to update
      downloadPDFReport(result)
    } catch (e) { alert('PDF generation failed: ' + e.message) }
    finally { setGeneratingPdf(false) }
  }

  const handleDownloadCSV = async (result) => {
    setGeneratingCsv(true)
    try {
      await new Promise(r => setTimeout(r, 40))
      downloadCSV(result)
    } catch (e) { alert('CSV export failed: ' + e.message) }
    finally { setGeneratingCsv(false) }
  }

  const activeDims = getActiveDims()
  const riskCfg    = RISK_CONFIG[scanResult?.risk_score?.rating] || RISK_CONFIG.MEDIUM
  const findings   = scanResult ? collectFindings(scanResult.dimensions) : []

  return (
    <PageWrapper>
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-xl font-bold text-slate-900">AI Agent Vulnerability Sandbox</h1>
          <p className="text-[12px] text-slate-400 mt-0.5">
            8-dimension security probing · Offline Ollama inference
            {' — '}
            <span className={`font-semibold ${sandboxOnline === true ? 'text-emerald-500' : sandboxOnline === false ? 'text-red-400' : 'text-slate-400'}`}>
              {sandboxOnline === true ? `● online · ${availableModels.length} model(s)` : sandboxOnline === false ? '● sandbox offline' : '● checking…'}
            </span>
          </p>
        </div>
        <button onClick={() => { checkHealth(); fetchHistory(); fetchModelMeta() }}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 text-[11px] text-slate-500 hover:bg-sky-50 hover:text-sky-600 hover:border-sky-200 transition-colors">
          <RiRefreshLine className="text-sm" /> Refresh
        </button>
      </div>

      {/* Dimension pills */}
      <div className="flex flex-wrap gap-2 mb-5">
        {DIMENSIONS.map(d => (
          <span key={d.id} className={`px-3 py-1 rounded-full border text-[10px] font-bold uppercase tracking-wider ${sevBg[d.sev] || 'bg-slate-50 border-slate-200 text-slate-600'}`}>
            {d.label}
          </span>
        ))}
      </div>

      <Card className="p-0 overflow-hidden">
        {/* Tabs */}
        <div className="flex border-b border-slate-100">
          {['New Scan', 'Installed Models', 'Scan History'].map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-6 py-3.5 text-[12px] font-semibold border-b-2 transition-colors ${
                tab === t ? 'border-sky-500 text-sky-600 bg-sky-50/50'
                          : 'border-transparent text-slate-500 hover:text-slate-700 hover:bg-slate-50'
              }`}>
              {t}
            </button>
          ))}
        </div>

        <div className="p-6">

          {/* ════════ NEW SCAN TAB ════════ */}
          {tab === 'New Scan' && (
            <div className="space-y-6">

              {/* Upload zone */}
              <div
                onDragOver={e => { e.preventDefault(); setDragOver(true) }}
                onDragLeave={() => setDragOver(false)}
                onDrop={e => { e.preventDefault(); setDragOver(false); handleFile(e.dataTransfer.files[0]) }}
                onClick={() => fileInputRef.current?.click()}
                className={`relative border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all duration-200 ${
                  dragOver       ? 'border-sky-400 bg-sky-50' :
                  selectedFile   ? 'border-emerald-300 bg-emerald-50' :
                  uploadPhase === 'error' ? 'border-red-300 bg-red-50' :
                  'border-slate-200 bg-slate-50 hover:border-sky-300 hover:bg-sky-50/50'
                }`}>
                <input ref={fileInputRef} type="file" accept=".gguf" className="hidden"
                  onClick={e => e.stopPropagation()}
                  onChange={e => handleFile(e.target.files?.[0])} />
                {selectedFile ? (
                  <div className="flex items-center justify-center gap-5">
                    <div className="text-4xl">📦</div>
                    <div className="text-left flex-1 min-w-0">
                      <p className="font-bold text-[15px] text-slate-800 font-mono truncate">{selectedFile.name}</p>
                      <p className="text-[12px] text-slate-500 font-mono">{fmtBytes(selectedFile.size)}</p>
                      {/* Upload progress */}
                      {uploadPhase && uploadPhase !== 'ready' && (
                        <div className="mt-3 w-full">
                          <UploadProgress
                            phase={uploadPhase}
                            pct={uploadData.pct}
                            status={uploadData.status}
                            savedBytes={uploadData.saved_bytes}
                            completed={uploadData.completed}
                            total={uploadData.total}
                          />
                        </div>
                      )}
                      {uploadPhase === 'ready' && (
                        <p className="text-[12px] font-semibold text-emerald-600 mt-1">✓ Registered as "{uploadData.model_name}"</p>
                      )}
                    </div>
                    <button onClick={e => { e.stopPropagation(); clearFile() }}
                      className="ml-2 text-slate-400 hover:text-red-500 transition-colors text-xl flex-shrink-0">✕</button>
                  </div>
                ) : (
                  <>
                    <div className="w-14 h-14 rounded-xl border border-slate-200 flex items-center justify-center mx-auto mb-3">
                      <RiUpload2Line className="text-2xl text-slate-400" />
                    </div>
                    <p className="font-bold text-[15px] text-slate-700">Upload model file</p>
                    <p className="text-[12px] text-slate-400 mt-1">Drag and drop or click to browse</p>
                    <p className="text-[10px] text-slate-300 font-mono mt-2">SUPPORTED: .gguf (max 10 GB)</p>
                  </>
                )}
              </div>

              {/* OR divider */}
              <div className="flex items-center gap-3">
                <div className="flex-1 h-px bg-slate-100" />
                <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">or select installed model</span>
                <div className="flex-1 h-px bg-slate-100" />
              </div>

              {/* Config row */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2">Installed Model</label>
                  <select value={selectedModel} onChange={e => setSelectedModel(e.target.value)}
                    className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2.5 text-[13px] text-slate-700 font-mono outline-none focus:border-sky-400 transition-colors">
                    {availableModels.length === 0
                      ? <option value="">Loading models…</option>
                      : availableModels.map(m => <option key={m} value={m}>{m}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2">Scan Profile</label>
                  <select value={scanProfile} onChange={e => setScanProfile(e.target.value)}
                    className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2.5 text-[13px] text-slate-700 font-mono outline-none focus:border-sky-400 transition-colors">
                    <option value="all">Full scan (all 8 dimensions)</option>
                    <option value="quick">Quick scan (critical only)</option>
                    <option value="custom">Custom selection</option>
                  </select>
                </div>
              </div>

              {/* Custom dimension picker */}
              <AnimatePresence>
                {scanProfile === 'custom' && (
                  <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
                    <label className="block text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2">Select Dimensions</label>
                    <div className="grid grid-cols-2 gap-2">
                      {DIMENSIONS.map(d => (
                        <label key={d.id}
                          onClick={() => setCustomDims(prev => ({ ...prev, [d.id]: !prev[d.id] }))}
                          className={`flex items-center gap-3 p-3 border rounded-xl cursor-pointer transition-all ${customDims[d.id] ? 'border-sky-300 bg-sky-50' : 'border-slate-200 bg-white hover:border-slate-300'}`}>
                          <div className={`w-4 h-4 rounded border flex items-center justify-center flex-shrink-0 transition-all ${customDims[d.id] ? 'bg-sky-500 border-sky-500' : 'border-slate-300'}`}>
                            {customDims[d.id] && <RiCheckLine className="text-white text-[9px]" />}
                          </div>
                          <span className="text-[12px] font-semibold text-slate-700 flex-1">{d.label}</span>
                          <span className={`text-[9px] font-bold uppercase ${sevBg[d.sev]?.split(' ')[2] || 'text-slate-500'}`}>{d.sev}</span>
                        </label>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Judge toggle */}
              <div className="flex items-center justify-between py-3.5 border-t border-slate-100">
                <div>
                  <p className="text-[13px] font-semibold text-slate-700">LLM Judge scoring</p>
                  <p className="text-[11px] text-slate-400">Uses offline tinyllama model as judge — no API key needed</p>
                </div>
                <button onClick={() => setJudgeEnabled(prev => !prev)}
                  className={`w-11 h-6 rounded-full relative transition-colors flex-shrink-0 ${judgeEnabled ? 'bg-sky-500' : 'bg-slate-200'}`}>
                  <span className={`absolute top-0.5 w-5 h-5 bg-white rounded-full shadow transition-all ${judgeEnabled ? 'left-5' : 'left-0.5'}`} />
                </button>
              </div>

              {/* Run button */}
              <button onClick={startScan} disabled={scanning}
                className="w-full py-4 bg-sky-500 hover:bg-sky-600 disabled:bg-slate-200 disabled:text-slate-400 text-white font-bold text-[15px] rounded-xl transition-all flex items-center justify-center gap-3 disabled:cursor-not-allowed">
                {scanning
                  ? <><RiRefreshLine className="animate-spin text-lg" /> Scanning — please wait…</>
                  : <><RiFlashlightLine className="text-lg" /> Run Security Scan</>
                }
              </button>

              {/* ── Progress panel ──────────────────────────────────────────── */}
              <AnimatePresence>
                {(scanPhase === 'scanning' || scanPhase === 'uploading') && (
                  <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="space-y-4">
                    {/* Overall scan progress bar */}
                    {scanPhase === 'scanning' && (
                      <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-2">
                        <div className="flex justify-between items-center text-[12px]">
                          <span className="font-bold text-slate-700">
                            {scanProgress < 100 ? `Scanning… ${scanProgress}%` : 'Scan complete ✓'}
                          </span>
                          <span className="font-mono text-sky-600 font-bold">{scanProgress}%</span>
                        </div>
                        <div className="w-full h-2.5 bg-slate-200 rounded-full overflow-hidden">
                          <motion.div
                            className="h-full rounded-full bg-gradient-to-r from-sky-400 to-violet-500"
                            animate={{ width: `${scanProgress}%` }}
                            transition={{ duration: 0.5 }}
                          />
                        </div>
                        <p className="text-[10px] font-mono text-slate-400">
                          {currentDim ? `active: ${currentDim.replace(/_/g,' ')}` : 'initializing…'}
                        </p>
                      </div>
                    )}

                    {/* Per-dim list */}
                    <div className="space-y-1.5">
                      {activeDims.map(d => {
                        const ds = dimStatuses[d.id] || { status: 'waiting', result: 'queued' }
                        return (
                          <div key={d.id} className="flex items-center gap-3 px-4 py-2.5 bg-white border border-slate-100 rounded-xl">
                            <DimStatusBadge status={ds.status} />
                            <span className="text-[12px] font-semibold text-slate-700 flex-1">{d.label}</span>
                            <span className="text-[11px] font-mono text-slate-400">{ds.result}</span>
                          </div>
                        )
                      })}
                    </div>

                    {/* Live prompt log */}
                    <div ref={logBoxRef} className="bg-slate-950 rounded-xl p-4 font-mono text-[11px] leading-relaxed h-44 overflow-auto space-y-px">
                      {logLines.map((l, i) => (
                        <div key={i} className={
                          l.type === 'ok'     ? 'text-emerald-400' :
                          l.type === 'err'    ? 'text-red-400'     :
                          l.type === 'info'   ? 'text-sky-400'     :
                          l.type === 'prompt' ? 'text-slate-500'   : 'text-slate-400'
                        }>{l.msg}</div>
                      ))}
                      {logLines.length === 0 && <div className="text-slate-600">waiting for prompts…</div>}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* ── Results panel ───────────────────────────────────────────── */}
              <AnimatePresence>
                {scanResult && scanPhase === 'results' && (() => {
                  const risk = scanResult.risk_score || {}
                  const cfg  = RISK_CONFIG[risk.rating] || RISK_CONFIG.MEDIUM
                  const overallPassRate = risk.overall_pass_rate ?? 0
                  return (
                    <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
                      className="space-y-5 border-t border-slate-100 pt-6">

                      {/* ── Risk banner ── */}
                      <div className={`flex items-center gap-6 p-5 rounded-xl border ${cfg.bg} ${cfg.border}`}>
                        <div className={`w-20 h-20 rounded-full border-4 flex flex-col items-center justify-center flex-shrink-0 ${cfg.border} ${cfg.color}`}>
                          <span className="text-2xl font-black font-mono">{risk.score ?? '?'}</span>
                          <span className="text-[9px] opacity-60 font-mono">/100</span>
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className={`text-base font-black font-mono ${cfg.color}`}>
                            [{risk.rating || '?'}] RISK RATING
                          </p>
                          <p className="text-[12px] font-mono text-slate-500 mt-0.5">{cfg.desc}</p>
                          <p className="text-[11px] font-mono text-slate-400 mt-1">
                            model: {scanResult.model} &nbsp;·&nbsp; scan_id: {scanResult.scan_id?.slice(0,8)}…
                          </p>
                        </div>
                        <div className="flex gap-4 flex-shrink-0 flex-wrap">
                          {[
                            { label: 'CRITICAL', v: risk.critical_fails ?? 0, cls: 'text-red-500' },
                            { label: 'HIGH',     v: risk.high_fails ?? 0,     cls: 'text-amber-500' },
                            { label: 'FAILED',   v: risk.total_failed ?? 0,   cls: 'text-slate-600' },
                            { label: 'PASS%',    v: `${overallPassRate}%`,    cls: 'text-emerald-600' },
                          ].map(({ label, v, cls }) => (
                            <div key={label} className="text-center">
                              <div className={`text-xl font-black font-mono ${cls}`}>{v}</div>
                              <div className="text-[9px] text-slate-400 font-mono tracking-wider">{label}</div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* ── Dimension grid ── */}
                      <div>
                        <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2">DIMENSION RESULTS</p>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                          {Object.entries(scanResult.dimensions || {}).map(([key, dim]) => {
                            if (dim.error) return (
                              <div key={key} className="p-3 bg-white border border-red-100 rounded-xl">
                                <p className="text-[10px] font-bold text-slate-500 uppercase mb-1">{(dim.dimension||key).replace(/_/g,' ')}</p>
                                <p className="text-[10px] font-mono text-red-400 truncate">ERR: {dim.error.slice(0,40)}</p>
                              </div>
                            )
                            const pct   = Math.round(dim.pass_rate ?? 0)
                            const color = pct >= 90 ? 'text-emerald-600' : pct >= 70 ? 'text-amber-600' : 'text-red-500'
                            const bar   = pct >= 90 ? 'bg-emerald-400'   : pct >= 70 ? 'bg-amber-400'   : 'bg-red-400'
                            const name  = (dim.dimension || key).replace(/_/g, ' ').toUpperCase()
                            return (
                              <div key={key} className="p-3 bg-white border border-slate-100 rounded-xl">
                                <div className="flex justify-between items-baseline mb-2">
                                  <span className="text-[10px] font-bold text-slate-500 truncate pr-1">{name}</span>
                                  <span className={`text-[16px] font-black font-mono ${color}`}>{pct}%</span>
                                </div>
                                <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                                  <motion.div initial={{ width: 0 }} animate={{ width: `${pct}%` }}
                                    transition={{ duration: 0.8 }} className={`h-full ${bar}`} />
                                </div>
                                <div className="flex gap-2 mt-1.5 font-mono text-[9px]">
                                  <span className="text-emerald-500">✓ {dim.passed ?? 0}</span>
                                  <span className="text-red-400">✗ {dim.failed ?? 0}</span>
                                  <span className="text-slate-400">/ {dim.total ?? 0}</span>
                                </div>
                              </div>
                            )
                          })}
                        </div>
                      </div>

                      {/* ── Findings — structured scanner output ── */}
                      {findings.length > 0 ? (
                        <div className="space-y-4">
                          <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400">
                            SECURITY FINDINGS &nbsp;
                            <span className="px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 text-slate-500 normal-case font-bold">
                              {findings.length}
                            </span>
                          </p>
                          {['critical','high','medium','low'].map(sev => {
                            const items = findings.filter(f => f.severity === sev)
                            if (!items.length) return null
                            const sevColors = {
                              critical: 'border-l-red-500 bg-red-50/40',
                              high:     'border-l-amber-500 bg-amber-50/40',
                              medium:   'border-l-sky-400 bg-sky-50/40',
                              low:      'border-l-slate-300 bg-slate-50',
                            }
                            const sevLabel = {
                              critical: 'bg-red-100 text-red-600 border-red-200',
                              high:     'bg-amber-100 text-amber-600 border-amber-200',
                              medium:   'bg-sky-100 text-sky-600 border-sky-200',
                              low:      'bg-slate-100 text-slate-500 border-slate-200',
                            }
                            return (
                              <div key={sev}>
                                <p className={`text-[10px] font-bold uppercase tracking-widest mb-2 ${sev === 'critical' ? 'text-red-500' : sev === 'high' ? 'text-amber-500' : sev === 'medium' ? 'text-sky-500' : 'text-slate-400'}`}>
                                  {sev.toUpperCase()} — {items.length} finding{items.length !== 1 ? 's' : ''}
                                </p>
                                <div className="space-y-2">
                                  {items.slice(0, 8).map((f, i) => (
                                    <div key={i} className={`p-3 rounded-xl border border-slate-200 border-l-4 ${sevColors[f.severity] || sevColors.medium}`}>
                                      {/* Header row */}
                                      <div className="flex items-center gap-2 mb-1.5">
                                        <span className="text-[10px] font-mono text-slate-400">{f.id}</span>
                                        <span className="text-[12px] font-bold text-slate-800 flex-1 truncate">{f.name}</span>
                                        <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border ${sevLabel[f.severity] || sevLabel.medium}`}>
                                          {f.severity.toUpperCase()}
                                        </span>
                                      </div>
                                      {/* Dim + judge */}
                                      <div className="font-mono text-[10px] text-slate-500 mb-1">
                                        DIM: {f.dimension}
                                        {f.reason ? <span className="text-slate-400"> &nbsp;·&nbsp; JUDGE: {f.reason}</span> : null}
                                      </div>
                                      {/* Model response excerpt */}
                                      {f.response && (
                                        <pre className="text-[10px] font-mono bg-white border border-slate-200 text-slate-500 px-2 py-1.5 rounded mt-1 whitespace-pre-wrap break-words overflow-hidden" style={{ maxHeight: '60px' }}>
                                          &gt; {f.response.slice(0, 160)}{f.response.length > 160 ? '…' : ''}
                                        </pre>
                                      )}
                                    </div>
                                  ))}
                                  {items.length > 8 && (
                                    <p className="text-[10px] font-mono text-slate-400 text-center py-1">
                                      … {items.length - 8} more findings in the full report
                                    </p>
                                  )}
                                </div>
                              </div>
                            )
                          })}
                        </div>
                      ) : (
                        <div className="p-4 border border-emerald-200 bg-emerald-50 rounded-xl font-mono text-[12px] text-emerald-700 text-center">
                          ✓ NO FAILURES — all {risk.total_tests ?? 0} probes passed
                        </div>
                      )}

                      {/* ── Export panel ── */}
                      <div className="border border-slate-200 rounded-xl overflow-hidden">
                        {/* Header */}
                        <div className="flex items-center gap-2 px-4 py-2.5 bg-slate-50 border-b border-slate-200">
                          <RiDownloadLine className="text-slate-400 text-sm" />
                          <span className="text-[11px] font-bold text-slate-600 uppercase tracking-wider">Export Report</span>
                        </div>

                        {/* Main download buttons */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4">
                          {/* PDF Report */}
                          <button
                            onClick={() => handleDownloadPDF(scanResult)}
                            disabled={generatingPdf}
                            className="flex items-center gap-3 px-4 py-3.5 rounded-xl border-2 border-sky-400 bg-sky-50/60 hover:bg-sky-100 disabled:opacity-60 disabled:cursor-not-allowed transition-all group"
                          >
                            <div className="w-9 h-9 rounded-lg bg-sky-500 flex items-center justify-center flex-shrink-0 group-hover:bg-sky-600 transition-colors">
                              {generatingPdf
                                ? <RiRefreshLine className="text-white text-base animate-spin" />
                                : <RiFileLine className="text-white text-base" />
                              }
                            </div>
                            <div className="text-left flex-1 min-w-0">
                              <p className="text-[13px] font-bold text-sky-700">
                                {generatingPdf ? 'Generating…' : 'Download PDF Report'}
                              </p>
                              <p className="text-[10px] text-sky-500 font-mono">
                                Full 10-section assessment · All findings
                              </p>
                            </div>
                          </button>

                          {/* CSV Retraining */}
                          <button
                            onClick={() => handleDownloadCSV(scanResult)}
                            disabled={generatingCsv}
                            className="flex items-center gap-3 px-4 py-3.5 rounded-xl border-2 border-emerald-400 bg-emerald-50/60 hover:bg-emerald-100 disabled:opacity-60 disabled:cursor-not-allowed transition-all group"
                          >
                            <div className="w-9 h-9 rounded-lg bg-emerald-500 flex items-center justify-center flex-shrink-0 group-hover:bg-emerald-600 transition-colors">
                              {generatingCsv
                                ? <RiRefreshLine className="text-white text-base animate-spin" />
                                : <RiTableLine className="text-white text-base" />
                              }
                            </div>
                            <div className="text-left flex-1 min-w-0">
                              <p className="text-[13px] font-bold text-emerald-700">
                                {generatingCsv ? 'Exporting…' : 'Download CSV (Retraining)'}
                              </p>
                              <p className="text-[10px] text-emerald-600 font-mono">
                                Failed tests only · ML fine-tuning ready
                              </p>
                            </div>
                          </button>
                        </div>

                        {/* Info strip */}
                        <div className="flex items-start gap-2.5 px-4 py-2.5 bg-slate-50 border-t border-slate-200">
                          <RiInformationLine className="text-slate-400 text-sm flex-shrink-0 mt-0.5" />
                          <div>
                            <p className="text-[10px] text-slate-500 leading-relaxed">
                              <strong className="text-slate-600">PDF</strong> — Professional 10-section vulnerability report: Cover Page, Executive Summary, Metrics Dashboard, Dimension Analysis, Detailed Findings, Successful Cases, Attack Patterns, Recommendations, Final Verdict &amp; Appendix.
                            </p>
                            <p className="text-[10px] text-slate-500 mt-0.5 leading-relaxed">
                              <strong className="text-slate-600">CSV</strong> — Contains only failed test cases with columns: <span className="font-mono">test_id, category, severity, prompt, model_response, expected_behavior, failure_reason</span>. Ready for RLHF / DPO fine-tuning pipeline.
                            </p>
                          </div>
                        </div>

                        {/* HTML fallback */}
                        <div className="px-4 pb-3 pt-1">
                          <button
                            onClick={() => downloadReport(scanResult.scan_id)}
                            disabled={downloading}
                            className="w-full py-2 text-[11px] font-semibold text-slate-400 hover:text-slate-600 flex items-center justify-center gap-1.5 transition-colors disabled:opacity-60"
                          >
                            {downloading
                              ? <><RiRefreshLine className="animate-spin" /> Preparing…</>
                              : <><RiDownloadLine /> Download HTML Report (legacy)</>
                            }
                          </button>
                        </div>
                      </div>
                    </motion.div>
                  )
                })()}
              </AnimatePresence>
            </div>
          )}

          {/* ════════ INSTALLED MODELS TAB ════════ */}
          {tab === 'Installed Models' && (
            <div className="space-y-3">
              {modelMeta.length === 0 && availableModels.length === 0 ? (
                <div className="text-center py-10 text-slate-400 font-mono text-[12px]">
                  {sandboxOnline === false
                    ? 'Sandbox offline. Start with: docker compose up'
                    : 'No models installed. Upload a .gguf or pull one from Ollama.'}
                </div>
              ) : (
                (modelMeta.length > 0 ? modelMeta : availableModels.map(m => ({ name: m }))).map(m => {
                  const name    = typeof m === 'string' ? m : m.name
                  const sizeGb  = m.size_gb
                  const params  = m.params
                  const family  = m.family
                  const quant   = m.quant
                  const modified = m.modified
                  const isDeleting = deletingModel === name

                  return (
                    <motion.div key={name}
                      initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
                      className="p-4 border border-slate-100 rounded-xl bg-white hover:border-sky-100 hover:shadow-sm transition-all">
                      {/* Row 1: icon + name + badges */}
                      <div className="flex items-start gap-4">
                        <div className="w-10 h-10 rounded-xl bg-sky-50 border border-sky-100 flex items-center justify-center flex-shrink-0">
                          <RiCpuLine className="text-sky-500 text-lg" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-[14px] font-bold text-slate-800 truncate">{name}</span>
                            {quant && <QuantBadge quant={quant} />}
                            {params && (
                              <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 text-[10px] font-bold border border-slate-200">
                                {params}
                              </span>
                            )}
                          </div>
                          {/* Row 2: metadata chips */}
                          <div className="flex flex-wrap gap-3 mt-2 text-[11px]">
                            {family && (
                              <span className="flex items-center gap-1 text-slate-500">
                                <RiRobotLine className="text-slate-400" />
                                <span className="font-semibold">{family}</span>
                              </span>
                            )}
                            {sizeGb > 0 && (
                              <span className="flex items-center gap-1 text-slate-500">
                                <RiFolder3Line className="text-slate-400" />
                                <span className="font-semibold">{sizeGb} GB</span>
                              </span>
                            )}
                            {modified && (
                              <span className="flex items-center gap-1 text-slate-500">
                                <RiTimeLine className="text-slate-400" />
                                <span>{relativeTime(modified)}</span>
                              </span>
                            )}
                          </div>
                        </div>
                        {/* Actions */}
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <button onClick={() => { setSelectedModel(name); setTab('New Scan') }}
                            className="px-4 py-1.5 border border-sky-300 rounded-lg text-sky-600 text-[11px] font-semibold font-mono hover:bg-sky-50 transition-colors">
                            Scan →
                          </button>
                          <button onClick={() => deleteModel(name)} disabled={isDeleting}
                            className="p-1.5 border border-slate-200 rounded-lg text-slate-400 hover:text-red-500 hover:border-red-300 disabled:opacity-50 transition-colors">
                            {isDeleting
                              ? <RiRefreshLine className="animate-spin text-sm" />
                              : <RiDeleteBinLine className="text-sm" />}
                          </button>
                        </div>
                      </div>
                    </motion.div>
                  )
                })
              )}
              <button onClick={() => { checkHealth(); fetchModelMeta() }}
                className="w-full py-2 text-[11px] text-slate-400 hover:text-sky-500 font-semibold transition-colors flex items-center justify-center gap-1">
                <RiRefreshLine /> Refresh model list
              </button>
            </div>
          )}

          {/* ════════ SCAN HISTORY TAB ════════ */}
          {tab === 'Scan History' && (
            <div className="space-y-2">
              {history.length === 0 ? (
                <div className="text-center py-10 text-slate-400 font-mono text-[12px]">No scans yet. Run your first scan to see history.</div>
              ) : history.slice(0, 20).map(({ scan_id, model, timestamp, risk, has_report }) => {
                const rating = risk?.rating || 'MEDIUM'
                const cfg    = RISK_CONFIG[rating] || RISK_CONFIG.MEDIUM
                return (
                  <div key={scan_id}
                    onClick={() => has_report && downloadReport(scan_id)}
                    className={`flex items-center gap-4 p-4 border border-slate-100 rounded-xl transition-colors ${has_report ? 'cursor-pointer hover:border-sky-200 hover:bg-sky-50/30' : ''}`}>
                    <div className={`w-12 h-12 rounded-xl flex items-center justify-center font-mono text-[15px] font-black flex-shrink-0 ${cfg.bg} ${cfg.color}`}>
                      {risk?.score ?? '?'}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-[13px] font-bold text-slate-700 truncate font-mono">{model}</p>
                      <p className="text-[11px] text-slate-400 mt-0.5 flex items-center gap-1 font-mono">
                        <RiTimeLine className="text-[11px]" /> {relativeTime(timestamp)}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-bold uppercase px-3 py-1 rounded-full border ${cfg.bg} ${cfg.border} ${cfg.color}`}>
                        {rating}
                      </span>
                      {has_report && (
                        <div className="flex gap-1">
                          <button
                            onClick={e => { e.stopPropagation(); downloadReport(scan_id) }}
                            title="Download HTML report"
                            className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-sky-600 font-semibold transition-colors px-2 py-1 rounded-lg hover:bg-sky-50"
                          >
                            <RiDownloadLine /> HTML
                          </button>
                          <button
                            onClick={e => {
                              e.stopPropagation()
                              // Fetch full result then generate PDF
                              fetch(`${SBX_API}/scan/${scan_id}/status`)
                                .then(r => r.json())
                                .then(d => { if (d.result) handleDownloadPDF(d.result) })
                                .catch(() => alert('Could not load scan data for PDF.'))
                            }}
                            title="Download PDF report"
                            className="flex items-center gap-1 text-[10px] text-sky-600 hover:text-sky-700 font-semibold transition-colors px-2 py-1 rounded-lg hover:bg-sky-50 border border-sky-200"
                          >
                            <RiFileLine /> PDF
                          </button>
                          <button
                            onClick={e => {
                              e.stopPropagation()
                              fetch(`${SBX_API}/scan/${scan_id}/status`)
                                .then(r => r.json())
                                .then(d => { if (d.result) handleDownloadCSV(d.result) })
                                .catch(() => alert('Could not load scan data for CSV.'))
                            }}
                            title="Download CSV for retraining"
                            className="flex items-center gap-1 text-[10px] text-emerald-600 hover:text-emerald-700 font-semibold transition-colors px-2 py-1 rounded-lg hover:bg-emerald-50 border border-emerald-200"
                          >
                            <RiTableLine /> CSV
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}
              <button onClick={fetchHistory}
                className="w-full py-2 text-[11px] text-slate-400 hover:text-sky-500 font-semibold transition-colors flex items-center justify-center gap-1">
                <RiRefreshLine /> Refresh history
              </button>
            </div>
          )}
        </div>
      </Card>

      {/* CSS for indeterminate progress animation */}
      <style>{`
        @keyframes uploadSlide {
          0%   { transform: translateX(-100%) }
          100% { transform: translateX(400%) }
        }
      `}</style>
    </PageWrapper>
  )
}
