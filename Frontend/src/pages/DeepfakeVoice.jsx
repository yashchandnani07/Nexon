import { useState, useRef, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiMicLine, RiUploadCloud2Line, RiStopCircleLine, RiHistoryLine,
  RiShieldCheckLine, RiAlertLine, RiRobot2Line, RiCheckLine,
  RiCloseLine, RiLoader4Line, RiTimeLine, RiFileMusicLine,
  RiBarChartLine, RiArrowRightLine, RiRecordCircleLine, RiPlayLine,
  RiRefreshLine,
} from 'react-icons/ri'
import {
  Card, PageWrapper, PageHeader, SectionHeader, RiskBadge,
  ConfidenceRow, AlertStrip, SubTabs,
} from '../components/ui'

/* ══════════════════════════════════════════════════════════════════
   Constants
══════════════════════════════════════════════════════════════════ */
const API  = '/api/voice-scan'
const WS   = (() => {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${window.location.host}/api/voice-scan/ws/realtime`
})()

const TIER_CONFIG = {
  CRITICAL: { color: '#F87171', bg: '#FFF1F2', label: 'CRITICAL'  },
  HIGH:     { color: '#FB923C', bg: '#FFF7ED', label: 'HIGH RISK' },
  MEDIUM:   { color: '#FBBF24', bg: '#FFFBEB', label: 'MEDIUM'    },
  LOW:      { color: '#34D399', bg: '#ECFDF5', label: 'LOW'       },
}

const steps = [
  { n: '1', title: 'MFCC Extraction',    desc: '40 mel-frequency cepstral coefficients + delta derivatives extracted per frame' },
  { n: '2', title: 'SVM Anti-spoofing',  desc: 'Random Forest trained on real vs synthetic voice distributions'                },
  { n: '3', title: 'Wav2Vec2 Features',  desc: 'Fine-tuned transformer for latent acoustic feature analysis'                    },
  { n: '4', title: 'Ensemble + Llama3',  desc: 'Weighted fusion → Llama 3 contextual explanation for security analysts'        },
]

/* ══════════════════════════════════════════════════════════════════
   Sub-components
══════════════════════════════════════════════════════════════════ */

/* ── Animated Waveform bar display ────────────────────────────── */
function WaveformBars({ samples = [], color = '#0EA5E9', height = 64, recording = false }) {
  const bars = samples.length > 0 ? samples : Array.from({ length: 60 }, () => 0.1)
  return (
    <div className="flex items-center gap-px w-full" style={{ height }}>
      {bars.map((v, i) => {
        const h = Math.max(3, Math.round(v * height * 1.4))
        return (
          <motion.div
            key={i}
            animate={{ height: recording ? [h, h * (0.5 + Math.random()), h] : h }}
            transition={recording ? { duration: 0.4, repeat: Infinity, ease: 'easeInOut', delay: i * 0.015 } : { duration: 0.4 }}
            className="flex-1 rounded-full"
            style={{ background: color, minWidth: 2, maxWidth: 8 }}
          />
        )
      })}
    </div>
  )
}

/* ── SVG Ring Score ────────────────────────────────────────────── */
function RingScore({ score, verdict, size = 140 }) {
  const r    = 52
  const circ = 2 * Math.PI * r
  const off  = circ - (score / 100) * circ
  const tc   = TIER_CONFIG[verdict === 'FAKE' ? (score >= 86 ? 'CRITICAL' : 'HIGH') : 'LOW']
  const strokeColor = verdict === 'FAKE' ? (score >= 61 ? '#FB923C' : '#FBBF24') : '#34D399'

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg viewBox="0 0 120 120" width={size} height={size} className="-rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="#E2E8F0" strokeWidth="11" />
        <motion.circle
          cx="60" cy="60" r={r} fill="none"
          stroke={strokeColor} strokeWidth="11" strokeLinecap="round"
          strokeDasharray={circ}
          initial={{ strokeDashoffset: circ }}
          animate={{ strokeDashoffset: off }}
          transition={{ duration: 1.2, ease: [0.34, 1.2, 0.64, 1] }}
        />
      </svg>
      <div className="absolute text-center">
        <p className="text-[26px] font-bold text-gray-900 leading-none">{score}</p>
        <p className="text-[10px] text-gray-500 font-semibold mt-0.5">Risk Score</p>
        <p className={`text-[11px] font-bold mt-0.5 ${verdict === 'FAKE' ? 'text-orange-500' : 'text-emerald-600'}`}>
          {verdict === 'FAKE' ? '⚠ FAKE' : '✓ REAL'}
        </p>
      </div>
    </div>
  )
}

/* ── Feedback Modal ────────────────────────────────────────────── */
function FeedbackModal({ predId, currentVerdict, onClose, onSubmit }) {
  const [label, setLabel]   = useState(currentVerdict)
  const [notes, setNotes]   = useState('')
  const [saving, setSaving] = useState(false)
  const [done, setDone]     = useState(false)

  const submit = async () => {
    setSaving(true)
    try {
      const fd = new FormData()
      fd.append('correct_label', label)
      fd.append('reviewer_id',   'analyst')
      fd.append('notes',         notes)
      fd.append('verdict',       currentVerdict)
      const res = await fetch(`${API}/feedback/${predId}`, { method: 'POST', body: fd })
      if (res.ok) { setDone(true); setTimeout(() => { onSubmit?.(); onClose() }, 1500) }
    } finally { setSaving(false) }
  }

  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.92, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.92, opacity: 0 }}
        className="bg-white rounded-2xl shadow-2xl w-full max-w-md mx-4 p-6"
        onClick={e => e.stopPropagation()}
      >
        {done ? (
          <div className="text-center py-6">
            <div className="w-14 h-14 rounded-full bg-emerald-50 flex items-center justify-center mx-auto mb-3">
              <RiCheckLine className="text-emerald-500 text-2xl" />
            </div>
            <p className="text-[15px] font-bold text-gray-900">Feedback Submitted!</p>
            <p className="text-[12px] text-gray-500 mt-1">
              {label !== currentVerdict ? 'Added to retraining queue ✓' : 'Confirmed — model is accurate ✓'}
            </p>
          </div>
        ) : (
          <>
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-[16px] font-bold text-gray-900">Submit Feedback</h3>
              <button onClick={onClose} className="w-8 h-8 rounded-full bg-slate-50 flex items-center justify-center hover:bg-slate-100 transition-colors">
                <RiCloseLine className="text-gray-500" />
              </button>
            </div>

            <p className="text-[12px] text-gray-500 mb-4">
              Our model predicted: <span className={`font-bold ${currentVerdict === 'FAKE' ? 'text-orange-500' : 'text-emerald-600'}`}>{currentVerdict}</span>. Was this correct?
            </p>

            {/* Verdict selector */}
            <div className="flex gap-3 mb-5">
              {['REAL', 'FAKE'].map(v => (
                <button
                  key={v}
                  onClick={() => setLabel(v)}
                  className={`flex-1 py-3 rounded-xl font-semibold text-[13px] border-2 transition-all ${
                    label === v
                      ? v === 'FAKE' ? 'border-orange-400 bg-orange-50 text-orange-700' : 'border-emerald-400 bg-emerald-50 text-emerald-700'
                      : 'border-slate-100 text-gray-500 hover:border-slate-200'
                  }`}
                >
                  {v === 'FAKE' ? '⚠ AI Generated (FAKE)' : '✓ Genuine (REAL)'}
                </button>
              ))}
            </div>

            {/* Notes */}
            <div className="mb-5">
              <label className="text-[12px] font-semibold text-gray-600 mb-1.5 block">Notes (optional)</label>
              <textarea
                value={notes} onChange={e => setNotes(e.target.value)}
                placeholder="Describe any observations about this audio..."
                className="w-full border border-slate-200 rounded-xl px-3.5 py-3 text-[12px] text-gray-800 font-medium placeholder-gray-300 outline-none focus:border-sky-400 resize-none h-20"
              />
            </div>

            {label !== currentVerdict && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                className="inline-alert inline-alert-info mb-4 text-[11px]">
                <RiRefreshLine />
                <span>This correction will be <strong>added to the retraining queue</strong> to improve the model.</span>
              </motion.div>
            )}

            <button
              onClick={submit} disabled={saving}
              className="btn-primary w-full justify-center py-3"
            >
              {saving ? <><RiLoader4Line className="animate-spin" /> Submitting…</> : 'Submit Feedback'}
            </button>
          </>
        )}
      </motion.div>
    </motion.div>
  )
}

/* ── History Row ───────────────────────────────────────────────── */
function HistoryRow({ row, onFeedback }) {
  const tc   = TIER_CONFIG[row.tier] ?? TIER_CONFIG.LOW
  const date = new Date((row.created_at || '').replace(' ', 'T'))
  const isValid = !isNaN(date)

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }}
      className={`flex items-center gap-3 py-3.5 px-4 border-b border-slate-50 last:border-none hover:bg-sky-50/50 cursor-pointer group transition-colors border-l-2`}
      style={{ borderLeftColor: tc.color }}
    >
      <div className="icon-box icon-box-blue flex-shrink-0" style={{ width: 32, height: 32, borderRadius: 8 }}>
        <RiFileMusicLine className="text-sm" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-[12px] font-semibold text-gray-800 truncate">{row.file_name || 'audio_recording.wav'}</p>
        <p className="text-[10px] text-gray-400 mt-0.5">
          {isValid ? date.toLocaleString() : '—'} · {row.processing_ms ?? '—'}ms · {row.channel || 'upload'}
        </p>
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        <span
          className="text-[11px] font-bold px-2.5 py-1 rounded-lg"
          style={{ background: tc.bg, color: tc.color }}
        >
          {row.risk_score ?? '—'}/100
        </span>
        <span className={`chip text-[10px] ${row.verdict === 'FAKE' ? 'chip-high' : 'chip-safe'}`}>
          {row.verdict ?? '—'}
        </span>
        <button
          onClick={() => onFeedback(row)}
          className="text-[10px] font-semibold text-sky-500 hover:text-sky-700 opacity-0 group-hover:opacity-100 transition-opacity"
        >
          Feedback
        </button>
      </div>
    </motion.div>
  )
}

/* ══════════════════════════════════════════════════════════════════
   Main Component
══════════════════════════════════════════════════════════════════ */
export default function DeepfakeVoice() {
  const [tab, setTab]             = useState('Analyze')
  const [result, setResult]       = useState(null)
  const [loading, setLoading]     = useState(false)
  const [recording, setRecording] = useState(false)
  const [liveResult, setLiveResult] = useState(null)   // latest WS result
  const [liveWaveform, setLiveWaveform] = useState([]) // growing waveform
  const [recordDuration, setRecordDuration] = useState(0)
  const [history, setHistory]     = useState([])
  const [histLoading, setHistLoading] = useState(false)
  const [feedback, setFeedback]   = useState(null)     // { predId, verdict }

  const fileRef       = useRef(null)
  const wsRef         = useRef(null)
  const mediaRecRef   = useRef(null)
  const audioCtxRef   = useRef(null)
  const processorRef  = useRef(null)
  const timerRef      = useRef(null)

  /* ── Fetch history ────────────────────────────────────────────── */
  const fetchHistory = useCallback(async () => {
    setHistLoading(true)
    try {
      const res = await fetch(`${API}/history?limit=30`)
      if (res.ok) {
        const data = await res.json()
        setHistory(data.history || [])
      }
    } catch (e) { console.error('History fetch failed', e) }
    finally { setHistLoading(false) }
  }, [])

  useEffect(() => { fetchHistory() }, [fetchHistory])

  /* ── Upload handler ───────────────────────────────────────────── */
  const handleUpload = async (file) => {
    if (!file) return
    setLoading(true); setResult(null)
    try {
      const fd = new FormData()
      fd.append('file', file)
      fd.append('use_llm', 'true')
      const res  = await fetch(`${API}/analyze/voice`, { method: 'POST', body: fd })
      const data = await res.json()
      if (res.ok) {
        setResult({ ...data, fileName: file.name })
        fetchHistory()
      } else {
        alert('Error: ' + (data.detail || 'Unknown'))
      }
    } catch (e) { alert('Could not reach Voice API') }
    finally { setLoading(false); if (fileRef.current) fileRef.current.value = '' }
  }

  /* ── Recording — WebSocket real-time ─────────────────────────── */
  const startRecording = useCallback(async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: { sampleRate: 16000, channelCount: 1 } })

      // WebSocket
      const ws = new WebSocket(WS)
      wsRef.current = ws
      ws.binaryType = 'arraybuffer'

      ws.onopen = () => console.log('[WS] Connected for real-time recording')
      ws.onerror = (e) => console.error('[WS] Error', e)

      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data)
          if (msg.type === 'result') {
            setLiveResult(msg)
            if (msg.waveform) {
              setLiveWaveform(prev => {
                const next = [...prev, ...msg.waveform]
                return next.slice(-120) // keep last 120 pts
              })
            }
          } else if (msg.type === 'tick' && msg.waveform_preview) {
            setLiveWaveform(prev => {
              const next = [...prev, ...msg.waveform_preview]
              return next.slice(-120)
            })
          }
        } catch (e) { /* ignore */ }
      }

      // AudioContext → ScriptProcessor → send Float32 chunks
      const ctx = new (window.AudioContext || window.webkitAudioContext)({ sampleRate: 16000 })
      audioCtxRef.current = ctx
      const src = ctx.createMediaStreamSource(stream)
      const proc = ctx.createScriptProcessor(4096, 1, 1)
      processorRef.current = proc

      proc.onaudioprocess = (e) => {
        if (ws.readyState === WebSocket.OPEN) {
          const pcm = e.inputBuffer.getChannelData(0)
          ws.send(pcm.buffer.slice(0))  // send Float32Array
        }
      }

      src.connect(proc)
      proc.connect(ctx.destination)

      mediaRecRef.current = stream
      setRecording(true)
      setLiveResult(null)
      setLiveWaveform([])
      setRecordDuration(0)

      // Timer
      timerRef.current = setInterval(() => setRecordDuration(d => d + 1), 1000)

    } catch (e) {
      alert('Microphone access denied or unavailable: ' + e.message)
    }
  }, [])

  const stopRecording = useCallback(() => {
    // Stop timer
    if (timerRef.current) clearInterval(timerRef.current)

    // Stop audio processor
    if (processorRef.current) { processorRef.current.disconnect(); processorRef.current = null }
    if (audioCtxRef.current)  { audioCtxRef.current.close();      audioCtxRef.current = null }

    // Stop mic tracks
    if (mediaRecRef.current) {
      mediaRecRef.current.getTracks().forEach(t => t.stop())
      mediaRecRef.current = null
    }

    // Close WS
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null }

    setRecording(false)
  }, [])

  // Cleanup on unmount
  useEffect(() => () => stopRecording(), [stopRecording])

  const fmtDur = (s) => `${Math.floor(s / 60).toString().padStart(2,'0')}:${(s % 60).toString().padStart(2,'0')}`

  /* ── Risk color helpers ───────────────────────────────────────── */
  const riskColor = (score) =>
    score >= 86 ? '#F87171' : score >= 61 ? '#FB923C' : score >= 31 ? '#FBBF24' : '#34D399'

  const tierLabel = (score) =>
    score >= 86 ? 'CRITICAL' : score >= 61 ? 'HIGH RISK' : score >= 31 ? 'MEDIUM' : 'LOW RISK'

  /* ══════════════════════════════════════════════════════════════
     Render
  ══════════════════════════════════════════════════════════════ */
  return (
    <PageWrapper>
      <PageHeader
        title="Deepfake Voice Detector"
        sub="MFCC · SVM · Wav2Vec2 ensemble · Real-time analysis · Llama 3 explanation"
      />

      <SubTabs
        tabs={['Analyze', 'Scan History']}
        active={tab}
        onChange={(t) => { setTab(t); if (t === 'Scan History') fetchHistory() }}
      />

      {/* ══════════════════════════════
          TAB: ANALYZE
      ══════════════════════════════ */}
      {tab === 'Analyze' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

          {/* Left column */}
          <div className="lg:col-span-2 space-y-4">

            {/* ── Input Card ── */}
            <Card>
              <SectionHeader title="Audio Input" />

              {/* Recording controls */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-5">
                {/* Record button */}
                <motion.button
                  onClick={recording ? stopRecording : startRecording}
                  whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.98 }}
                  className={`flex flex-col items-center justify-center gap-2 py-7 rounded-2xl border-2 transition-all ${
                    recording
                      ? 'border-orange-400 bg-orange-50'
                      : 'border-sky-200 bg-sky-50 hover:border-sky-400'
                  }`}
                >
                  <div className={`w-12 h-12 rounded-full flex items-center justify-center ${recording ? 'bg-orange-500 animate-pulse' : 'bg-sky-500'}`}>
                    {recording
                      ? <RiStopCircleLine className="text-white text-2xl" />
                      : <RiMicLine className="text-white text-2xl" />
                    }
                  </div>
                  <div className="text-center">
                    <p className={`text-[13px] font-bold ${recording ? 'text-orange-700' : 'text-sky-700'}`}>
                      {recording ? 'Stop Recording' : 'Record Live Audio'}
                    </p>
                    {recording && (
                      <p className="text-[11px] text-orange-500 font-mono mt-0.5 flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-orange-500 animate-pulse inline-block" />
                        {fmtDur(recordDuration)} · Live analyzing…
                      </p>
                    )}
                    {!recording && <p className="text-[11px] text-sky-400 mt-0.5">Real-time AI detection</p>}
                  </div>
                </motion.button>

                {/* Upload button */}
                <motion.button
                  onClick={() => fileRef.current?.click()}
                  disabled={loading || recording}
                  whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.98 }}
                  className="flex flex-col items-center justify-center gap-2 py-7 rounded-2xl border-2 border-dashed border-slate-200 hover:border-sky-300 hover:bg-sky-50/50 transition-all disabled:opacity-50"
                >
                  <div className="w-12 h-12 rounded-full bg-slate-100 flex items-center justify-center">
                    {loading
                      ? <RiLoader4Line className="text-sky-500 text-2xl animate-spin" />
                      : <RiUploadCloud2Line className="text-slate-400 text-2xl" />
                    }
                  </div>
                  <div className="text-center">
                    <p className="text-[13px] font-bold text-gray-700">
                      {loading ? 'Analyzing…' : 'Upload Audio File'}
                    </p>
                    <p className="text-[11px] text-gray-400 mt-0.5">WAV · MP3 · FLAC · M4A · OGG</p>
                  </div>
                </motion.button>
                <input ref={fileRef} type="file" className="hidden" accept=".wav,.mp3,.ogg,.m4a,.flac,.aac" onChange={e => handleUpload(e.target.files?.[0])} />
              </div>

              {/* ── Live waveform during recording ── */}
              <AnimatePresence>
                {recording && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                    className="overflow-hidden"
                  >
                    <div className="bg-gray-900 rounded-2xl p-4 mb-4">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full bg-orange-400 animate-pulse" />
                          <span className="text-[11px] font-semibold text-gray-300">Live Waveform</span>
                        </div>
                        <span className="text-[10px] font-mono text-gray-500">{fmtDur(recordDuration)}</span>
                      </div>
                      <WaveformBars
                        samples={liveWaveform.length ? liveWaveform.slice(-80) : []}
                        color={liveResult ? riskColor(liveResult.risk_score) : '#38BDF8'}
                        height={56}
                        recording={recording}
                      />
                    </div>

                    {/* Live score card */}
                    {liveResult && (
                      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
                        className="grid grid-cols-2 gap-3 mb-4">
                        <div className="p-3 rounded-xl border border-slate-100 bg-slate-50 text-center">
                          <p className="text-[10px] text-gray-400 font-medium uppercase tracking-wider mb-1">Live Risk</p>
                          <p className="text-[28px] font-bold leading-none" style={{ color: riskColor(liveResult.risk_score) }}>
                            {liveResult.risk_score}
                          </p>
                          <p className="text-[10px] font-semibold mt-0.5" style={{ color: riskColor(liveResult.risk_score) }}>
                            {tierLabel(liveResult.risk_score)}
                          </p>
                        </div>
                        <div className="p-3 rounded-xl border border-slate-100 bg-slate-50">
                          <p className="text-[10px] text-gray-400 font-medium uppercase tracking-wider mb-2">Chunk #{liveResult.chunk}</p>
                          <div className="space-y-1.5">
                            <div className="flex justify-between text-[11px] pt-1">
                              <span className="text-gray-500 font-semibold">Verdict</span>
                              <span className={`font-bold text-[11px] ${liveResult.verdict === 'FAKE' ? 'text-orange-500' : 'text-emerald-600'}`}>
                                {liveResult.verdict}
                              </span>
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    )}

                    {!liveResult && (
                      <div className="flex items-center gap-2 text-[12px] text-gray-400 mb-3">
                        <RiLoader4Line className="animate-spin text-sky-400" />
                        Accumulating audio — first score in ~3s…
                      </div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </Card>

            {/* ── Upload Result Panel ── */}
            <AnimatePresence>
              {result && !recording && (
                <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
                  <Card>
                    {/* Header */}
                    <div className="flex items-start justify-between mb-5 pb-4 border-b border-slate-100">
                      <div className="flex items-center gap-3">
                        <div className="icon-box icon-box-blue" style={{ width: 38, height: 38 }}>
                          <RiFileMusicLine className="text-base" />
                        </div>
                        <div>
                          <p className="text-[14px] font-bold text-gray-900">{result.fileName}</p>
                          <p className="text-[11px] text-gray-400 mt-0.5">
                            {result.duration_s ? `${result.duration_s}s` : ''} · {result.processing_ms}ms · {result.chunks_analyzed} chunks
                          </p>
                        </div>
                      </div>
                      <span className={`chip text-[11px] font-bold ${result.verdict === 'FAKE' ? 'chip-high' : 'chip-safe'}`}>
                        {result.verdict}
                      </span>
                    </div>

                    {/* Risk ring + waveform */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mb-5">
                      {/* Left: Ring */}
                      <div className="flex flex-col items-center justify-center gap-3">
                        <RingScore score={result.risk_score} verdict={result.verdict} size={150} />
                        <div className="text-center">
                          <span
                            className="text-[12px] font-bold px-3 py-1.5 rounded-full"
                            style={{
                              background: (TIER_CONFIG[result.tier] ?? TIER_CONFIG.LOW).bg,
                              color:      (TIER_CONFIG[result.tier] ?? TIER_CONFIG.LOW).color,
                            }}
                          >
                            {result.tier ?? 'LOW'} RISK
                          </span>
                          <p className="text-[11px] text-gray-500 mt-2 max-w-[160px]">{result.action}</p>
                        </div>
                      </div>

                      {/* Right: Waveform */}
                      <div>
                        <p className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">Audio Waveform</p>
                        <div className="bg-gray-900 rounded-2xl p-4">
                          <WaveformBars
                            samples={(result.waveform_samples || []).slice(0, 80)}
                            color={result.verdict === 'FAKE' ? '#FB923C' : '#34D399'}
                            height={64}
                          />
                        </div>
                        <p className="text-[10px] text-gray-400 mt-2">
                          Amplitude envelope · {result.duration_s ?? '?'}s · {result.sample_rate ?? 16000}Hz
                        </p>
                      </div>
                    </div>

                    {/* Score bars */}
                    <div className="mb-5">
                      <p className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">Model Scores</p>
                      <ConfidenceRow label="Final Risk Score" value={result.risk_score ?? 0} delay={0.0} />
                    </div>

                    {/* SHAP Indicators */}
                    {result.top_indicators?.length > 0 && (
                      <div className="mb-5">
                        <p className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">SHAP Top Indicators</p>
                        <div className="space-y-2">
                          {result.top_indicators.map((ind, i) => (
                            <div key={i} className="flex items-start gap-2 py-1.5 border-b border-slate-50 last:border-none">
                              <span className="w-5 h-5 rounded-md bg-sky-50 text-sky-600 text-[10px] font-bold flex items-center justify-center flex-shrink-0">{i + 1}</span>
                              <p className="text-[12px] text-gray-700 font-medium">{ind}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Llama3 Explanation */}
                    {result.explanation && (
                      <div className="mb-5 bg-gradient-to-br from-sky-50 to-indigo-50 rounded-2xl p-4 border border-sky-100">
                        <div className="flex items-center gap-2 mb-3">
                          <div className="icon-box icon-box-indigo" style={{ width: 28, height: 28, borderRadius: 7 }}>
                            <RiRobot2Line className="text-xs" />
                          </div>
                          <p className="text-[12px] font-bold text-indigo-800">Llama 3 Analyst Explanation</p>
                          <span className="chip chip-muted text-[9px] ml-auto">AI Generated</span>
                        </div>
                        <p className="text-[13px] text-gray-700 leading-relaxed">{result.explanation}</p>
                      </div>
                    )}
                    {!result.explanation && (
                      <AlertStrip level="info">
                        <RiRobot2Line />
                        <span>Llama 3 explanation unavailable — <strong>Ollama</strong> not detected. Start ollama and re-analyze to enable AI explanations.</span>
                      </AlertStrip>
                    )}

                    {/* Actions */}
                    <div className="flex flex-wrap gap-2 pt-4 border-t border-slate-100">
                      <button
                        onClick={() => setFeedback({ predId: result.prediction_id, verdict: result.verdict })}
                        className="btn-primary"
                      >
                        <RiCheckLine /> Submit Feedback
                      </button>
                      <button className="btn-ghost">
                        <RiBarChartLine /> Download Report
                      </button>
                    </div>
                  </Card>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* ── Right Sidebar ── */}
          <div className="space-y-4">
            {/* How It Works */}
            <Card>
              <SectionHeader title="How It Works" />
              <div className="space-y-4">
                {steps.map(({ n, title, desc }, i) => (
                  <motion.div
                    key={n} initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.07 }}
                    className="flex gap-3"
                  >
                    <div className="w-7 h-7 rounded-lg bg-sky-50 border border-sky-200 flex items-center justify-center flex-shrink-0 text-[12px] font-bold text-sky-600">{n}</div>
                    <div>
                      <p className="text-[12px] font-bold text-gray-800">{title}</p>
                      <p className="text-[11px] text-gray-400 leading-relaxed mt-0.5">{desc}</p>
                    </div>
                  </motion.div>
                ))}
              </div>
            </Card>

            {/* Quick Stats */}
            <Card>
              <SectionHeader
                title="Session Stats"
                right={
                  <button onClick={fetchHistory} className="text-[11px] text-sky-500 hover:text-sky-700">Refresh</button>
                }
              />
              <div className="space-y-0">
                {[
                  { label: 'Total Scans', value: history.length, accent: false },
                  { label: 'Deepfakes Detected', value: history.filter(h => h.verdict === 'FAKE').length, accent: true },
                  { label: 'Genuine Audio',       value: history.filter(h => h.verdict === 'REAL').length, accent: false },
                ].map(({ label, value, accent }) => (
                  <div key={label} className="py-3 border-b border-slate-50 last:border-none flex justify-between items-center">
                    <span className="text-[12px] text-gray-500 font-medium">{label}</span>
                    <span className={`text-[18px] font-bold ${accent ? 'text-orange-500' : 'text-gray-900'}`}>{value}</span>
                  </div>
                ))}
              </div>
            </Card>

            {/* Formats */}
            <Card>
              <SectionHeader title="Supported Formats" />
              <div className="grid grid-cols-3 gap-2">
                {['WAV', 'MP3', 'FLAC', 'OGG', 'M4A', 'AAC'].map(f => (
                  <div key={f} className="p-2 bg-sky-50 border border-sky-100 rounded-lg text-[11px] font-bold text-sky-700 text-center">{f}</div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      )}

      {/* ══════════════════════════════
          TAB: SCAN HISTORY
      ══════════════════════════════ */}
      {tab === 'Scan History' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* History list */}
          <div className="lg:col-span-2">
            <Card>
              <div className="flex items-center justify-between mb-4">
                <SectionHeader title={`Scan History (${history.length})`} />
                <button onClick={fetchHistory} className="btn-ghost text-[12px] py-1.5 px-3 -mt-4">
                  <RiRefreshLine className={histLoading ? 'animate-spin' : ''} />
                  Refresh
                </button>
              </div>
              {histLoading ? (
                <div className="flex flex-col items-center py-12 gap-3">
                  <RiLoader4Line className="text-sky-400 text-3xl animate-spin" />
                  <p className="text-[12px] text-gray-400">Loading scan history…</p>
                </div>
              ) : history.length === 0 ? (
                <div className="text-center py-12 text-gray-400">
                  <RiHistoryLine className="text-4xl mx-auto mb-2 opacity-30" />
                  <p className="text-[13px] font-medium">No scans yet</p>
                  <p className="text-[11px] mt-1">Upload or record audio to get started</p>
                </div>
              ) : (
                history.map((row, i) => (
                  <HistoryRow
                    key={row.id ?? i}
                    row={row}
                    onFeedback={(r) => setFeedback({ predId: r.id, verdict: r.verdict })}
                  />
                ))
              )}
            </Card>
          </div>

          {/* Stats sidebar */}
          <div className="space-y-4">
            <Card>
              <SectionHeader title="Detection Summary" />
              {(() => {
                const total = history.length || 1
                const fakes = history.filter(h => h.verdict === 'FAKE').length
                const pct   = Math.round(fakes / total * 100)
                return (
                  <div>
                    <div className="flex flex-col items-center my-4">
                      <RingScore
                        score={pct}
                        verdict={pct >= 50 ? 'FAKE' : 'REAL'}
                        size={120}
                      />
                      <p className="text-[11px] text-gray-500 mt-2">Deepfake Detection Rate</p>
                    </div>
                    <div className="space-y-2.5 mt-2">
                      {[
                        { l: 'Total Scanned', v: history.length, c: 'text-gray-900' },
                        { l: 'Deepfakes (FAKE)', v: fakes, c: 'text-orange-500' },
                        { l: 'Genuine (REAL)', v: history.length - fakes, c: 'text-emerald-600' },
                      ].map(({ l, v, c }) => (
                        <div key={l} className="flex justify-between py-2 border-b border-slate-50 last:border-none">
                          <span className="text-[11px] text-gray-500">{l}</span>
                          <span className={`text-[13px] font-bold ${c}`}>{v}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              })()}
            </Card>

            <Card>
              <SectionHeader title="Recent Risk Tiers" />
              {Object.entries(
                history.slice(0, 10).reduce((acc, h) => {
                  acc[h.tier || 'LOW'] = (acc[h.tier || 'LOW'] || 0) + 1
                  return acc
                }, {})
              ).map(([tier, count]) => {
                const tc = TIER_CONFIG[tier] ?? TIER_CONFIG.LOW
                return (
                  <div key={tier} className="flex items-center justify-between py-2.5 border-b border-slate-50 last:border-none">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ background: tc.color }} />
                      <span className="text-[12px] text-gray-600 font-medium">{tier}</span>
                    </div>
                    <span className="text-[12px] font-bold text-gray-900">{count}</span>
                  </div>
                )
              })}
            </Card>
          </div>
        </div>
      )}

      {/* Feedback Modal */}
      <AnimatePresence>
        {feedback && (
          <FeedbackModal
            predId={feedback.predId}
            currentVerdict={feedback.verdict}
            onClose={() => setFeedback(null)}
            onSubmit={() => { setFeedback(null); fetchHistory() }}
          />
        )}
      </AnimatePresence>
    </PageWrapper>
  )
}
