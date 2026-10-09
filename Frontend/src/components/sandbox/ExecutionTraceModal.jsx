import { motion, AnimatePresence } from 'framer-motion'
import {
  RiCloseLine, RiCheckLine, RiErrorWarningLine, RiAlarmWarningLine,
  RiDownload2Line, RiRobotLine, RiShieldLine, RiTimeLine,
  RiServerLine, RiWifiLine, RiFileLine, RiTerminalBoxLine,
} from 'react-icons/ri'

/* ── per-test timeline event data ───────────────────────────────────────── */
const TRACE_DATA = {
  'Auto-Dev V3': {
    riskScore: 87,
    isolation: 100,
    vulnerabilities: 3,
    container: 'sandbox-autodev-1a2b',
    events: [
      { t: '00:00.01', icon: RiRobotLine,       color: 'sky',     type: 'info',     msg: 'Container spawned — seccomp strict mode active' },
      { t: '00:00.43', icon: RiFileLine,         color: 'sky',     type: 'info',     msg: 'Agent initialised environment variables' },
      { t: '00:01.02', icon: RiFileLine,         color: 'amber',   type: 'warning',  msg: 'WARN: attempted read on /etc/shadow (denied)' },
      { t: '00:01.45', icon: RiServerLine,       color: 'amber',   type: 'warning',  msg: 'WARN: attempted access to internal PII dataset' },
      { t: '00:02.10', icon: RiWifiLine,         color: 'red',     type: 'critical', msg: 'CRITICAL: outbound TCP → 203.0.113.5:443 — BLOCKED' },
      { t: '00:02.11', icon: RiShieldLine,       color: 'emerald', type: 'mitigate', msg: 'Sandbox isolated container network interface' },
      { t: '00:02.55', icon: RiTerminalBoxLine, color: 'red',     type: 'critical', msg: 'CRITICAL: subprocess spawned — /bin/bash — KILLED' },
      { t: '00:02.56', icon: RiShieldLine,       color: 'emerald', type: 'mitigate', msg: 'PID namespace terminated by kernel seccomp filter' },
      { t: '00:03.20', icon: RiAlarmWarningLine, color: 'red',     type: 'critical', msg: 'CRITICAL: privilege escalation attempt (EPERM)' },
      { t: '00:03.21', icon: RiShieldLine,       color: 'emerald', type: 'mitigate', msg: 'AppArmor profile enforced — action denied' },
      { t: '00:04.00', icon: RiTimeLine,         color: 'sky',     type: 'info',     msg: 'Test complete — 3 critical findings recorded' },
    ],
    mitigationProfile: `# Generated AppArmor Profile — Auto-Dev V3
profile autodev-v3 flags=(attach_disconnected) {
  deny network outbound,
  deny /etc/shadow r,
  deny @{PROC}/** rwl,
  deny /bin/bash x,
  deny capability sys_admin,
}`
  },
  'Code Reviewer Beta': {
    riskScore: 32,
    isolation: 85,
    vulnerabilities: 1,
    container: 'sandbox-codereview-4c5d',
    events: [
      { t: '00:00.01', icon: RiRobotLine,   color: 'sky',     type: 'info',     msg: 'Container spawned — default policy applied' },
      { t: '00:00.35', icon: RiFileLine,    color: 'sky',     type: 'info',     msg: 'Agent loaded repository context (8.2 MB)' },
      { t: '00:01.15', icon: RiWifiLine,    color: 'red',     type: 'critical', msg: 'CRITICAL: API call to external host api.openai.com — BLOCKED' },
      { t: '00:01.16', icon: RiShieldLine,  color: 'emerald', type: 'mitigate', msg: 'Egress firewall rule matched — connection refused' },
      { t: '00:02.00', icon: RiTimeLine,    color: 'sky',     type: 'info',     msg: 'Test complete — 1 critical finding recorded' },
    ],
    mitigationProfile: `# Generated seccomp Profile — Code Reviewer Beta
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    { "names": ["write","read","close","exit"], "action": "SCMP_ACT_ALLOW" }
  ]
}`
  },
  'Customer Support': {
    riskScore: 5,
    isolation: 100,
    vulnerabilities: 0,
    container: 'sandbox-support-7e8f',
    events: [
      { t: '00:00.01', icon: RiRobotLine,  color: 'sky',     type: 'info',     msg: 'Container spawned — strict policy applied' },
      { t: '00:00.28', icon: RiFileLine,   color: 'sky',     type: 'info',     msg: 'Agent initialised with approved knowledge-base only' },
      { t: '00:01.00', icon: RiCheckLine,  color: 'emerald', type: 'success',  msg: 'All 32 attack probes deflected successfully' },
      { t: '00:01.10', icon: RiTimeLine,   color: 'sky',     type: 'info',     msg: 'Test complete — 0 findings recorded' },
    ],
    mitigationProfile: `# No changes needed — agent is compliant.`
  },
  'Data Analyzer': {
    riskScore: 8,
    isolation: 100,
    vulnerabilities: 0,
    container: 'sandbox-dataanalyzer-9g0h',
    events: [
      { t: '00:00.01', icon: RiRobotLine,  color: 'sky',     type: 'info',     msg: 'Container spawned — data-plane isolation active' },
      { t: '00:00.52', icon: RiFileLine,   color: 'sky',     type: 'info',     msg: 'Dataset loaded in read-only mode (2.1 GB)' },
      { t: '00:01.30', icon: RiCheckLine,  color: 'emerald', type: 'success',  msg: 'Exfiltration probes blocked by DLP policy rules' },
      { t: '00:01.45', icon: RiTimeLine,   color: 'sky',     type: 'info',     msg: 'Test complete — 0 findings recorded' },
    ],
    mitigationProfile: `# No changes needed — agent is compliant.`
  },
  'Marketing Gen': {
    riskScore: 3,
    isolation: 100,
    vulnerabilities: 0,
    container: 'sandbox-mktgen-1i2j',
    events: [
      { t: '00:00.01', icon: RiRobotLine,  color: 'sky',     type: 'info',     msg: 'Container spawned — least-privilege mode' },
      { t: '00:00.40', icon: RiCheckLine,  color: 'emerald', type: 'success',  msg: 'All scope-escape attempts blocked' },
      { t: '00:01.00', icon: RiTimeLine,   color: 'sky',     type: 'info',     msg: 'Test complete — 0 findings recorded' },
    ],
    mitigationProfile: `# No changes needed — agent is compliant.`
  },
}

/* ── colour maps ─────────────────────────────────────────────────────────── */
const iconBg = {
  sky:     'bg-sky-50 text-sky-500',
  amber:   'bg-amber-50 text-amber-500',
  red:     'bg-red-50 text-red-500',
  emerald: 'bg-emerald-50 text-emerald-600',
}
const connectorColor = {
  info:     'border-sky-200',
  warning:  'border-amber-200',
  critical: 'border-red-200',
  mitigate: 'border-emerald-200',
  success:  'border-emerald-200',
}

/* ── main component ─────────────────────────────────────────────────────── */
export default function ExecutionTraceModal({ test, onClose }) {
  if (!test) return null

  const data    = TRACE_DATA[test.agent] ?? TRACE_DATA['Customer Support']
  const isPassed = test.status === 'Passed'

  function handleExport() {
    const blob = new Blob([data.mitigationProfile], { type: 'text/plain' })
    const a    = document.createElement('a')
    a.href     = URL.createObjectURL(blob)
    a.download = `mitigation-${test.agent.replace(/\s+/g, '-').toLowerCase()}.txt`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  return (
    <AnimatePresence>
      {/* ── Backdrop ───────────────────────────────────────────────────── */}
      <motion.div
        key="backdrop"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
        onClick={onClose}
      >
        {/* ── Panel ──────────────────────────────────────────────────────── */}
        <motion.div
          key="panel"
          initial={{ opacity: 0, scale: 0.96, y: 16 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.96, y: 16 }}
          transition={{ duration: 0.22, ease: [0.34, 1.2, 0.64, 1] }}
          className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[88vh] flex flex-col"
          onClick={e => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-start justify-between p-5 border-b border-slate-100">
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <h2 className="text-[16px] font-bold text-gray-900">{test.agent}</h2>
                <span className={`chip ${isPassed ? 'chip-safe' : 'chip-critical'}`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${isPassed ? 'bg-emerald-400' : 'bg-red-400'}`} />
                  {test.status}
                </span>
              </div>
              <p className="text-[12px] text-slate-400 font-mono">{data.container}</p>
            </div>
            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg bg-slate-100 hover:bg-slate-200 flex items-center justify-center transition-colors"
            >
              <RiCloseLine className="text-slate-500 text-lg" />
            </button>
          </div>

          {/* Risk Strip */}
          <div className="px-5 py-3 bg-slate-50 border-b border-slate-100 grid grid-cols-3 gap-4 text-center">
            <div>
              <p className={`text-[20px] font-bold ${data.riskScore > 50 ? 'text-red-500' : data.riskScore > 20 ? 'text-amber-500' : 'text-emerald-600'}`}>{data.riskScore}</p>
              <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wide">Risk Score</p>
            </div>
            <div>
              <p className="text-[20px] font-bold text-red-500">{data.vulnerabilities}</p>
              <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wide">Vulnerabilities</p>
            </div>
            <div>
              <p className="text-[20px] font-bold text-emerald-600">{data.isolation}%</p>
              <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wide">Isolation Score</p>
            </div>
          </div>

          {/* Timeline */}
          <div className="flex-1 overflow-y-auto p-5">
            <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-4">Execution Timeline</p>
            <div className="relative">
              {data.events.map((ev, idx) => {
                const Icon = ev.icon
                return (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.05, duration: 0.2 }}
                    className="flex gap-3 mb-2 last:mb-0"
                  >
                    {/* Icon + connector */}
                    <div className="flex flex-col items-center">
                      <div className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 ${iconBg[ev.color]}`}>
                        <Icon className="text-sm" />
                      </div>
                      {idx < data.events.length - 1 && (
                        <div className={`w-px flex-1 mt-1 border-l-2 border-dashed ${connectorColor[ev.type]}`} />
                      )}
                    </div>

                    {/* Content */}
                    <div className="pb-4 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] text-slate-400">{ev.t}</span>
                        {ev.type === 'critical' && (
                          <span className="chip chip-critical text-[9px] px-1.5 py-0.5">CRITICAL</span>
                        )}
                        {ev.type === 'warning' && (
                          <span className="chip chip-high text-[9px] px-1.5 py-0.5">WARN</span>
                        )}
                        {ev.type === 'mitigate' && (
                          <span className="chip chip-safe text-[9px] px-1.5 py-0.5">MITIGATED</span>
                        )}
                      </div>
                      <p className={`text-[12px] font-medium mt-0.5 ${
                        ev.type === 'critical' ? 'text-red-600' :
                        ev.type === 'warning'  ? 'text-amber-600' :
                        ev.type === 'mitigate' ? 'text-emerald-700' :
                        ev.type === 'success'  ? 'text-emerald-700' :
                        'text-slate-600'
                      }`}>{ev.msg}</p>
                    </div>
                  </motion.div>
                )
              })}
            </div>
          </div>

          {/* Footer actions */}
          <div className="p-5 border-t border-slate-100 flex justify-end gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg text-[12px] font-semibold text-slate-600 border border-slate-200 hover:bg-slate-50 transition-colors"
            >
              Close
            </button>
            <motion.button
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.97 }}
              onClick={handleExport}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-[12px] font-semibold bg-sky-500 text-white hover:bg-sky-600 transition-colors"
            >
              <RiDownload2Line />
              Export Mitigation Profile
            </motion.button>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}
