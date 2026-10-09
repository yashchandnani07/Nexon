import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiRobotFill, RiCheckDoubleLine, RiCloseCircleLine, RiTimeLine,
  RiDashboard2Line, RiPlayCircleLine, RiFlashlightLine, RiSearchLine,
  RiShieldFlashLine, RiAlarmWarningLine, RiArrowRightLine,
} from 'react-icons/ri'
import {
  Card, StatCard, RiskBadge, PageWrapper, SectionHeader, ProgressBar,
} from '../../components/ui'
import ExecutionTraceModal from '../../components/sandbox/ExecutionTraceModal'

// ── Initial test data ──────────────────────────────────────────────────────
const INITIAL_TESTS = [
  { agent: 'Auto-Dev V3',        dev: 'amit.k',       status: 'Failed', vulnerabilities: 3, isolation: 100, time: '10m ago' },
  { agent: 'Customer Support',   dev: 'priya.s',      status: 'Passed', vulnerabilities: 0, isolation: 100, time: '2h ago' },
  { agent: 'Data Analyzer',      dev: 'rahul.v',      status: 'Passed', vulnerabilities: 0, isolation: 100, time: '5h ago' },
  { agent: 'Code Reviewer Beta', dev: 'deepa.i',      status: 'Failed', vulnerabilities: 1, isolation: 85,  time: '1d ago' },
  { agent: 'Marketing Gen',      dev: 'system_auto',  status: 'Passed', vulnerabilities: 0, isolation: 100, time: '1d ago' },
]

// ── Scenario definitions ───────────────────────────────────────────────────
const AGENTS = [
  'Customer Support',
  'Data Analyzer',
  'Auto-Dev V3',
  'Code Reviewer Beta',
  'Marketing Gen',
]

const SCENARIOS = [
  { id: 'exfil',    label: 'Data Exfiltration',       icon: RiAlarmWarningLine, outcome: 'Failed', vulns: 2, iso: 100 },
  { id: 'rce',      label: 'Remote Code Execution',   icon: RiFlashlightLine,   outcome: 'Failed', vulns: 3, iso: 100 },
  { id: 'escalate', label: 'Privilege Escalation',    icon: RiShieldFlashLine,  outcome: 'Failed', vulns: 1, iso: 85  },
  { id: 'scope',    label: 'Scope Escape (Prompt)',   icon: RiSearchLine,       outcome: 'Passed', vulns: 0, iso: 100 },
  { id: 'network',  label: 'Network Egress Probe',    icon: RiPlayCircleLine,   outcome: 'Failed', vulns: 1, iso: 100 },
]

// ── Simulation steps streamed in the terminal ──────────────────────────────
const SIM_STEPS = {
  exfil: [
    '▶  Spinning up isolated container…',
    '✔  seccomp profile active (strict)',
    '▶  Injecting data-exfiltration payload…',
    '⚠  Agent accessed /var/data/customer_pii (anomalous)',
    '⚠  Outbound POST → 203.0.113.5:443 — intercepted',
    '✔  DLP gateway blocked exfiltration attempt',
    '🔴 TEST FAILED — 2 critical findings logged',
  ],
  rce: [
    '▶  Spinning up isolated container…',
    '✔  AppArmor profile enforced',
    '▶  Injecting RCE payload via crafted tool call…',
    '⚠  Subprocess spawned: /bin/bash -i',
    '✔  seccomp SIGSYS — syscall execve denied',
    '⚠  Memory injection attempted via mmap',
    '✔  Kernel hardening blocked mmap exec',
    '🔴 TEST FAILED — 3 critical findings logged',
  ],
  escalate: [
    '▶  Spinning up isolated container…',
    '✔  Capabilities dropped (no CAP_SYS_ADMIN)',
    '▶  Injecting privilege-escalation payload…',
    '⚠  SUID binary execution attempt → EPERM',
    '✔  AppArmor denied /proc/*/mem write',
    '🔴 TEST FAILED — 1 critical finding logged',
  ],
  scope: [
    '▶  Spinning up isolated container…',
    '✔  Prompt injection probe set loaded (42 samples)',
    '▶  Running adversarial prompt battery…',
    '✔  Agent refused all 42 jailbreak variants',
    '✔  System prompt integrity preserved',
    '🟢 TEST PASSED — 0 findings',
  ],
  network: [
    '▶  Spinning up isolated container…',
    '✔  Network namespace isolated',
    '▶  Running egress probe (50 destinations)…',
    '⚠  DNS query to external resolver — blocked',
    '⚠  Outbound TCP probe → 8.8.8.8:80 — refused',
    '✔  Egress firewall rules enforced correctly',
    '🔴 TEST FAILED — 1 finding logged',
  ],
}

// ── Vulnerability breakdown data ───────────────────────────────────────────
const VULN_BREAKDOWN = [
  { name: 'Unrestricted File Read', count: 42, pct: 68 },
  { name: 'Network Exfiltration',   count: 15, pct: 24 },
  { name: 'Subprocess Spawning',    count: 12, pct: 19 },
  { name: 'Privilege Escalation',   count: 2,  pct: 3  },
]

// ── Helpers ────────────────────────────────────────────────────────────────
function timeLabel() {
  return 'just now'
}

// ═══════════════════════════════════════════════════════════════════════════
export default function SandboxMonitor() {
  const [tests,        setTests]        = useState(INITIAL_TESTS)
  const [selectedTest, setSelectedTest] = useState(null)
  const [simAgent,     setSimAgent]     = useState(AGENTS[0])
  const [simScenario,  setSimScenario]  = useState(SCENARIOS[0])
  const [simRunning,   setSimRunning]   = useState(false)
  const [simLines,     setSimLines]     = useState([])
  const [simDone,      setSimDone]      = useState(false)

  // derive stats
  const total  = tests.length
  const passed = tests.filter(t => t.status === 'Passed').length
  const failed = tests.filter(t => t.status === 'Failed').length

  // ── run simulation ───────────────────────────────────────────────────────
  function handleRunSimulation() {
    setSimRunning(true)
    setSimDone(false)
    setSimLines([])

    const steps  = SIM_STEPS[simScenario.id] ?? SIM_STEPS.scope
    let   stepIdx = 0

    const interval = setInterval(() => {
      if (stepIdx < steps.length) {
        setSimLines(prev => [...prev, steps[stepIdx]])
        stepIdx++
      } else {
        clearInterval(interval)
        setSimRunning(false)
        setSimDone(true)

        // Prepend a new row to the table
        const newTest = {
          agent:           simAgent,
          dev:             'admin_sim',
          status:          simScenario.outcome,
          vulnerabilities: simScenario.vulns,
          isolation:       simScenario.iso,
          time:            timeLabel(),
          _highlight:      true,
        }
        setTests(prev => [newTest, ...prev])
      }
    }, 520)
  }

  return (
    <PageWrapper>
      {/* Page heading */}
      <div className="mb-6">
        <h1 className="text-[22px] font-bold text-gray-900">Agent Sandbox Monitor</h1>
        <p className="text-[13px] text-slate-500 mt-1">
          Enterprise-wide oversight of AI Agent vulnerability testing, Docker container isolation, and system-call monitoring.
        </p>
      </div>

      {/* ── Stats ───────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard icon={RiRobotFill}       value={total + 337}  label="Total Agents Tested"  change="12"  changeDir="up"   iconBg="bg-sky-50 p-2.5 rounded-xl text-sky-500"     />
        <StatCard icon={RiCheckDoubleLine} value={passed + 278} label="Passed Validation"    change="8"   changeDir="up"   iconBg="bg-emerald-50 p-2.5 rounded-xl text-emerald-500" />
        <StatCard icon={RiCloseCircleLine} value={failed + 59}  label="Failed (Vulnerable)"  change="2"  changeDir="down" iconBg="bg-red-50 p-2.5 rounded-xl text-red-500"      />
        <StatCard icon={RiDashboard2Line}  value="100%"         label="Isolation Activeness" change="0%"  changeDir="up"   iconBg="bg-indigo-50 p-2.5 rounded-xl text-indigo-500"  />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

        {/* ── Left: Executions table + Simulation runner ─────────────────── */}
        <div className="lg:col-span-2 space-y-5">

          {/* Recent executions */}
          <Card>
            <SectionHeader title="Recent Sandbox Executions" right={
              <span className="text-[11px] text-slate-400 font-mono">Click a row for full trace</span>
            } />
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-100">
                  <th className="tbl-th">Agent Name</th>
                  <th className="tbl-th">Developer</th>
                  <th className="tbl-th">Status</th>
                  <th className="tbl-th">Vulns</th>
                  <th className="tbl-th">Isolation</th>
                  <th className="tbl-th">Time</th>
                  <th className="tbl-th"></th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence>
                  {tests.map((test, i) => (
                    <motion.tr
                      key={`${test.agent}-${i}`}
                      layout
                      initial={{ opacity: 0, y: -8, backgroundColor: test._highlight ? '#eff6ff' : '#ffffff' }}
                      animate={{ opacity: 1, y: 0, backgroundColor: '#ffffff' }}
                      transition={{ delay: test._highlight ? 0 : i * 0.05, duration: 0.3 }}
                      className="border-b border-slate-50 last:border-none hover:bg-slate-50 cursor-pointer group"
                      onClick={() => setSelectedTest(test)}
                    >
                      <td className="p-3 text-[12px] font-bold text-slate-700">{test.agent}</td>
                      <td className="p-3 text-[11px] font-mono text-slate-400">{test.dev}</td>
                      <td className="p-3">
                        <RiskBadge level={test.status === 'Passed' ? 'safe' : 'critical'}>
                          {test.status}
                        </RiskBadge>
                      </td>
                      <td className="p-3">
                        <span className={`text-[12px] font-bold ${test.vulnerabilities > 0 ? 'text-red-500' : 'text-emerald-600'}`}>
                          {test.vulnerabilities}
                        </span>
                      </td>
                      <td className="p-3">
                        <div className="w-24">
                          <ProgressBar value={test.isolation} color={test.isolation === 100 ? 'green' : 'yellow'} />
                        </div>
                      </td>
                      <td className="p-3 text-[11px] text-slate-400">{test.time}</td>
                      <td className="p-3">
                        <span className="text-[11px] text-sky-500 font-medium opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-0.5 whitespace-nowrap">
                          View trace <RiArrowRightLine />
                        </span>
                      </td>
                    </motion.tr>
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          </Card>

          {/* ── Threat Simulation Runner ─────────────────────────────────── */}
          <Card>
            <SectionHeader title="Threat Simulation Runner" right={
              <span className="chip chip-info">Interactive</span>
            } />

            <div className="grid grid-cols-2 gap-4 mb-4">
              {/* Agent selector */}
              <div>
                <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                  Target Agent
                </label>
                <select
                  value={simAgent}
                  onChange={e => setSimAgent(e.target.value)}
                  disabled={simRunning}
                  className="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 text-[12px] font-semibold text-gray-700 outline-none focus:border-sky-400 cursor-pointer transition-all disabled:opacity-50"
                >
                  {AGENTS.map(a => <option key={a} value={a}>{a}</option>)}
                </select>
              </div>

              {/* Scenario selector */}
              <div>
                <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                  Attack Scenario
                </label>
                <select
                  value={simScenario.id}
                  onChange={e => setSimScenario(SCENARIOS.find(s => s.id === e.target.value))}
                  disabled={simRunning}
                  className="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 text-[12px] font-semibold text-gray-700 outline-none focus:border-sky-400 cursor-pointer transition-all disabled:opacity-50"
                >
                  {SCENARIOS.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
                </select>
              </div>
            </div>

            {/* Scenario badge */}
            <div className="flex items-center gap-2 mb-4 p-3 bg-slate-50 rounded-xl border border-slate-100">
              {(() => { const Icon = simScenario.icon; return <Icon className="text-sky-500 text-lg flex-shrink-0" /> })()}
              <div>
                <p className="text-[12px] font-semibold text-slate-700">{simScenario.label}</p>
                <p className="text-[11px] text-slate-400">
                  Expected: {simScenario.outcome === 'Passed' ? '✅ Pass' : '🔴 Fail'} · {simScenario.vulns} finding(s)
                </p>
              </div>
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.97 }}
                onClick={handleRunSimulation}
                disabled={simRunning}
                className="ml-auto inline-flex items-center gap-2 px-4 py-2 rounded-lg text-[12px] font-bold bg-sky-500 text-white hover:bg-sky-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {simRunning ? (
                  <>
                    <motion.span animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 0.8, ease: 'linear' }} className="block w-3 h-3 border-2 border-white border-t-transparent rounded-full" />
                    Running…
                  </>
                ) : (
                  <><RiPlayCircleLine /> Run Simulation</>
                )}
              </motion.button>
            </div>

            {/* Terminal output */}
            <AnimatePresence>
              {(simLines.length > 0 || simRunning) && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="bg-slate-900 rounded-xl overflow-hidden"
                >
                  <div className="flex items-center gap-1.5 px-4 py-2 border-b border-slate-700">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-400" />
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
                    <span className="ml-2 text-[10px] font-mono text-slate-500">sandbox-terminal</span>
                  </div>
                  <div className="p-4 font-mono text-[11px] space-y-1 min-h-[100px]">
                    <AnimatePresence>
                      {simLines.map((line, idx) => (
                        <motion.p
                          key={idx}
                          initial={{ opacity: 0, x: -4 }}
                          animate={{ opacity: 1, x: 0 }}
                          className={
                            line.startsWith('🔴') ? 'text-red-400' :
                            line.startsWith('🟢') ? 'text-emerald-400' :
                            line.startsWith('⚠')  ? 'text-amber-400' :
                            line.startsWith('✔')  ? 'text-emerald-300' :
                            'text-slate-400'
                          }
                        >
                          {line}
                        </motion.p>
                      ))}
                    </AnimatePresence>
                    {simRunning && (
                      <motion.p
                        animate={{ opacity: [1, 0.3, 1] }}
                        transition={{ repeat: Infinity, duration: 0.9 }}
                        className="text-sky-400"
                      >
                        ▌
                      </motion.p>
                    )}
                    {simDone && (
                      <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-slate-500 mt-1">
                        — simulation complete —
                      </motion.p>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </Card>
        </div>

        {/* ── Right sidebar ──────────────────────────────────────────────── */}
        <div className="space-y-5">

          {/* Vulnerability breakdown */}
          <Card>
            <SectionHeader title="Most Common Vulnerabilities" />
            <div className="space-y-3 pt-1">
              {VULN_BREAKDOWN.map(v => (
                <div key={v.name} className="flex flex-col gap-1.5">
                  <div className="flex justify-between items-center text-[11px]">
                    <span className="font-semibold text-slate-600">{v.name}</span>
                    <span className="font-bold text-red-500">{v.count} incidents</span>
                  </div>
                  <ProgressBar value={v.pct} color="red" />
                </div>
              ))}
            </div>
          </Card>

          {/* Live container status */}
          <Card className="bg-slate-900 border-none">
            <div className="flex items-center gap-2 mb-4">
              <RiPlayCircleLine className="text-emerald-400 text-xl" />
              <h3 className="text-white font-semibold text-[13px]">Live Container Status</h3>
              <span className="ml-auto w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            </div>
            <div className="space-y-3">
              {[
                { label: 'Active Test Containers', value: '4 running',      color: 'text-emerald-400' },
                { label: 'seccomp filters',         value: 'Strict mode',    color: 'text-white' },
                { label: 'AppArmor profiles',       value: 'Enforced',       color: 'text-white' },
                { label: 'Network namespaces',      value: 'Isolated',       color: 'text-white' },
                { label: 'Kernel version',          value: 'Linux 6.5.0',    color: 'text-slate-400' },
              ].map(row => (
                <div key={row.label} className="flex justify-between text-[11px] border-b border-slate-800 pb-2 last:border-none last:pb-0">
                  <span className="text-slate-400">{row.label}</span>
                  <span className={`font-semibold ${row.color}`}>{row.value}</span>
                </div>
              ))}
            </div>
          </Card>

          {/* Quick actions */}
          <Card>
            <SectionHeader title="Quick Actions" />
            <div className="space-y-2">
              {[
                { label: 'Export All Results',   icon: '📋', color: 'bg-slate-50 hover:bg-slate-100 text-slate-700' },
                { label: 'Schedule Full Scan',   icon: '🗓',  color: 'bg-sky-50 hover:bg-sky-100 text-sky-700' },
                { label: 'View Audit Log',       icon: '📜', color: 'bg-slate-50 hover:bg-slate-100 text-slate-700' },
              ].map(a => (
                <button key={a.label} className={`w-full flex items-center gap-3 rounded-xl px-3.5 py-2.5 text-[12px] font-semibold transition-colors ${a.color}`}>
                  <span>{a.icon}</span> {a.label}
                </button>
              ))}
            </div>
          </Card>

        </div>
      </div>

      {/* ── Execution Trace Modal ──────────────────────────────────────── */}
      <ExecutionTraceModal test={selectedTest} onClose={() => setSelectedTest(null)} />
    </PageWrapper>
  )
}
