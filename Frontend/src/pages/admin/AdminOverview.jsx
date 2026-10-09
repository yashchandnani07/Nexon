import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  RiShieldUserLine, RiMessage3Line, RiRobotLine, RiLineChartLine,
  RiAlertLine, RiCheckboxCircleLine, RiDatabaseLine, RiArrowRightLine,
  RiRefreshLine, RiPlayCircleLine, RiCheckDoubleLine, RiLoader4Line
} from 'react-icons/ri'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, RadarChart, Radar, PolarGrid, PolarAngleAxis,
} from 'recharts'
import { Card, StatCard, RiskBadge, PageWrapper, SectionHeader, Tag, ProgressBar } from '../../components/ui'

const trend7d = [
  { day: 'Mon', blocked: 42, allowed: 312 },
  { day: 'Tue', blocked: 58, allowed: 298 },
  { day: 'Wed', blocked: 34, allowed: 276 },
  { day: 'Thu', blocked: 71, allowed: 341 },
  { day: 'Fri', blocked: 63, allowed: 315 },
  { day: 'Sat', blocked: 49, allowed: 287 },
  { day: 'Sun', blocked: 84, allowed: 302 },
]

const modulePieData = [
  { name: 'DLP Guardian',      value: 401, color: '#0EA5E9' },
  { name: 'Prompt Injection',  value: 34,  color: '#38BDF8' },
  { name: 'Agent Sandbox',     value: 12,  color: '#7DD3FC' },
  { name: 'Model Analytics',   value: 8,   color: '#BAE6FD' },
]

const radarData = [
  { module: 'DLP',       score: 94 },
  { module: 'Prompt',    score: 89 },
  { module: 'Sandbox',   score: 96 },
  { module: 'Analytics', score: 98 },
  { module: 'Policy',    score: 91 },
]

const recentAlerts = [
  { user: 'priya.sharma@bank.in',   action: 'Account No. shared with ChatGPT', module: 'DLP',    level: 'high',     time: '3m'  },
  { user: 'rahul.verma@bank.in',    action: 'Jailbreak attempt via Claude',     module: 'Prompt', level: 'high',     time: '11m' },
  { user: 'neha.sinha@bank.in',     action: 'SWIFT code in Gemini prompt',      module: 'DLP',    level: 'high',     time: '28m' },
  { user: 'amit.kumar@bank.in',     action: 'Agent read /etc/passwd',           module: 'Sandbox',level: 'suspicious',time: '45m' },
  { user: 'deepa.iyer@bank.in',     action: 'Base64 injection intercepted',     module: 'Prompt', level: 'high',     time: '1h'  },
]

const models = [
  { name: 'BERT Email Classifier',   accuracy: 94, status: 'healthy', drift: 'low'    },
  { name: 'Wav2Vec2 Voice',          accuracy: 83, status: 'warning', drift: 'medium' },
  { name: 'DLP Regex Engine',        accuracy: 99, status: 'healthy', drift: 'none'   },
  { name: 'Prompt Injection BERT',   accuracy: 96, status: 'healthy', drift: 'low'    },
  { name: 'CNN Website Fingerprint', accuracy: 91, status: 'healthy', drift: 'low'    },
]

const statCards = [
  { icon: RiDatabaseLine,       value: '18,420', label: 'Total Requests Today',   change: '14%',  changeDir: 'up', iconBg: 'icon-box icon-box-blue'   },
  { icon: RiShieldUserLine,     value: '401',    label: 'DLP Blocks Today',       change: '23%',  changeDir: 'up', iconBg: 'icon-box icon-box-slate'   },
  { icon: RiMessage3Line,       value: '34',     label: 'Injection Attempts',     change: '5',    changeDir: 'up', iconBg: 'icon-box icon-box-amber'   },
  { icon: RiCheckboxCircleLine, value: '97.2%',  label: 'Overall Block Accuracy', change: '0.5%', changeDir: 'up', iconBg: 'icon-box icon-box-green'   },
]

const tooltipStyle = {
  backgroundColor: '#fff', border: '1px solid #E2E8F0', borderRadius: '12px',
  fontSize: '12px', fontWeight: 600, color: '#374151', boxShadow: '0 4px 20px rgba(0,0,0,0.08)',
}

function StatusDot({ status }) {
  return (
    <div className={`flex items-center gap-1.5 text-[11px] font-semibold ${
      status === 'healthy' ? 'text-emerald-600' : status === 'warning' ? 'text-amber-600' : 'text-orange-600'
    }`}>
      <span className={`w-2 h-2 rounded-full ${
        status === 'healthy' ? 'bg-emerald-400' : status === 'warning' ? 'bg-amber-400 animate-pulse' : 'bg-orange-400 animate-pulse'
      }`} />
      {status === 'healthy' ? 'Healthy' : status === 'warning' ? 'Monitor' : 'Alert'}
    </div>
  )
}

const RADIAN = Math.PI / 180
function PieLabel({ cx, cy, midAngle, innerRadius, outerRadius, percent }) {
  if (percent < 0.06) return null
  const r = innerRadius + (outerRadius - innerRadius) * 0.55
  return (
    <text x={cx + r * Math.cos(-midAngle * RADIAN)} y={cy + r * Math.sin(-midAngle * RADIAN)}
      fill="white" textAnchor="middle" dominantBaseline="central" fontSize={10} fontWeight={700}>
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  )
}

export default function AdminOverview() {
  const [retrainQueue, setRetrainQueue] = useState(0)
  const [retraining, setRetraining]     = useState(false)
  const [retrainLog, setRetrainLog]     = useState([])

  const fetchRetrainStatus = async () => {
    try {
      const res = await fetch('/api/voice-scan/admin/retrain/status')
      if (res.ok) {
        const data = await res.json()
        setRetrainQueue(data.queue_size || 0)
      }
    } catch (e) { console.error('Failed to fetch retrain status', e) }
  }

  useEffect(() => {
    fetchRetrainStatus()
  }, [])

  const triggerRetrain = async () => {
    if (retrainQueue === 0) return
    setRetraining(true)
    try {
      const res = await fetch('/api/voice-scan/admin/retrain', { method: 'POST' })
      const data = await res.json()
      setRetrainLog(data.log || [`Started retraining on ${data.queue_size} samples...`])
      fetchRetrainStatus()
    } catch (e) {
      setRetrainLog(['Error triggering retraining check connection.'])
    } finally {
      setTimeout(() => setRetraining(false), 2000)
    }
  }

  return (
    <PageWrapper>
      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {statCards.map((s, i) => <StatCard key={s.label} {...s} delay={i * 0.06} />)}
      </div>

      {/* Row 1: Area chart + Pie chart */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-5">
        <div className="lg:col-span-2">
          <Card>
            <div className="flex items-center justify-between mb-4">
              <SectionHeader title="Request Traffic — Allowed vs Blocked" />
              <div className="flex items-center gap-4 text-[11px] font-medium text-gray-400 -mt-4">
                <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-sky-400 inline-block rounded" /> Allowed</span>
                <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-amber-400 inline-block rounded" /> Blocked</span>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={trend7d} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
                <defs>
                  <linearGradient id="gA2" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#0EA5E9" stopOpacity={0.15}/>
                    <stop offset="95%" stopColor="#0EA5E9" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="gB2" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#FBBF24" stopOpacity={0.12}/>
                    <stop offset="95%" stopColor="#FBBF24" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" />
                <XAxis dataKey="day" tick={{ fontSize: 10, fill: '#9CA3AF' }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 10, fill: '#9CA3AF' }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="allowed" stroke="#0EA5E9" strokeWidth={2} fill="url(#gA2)" name="Allowed" dot={false} activeDot={{ r: 4 }} />
                <Area type="monotone" dataKey="blocked"  stroke="#FBBF24" strokeWidth={2} fill="url(#gB2)"  name="Blocked"  dot={false} activeDot={{ r: 4 }} />
              </AreaChart>
            </ResponsiveContainer>
          </Card>
        </div>

        {/* Pie chart — Blocks by Module */}
        <Card>
          <SectionHeader title="Blocks by Module" />
          <div className="flex flex-col items-center">
            <PieChart width={180} height={160}>
              <Pie data={modulePieData} cx={90} cy={75} innerRadius={46} outerRadius={72} paddingAngle={2} dataKey="value" labelLine={false} label={PieLabel}>
                {modulePieData.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
            </PieChart>
            <div className="w-full mt-2 space-y-1.5">
              {modulePieData.map(({ name, value, color }) => (
                <div key={name} className="flex items-center justify-between text-[11px]">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ background: color }} />
                    <span className="text-gray-600 font-medium">{name}</span>
                  </div>
                  <span className="font-semibold text-gray-900">{value}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>

      {/* Row 2: Alerts + Retraining */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-5">
        {/* Retraining Panel */}
        <div className="lg:col-span-1">
          <Card>
            <SectionHeader
              title="Voice Model Retraining"
              right={<button onClick={fetchRetrainStatus} className="text-[14px] text-sky-500 hover:text-sky-700 p-1"><RiRefreshLine /></button>}
            />
            <div className="flex flex-col items-center justify-center p-4 bg-sky-50 rounded-2xl border border-sky-100 mb-4">
              <div className="w-14 h-14 rounded-full bg-white flex items-center justify-center mb-3 shadow-sm text-sky-500 text-2xl">
                <RiDatabaseLine />
              </div>
              <p className="text-[28px] font-bold text-gray-900 leading-none">{retrainQueue}</p>
              <p className="text-[12px] text-gray-500 font-medium mt-1">Corrections in Queue</p>
            </div>
            
            <button
              onClick={triggerRetrain}
              disabled={retrainQueue === 0 || retraining}
              className={`w-full py-3 rounded-xl flex items-center justify-center gap-2 font-bold text-[13px] transition-all ${
                retrainQueue === 0
                  ? 'bg-slate-100 text-gray-400 cursor-not-allowed'
                  : retraining
                    ? 'bg-amber-100 text-amber-700'
                    : 'bg-sky-500 text-white hover:bg-sky-600 shadow-md shadow-sky-500/20'
              }`}
            >
              {retraining ? <><RiLoader4Line className="animate-spin text-lg" /> Retraining...</> : <><RiPlayCircleLine className="text-lg" /> Start Retraining</>}
            </button>

            {retrainLog.length > 0 && (
              <div className="mt-4 p-3 bg-gray-900 rounded-xl">
                <p className="text-[10px] font-mono text-sky-400 mb-1">Process Log:</p>
                {retrainLog.map((l, idx) => (
                  <p key={idx} className="text-[10px] text-gray-300 font-mono leading-relaxed truncate">{l}</p>
                ))}
              </div>
            )}
          </Card>
        </div>

        {/* Recent Alerts */}
        <div className="lg:col-span-2">
          <Card>
            <SectionHeader
              title="Recent Enterprise Alerts"
              right={<button className="text-[12px] text-sky-500 hover:text-sky-700 font-semibold flex items-center gap-1">View All <RiArrowRightLine /></button>}
            />
            {recentAlerts.map(({ user, action, module: mod, level, time }, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.06 }}
                className={`flex items-start gap-3 py-3 border-b border-slate-50 last:border-none pl-3 ${
                  level === 'high' ? 'alert-row-high' : 'alert-row-suspicious'
                }`}
              >
                <div className={`icon-box flex-shrink-0 ${level === 'high' ? 'icon-box-orange' : 'icon-box-amber'}`} style={{ width: 28, height: 28, borderRadius: 7 }}>
                  <RiAlertLine className="text-xs" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-[11px] font-semibold text-gray-500 truncate">{user}</p>
                  <p className="text-[12px] font-medium text-gray-800 truncate mt-0.5">{action}</p>
                </div>
                <div className="flex flex-col items-end gap-1 flex-shrink-0">
                  <Tag>{mod}</Tag>
                  <span className="text-[10px] text-gray-400">{time} ago</span>
                </div>
              </motion.div>
            ))}
          </Card>
        </div>
      </div>

      {/* Row 3: Radar Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <Card>
          <SectionHeader title="Module Performance" />
          <RadarChart width={220} height={160} data={radarData} cx={110} cy={80}>
            <PolarGrid stroke="#E2E8F0" />
            <PolarAngleAxis dataKey="module" tick={{ fontSize: 9, fill: '#9CA3AF' }} />
            <Radar name="Score" dataKey="score" stroke="#0EA5E9" fill="#0EA5E9" fillOpacity={0.12} />
            <Tooltip contentStyle={tooltipStyle} />
          </RadarChart>
          {/* Model table */}
          <div className="mt-2 space-y-2.5">
            {models.map((m, i) => (
              <motion.div key={m.name} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }}
                className="flex items-center gap-3">
                <div className="flex-1 min-w-0">
                  <p className="text-[11px] font-semibold text-gray-700 truncate">{m.name}</p>
                  <ProgressBar value={m.accuracy} delay={0.1 + i * 0.05} color="blue" />
                </div>
                <span className={`text-[11px] font-bold ${m.accuracy >= 90 ? 'text-emerald-600' : 'text-amber-600'}`}>{m.accuracy}%</span>
                <StatusDot status={m.status} />
              </motion.div>
            ))}
          </div>
        </Card>
      </div>
    </PageWrapper>
  )
}
