import { motion } from 'framer-motion'
import { RiDownloadLine, RiCalendarLine, RiMoreLine } from 'react-icons/ri'
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  AreaChart, Area,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'
import {
  Card, Btn, StatCard, PageWrapper, PageHeader, FormSelect,
  SectionHeader, HorizBar,
} from '../components/ui'
import {
  RiAlertLine, RiShieldCheckLine, RiSpeedLine, RiCheckboxCircleLine,
} from 'react-icons/ri'

/* ── Data ── */
const dailyVolume = [
  { day: 'Mar 17', scans: 1540, threats: 198 },
  { day: 'Mar 18', scans: 1720, threats: 214 },
  { day: 'Mar 19', scans: 1480, threats: 187 },
  { day: 'Mar 20', scans: 1890, threats: 231 },
  { day: 'Mar 21', scans: 1650, threats: 205 },
  { day: 'Mar 22', scans: 1780, threats: 219 },
  { day: 'Mar 23', scans: 1842, threats: 247 },
]

const riskTiers = [
  { name: 'Safe',       value: 1595, color: '#34d399' },
  { name: 'Suspicious', value: 135,  color: '#fbbf24' },
  { name: 'High Risk',  value: 74,   color: '#fb923c' },
  { name: 'Critical',   value: 38,   color: '#f87171' },
]

const moduleAccuracy = [
  { module: 'Email',  acc: 93 },
  { module: 'Creds',  acc: 97 },
  { module: 'File',   acc: 88 },
  { module: 'Web',    acc: 96 },
  { module: 'Voice',  acc: 85 },
  { module: 'Prompt', acc: 94 },
  { module: 'Agent',  acc: 88 },
]

const credTypes = [
  { label: 'AWS / Cloud Keys',    count: 487 },
  { label: 'DB Passwords',        count: 341 },
  { label: 'GitHub / Git Tokens', count: 298 },
  { label: 'OAuth Tokens',        count: 187 },
  { label: 'PII (Email/Phone)',   count: 143 },
  { label: 'SSH / SSL Keys',      count: 92  },
]

const responseTimes = [
  { module: 'Email',   ms: 1.2 },
  { module: 'Creds',   ms: 0.4 },
  { module: 'File',    ms: 2.8 },
  { module: 'Web',     ms: 1.9 },
  { module: 'Voice',   ms: 2.1 },
  { module: 'Prompt',  ms: 0.8 },
  { module: 'Sandbox', ms: 12.4},
]

const fpRate = [
  { day: 'Mar 17', rate: 4.2 },
  { day: 'Mar 18', rate: 3.8 },
  { day: 'Mar 19', rate: 3.1 },
  { day: 'Mar 20', rate: 3.5 },
  { day: 'Mar 21', rate: 2.7 },
  { day: 'Mar 22', rate: 2.1 },
  { day: 'Mar 23', rate: 1.8 },
]

/* ── Shared tooltip style ── */
const tooltipStyle = {
  backgroundColor: '#fff',
  border: '1px solid #e2e8f0',
  borderRadius: '12px',
  fontSize: '12px',
  fontWeight: 600,
  color: '#475569',
  boxShadow: '0 4px 20px rgba(0,0,0,0.08)',
}

/* ── Chart card wrapper ── */
function ChartCard({ title, children, delay = 0, action }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.35 }}
      whileHover={{ y: -1, boxShadow: '0 4px 24px rgba(14,165,233,0.08)' }}
      className="bg-white rounded-2xl border border-slate-100 shadow-card p-5"
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-[13px] font-semibold text-slate-800">{title}</h3>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-400 bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1.5 cursor-pointer hover:bg-slate-100 transition-colors">
            <RiCalendarLine className="text-slate-400 text-xs" />
            <span>7 days</span>
          </div>
          <button className="w-7 h-7 rounded-lg border border-slate-200 bg-slate-50 flex items-center justify-center text-slate-400 hover:text-slate-600 transition-colors">
            {action || <RiDownloadLine className="text-sm" />}
          </button>
        </div>
      </div>
      {children}
    </motion.div>
  )
}

/* ── Custom pie label ── */
const renderPieLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }) => {
  const RADIAN = Math.PI / 180
  const radius = innerRadius + (outerRadius - innerRadius) * 0.55
  const x = cx + radius * Math.cos(-midAngle * RADIAN)
  const y = cy + radius * Math.sin(-midAngle * RADIAN)
  if (percent < 0.05) return null
  return (
    <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" fontSize={11} fontWeight={700}>
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  )
}

function barColor(acc) {
  if (acc >= 95) return '#0ea5e9'
  if (acc >= 90) return '#38bdf8'
  if (acc >= 85) return '#7dd3fc'
  return '#bae6fd'
}

function rtColor(ms) {
  if (ms > 5) return '#f87171'
  if (ms > 2) return '#fbbf24'
  return '#34d399'
}

export default function AdminAnalytics() {
  return (
    <PageWrapper>
      <PageHeader
        title="Admin Analytics"
        sub="Compliance reporting · Model performance · Operational metrics"
        right={
          <div className="flex items-center gap-2">
            <FormSelect className="w-36">
              <option>Last 7 Days</option>
              <option>Last 30 Days</option>
              <option>Last 90 Days</option>
            </FormSelect>
            <Btn variant="primary">
              <RiDownloadLine /> Export All
            </Btn>
          </div>
        }
      />

      {/* Summary stat row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard icon={RiShieldCheckLine}    value="12847"  label="Total Scans (7 days)"   change="12%"  changeDir="up"   delay={0.05} iconBg="bg-sky-50"     iconColor="text-sky-500"     />
        <StatCard icon={RiAlertLine}          value="1.8%"   label="Current FP Rate"         change="2.1%" changeDir="down" delay={0.10} iconBg="bg-emerald-50" iconColor="text-emerald-500" />
        <StatCard icon={RiSpeedLine}          value="1.4s"   label="Avg Scan Time"            change="0.3s" changeDir="down" delay={0.15} iconBg="bg-sky-50"     iconColor="text-sky-500"     />
        <StatCard icon={RiCheckboxCircleLine} value="94.2%"  label="Overall Accuracy"         change="0.8%" changeDir="up"  delay={0.20} iconBg="bg-emerald-50" iconColor="text-emerald-500" />
      </div>

      {/* Chart grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">

        {/* 1. Daily Detection Volume */}
        <ChartCard title="Daily Detection Volume" delay={0.05}>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={dailyVolume} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
              <defs>
                <linearGradient id="gScans" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.15}/>
                  <stop offset="95%" stopColor="#38bdf8" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="gThreats" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f87171" stopOpacity={0.12}/>
                  <stop offset="95%" stopColor="#f87171" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="day" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area type="monotone" dataKey="scans" stroke="#38bdf8" strokeWidth={2} fill="url(#gScans)" name="Scans" dot={false} activeDot={{ r: 4 }}/>
              <Area type="monotone" dataKey="threats" stroke="#f87171" strokeWidth={2} fill="url(#gThreats)" name="Threats" dot={false} activeDot={{ r: 4 }}/>
              <Legend wrapperStyle={{ fontSize: 11, color: '#64748b', paddingTop: 8 }} />
            </AreaChart>
          </ResponsiveContainer>
          <p className="text-[11px] text-slate-400 mt-2">↑ 18% increase today vs. 7-day average</p>
        </ChartCard>

        {/* 2. Risk Tier Distribution — donut */}
        <ChartCard title="Risk Tier Distribution" delay={0.10}>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie
                data={riskTiers}
                cx="50%" cy="50%"
                innerRadius={52} outerRadius={80}
                paddingAngle={2}
                dataKey="value"
                labelLine={false}
                label={renderPieLabel}
              >
                {riskTiers.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} formatter={(val, name) => [`${val.toLocaleString()} scans`, name]} />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-wrap justify-center gap-x-4 gap-y-1.5 mt-1">
            {riskTiers.map(({ name, color }) => (
              <div key={name} className="flex items-center gap-1.5 text-[11px] text-slate-500 font-medium">
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: color }} />
                {name}
              </div>
            ))}
          </div>
        </ChartCard>

        {/* 3. Module Accuracy — bar */}
        <ChartCard title="Module Accuracy Comparison" delay={0.15}>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={moduleAccuracy} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
              <XAxis dataKey="module" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
              <YAxis domain={[75, 100]} tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} formatter={(v) => [`${v}%`, 'Accuracy']} />
              <Bar dataKey="acc" name="Accuracy" radius={[6, 6, 0, 0]}>
                {moduleAccuracy.map((entry, i) => (
                  <Cell key={i} fill={barColor(entry.acc)} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* 4. Top Credential Types */}
        <ChartCard title="Top Credential Types Detected" delay={0.20}>
          <div className="space-y-0.5 mt-1">
            {credTypes.map(({ label, count }, i) => (
              <HorizBar key={label} label={label} count={count} max={487} delay={i * 0.07} />
            ))}
          </div>
        </ChartCard>

        {/* 5. Response Times */}
        <ChartCard title="Avg Response Time (seconds)" delay={0.25}>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart
              data={responseTimes}
              layout="vertical"
              margin={{ top: 4, right: 16, left: 20, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
              <YAxis dataKey="module" type="category" tick={{ fontSize: 10, fill: '#64748b' }} tickLine={false} axisLine={false} width={48} />
              <Tooltip contentStyle={tooltipStyle} formatter={(v) => [`${v}s`, 'Avg Time']} />
              <Bar dataKey="ms" name="Seconds" radius={[0, 6, 6, 0]}>
                {responseTimes.map((entry, i) => (
                  <Cell key={i} fill={rtColor(entry.ms)} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div className="flex items-center gap-4 mt-2">
            <div className="flex items-center gap-1.5 text-[11px] text-slate-500"><span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" /> Fast (&lt;2s)</div>
            <div className="flex items-center gap-1.5 text-[11px] text-slate-500"><span className="w-2 h-2 rounded-full bg-yellow-400 inline-block" /> Moderate</div>
            <div className="flex items-center gap-1.5 text-[11px] text-slate-500"><span className="w-2 h-2 rounded-full bg-red-400 inline-block" /> Slow (&gt;5s)</div>
          </div>
        </ChartCard>

        {/* 6. False Positive Rate */}
        <ChartCard title="False Positive Rate Over Time" delay={0.30}>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={fpRate} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="day" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
              <YAxis
                tick={{ fontSize: 10, fill: '#94a3b8' }}
                tickLine={false} axisLine={false}
                tickFormatter={(v) => `${v}%`}
              />
              <Tooltip contentStyle={tooltipStyle} formatter={(v) => [`${v}%`, 'FP Rate']} />
              <Line
                type="monotone" dataKey="rate" stroke="#0ea5e9" strokeWidth={2.5}
                dot={{ fill: '#0ea5e9', r: 3 }} activeDot={{ r: 5 }}
                name="FP Rate"
              />
            </LineChart>
          </ResponsiveContainer>
          <div className="flex items-center justify-between mt-3 p-3 bg-emerald-50 rounded-xl border border-emerald-100">
            <p className="text-[12px] text-emerald-700 font-semibold">
              ↓ FP rate down to 1.8% — retraining effective
            </p>
            <span className="text-[11px] font-bold text-emerald-600 bg-white px-2 py-0.5 rounded-full border border-emerald-200">
              -57%
            </span>
          </div>
        </ChartCard>

      </div>
    </PageWrapper>
  )
}
