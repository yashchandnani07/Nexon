import { motion } from 'framer-motion'
import {
  RiShieldCheckLine, RiAlertLine, RiSpeedLine, RiCheckboxCircleLine,
  RiMailUnreadLine, RiKeyLine, RiGlobalLine,
  RiMicLine, RiArrowRightLine, RiAttachment2,
} from 'react-icons/ri'
import {
  Card, StatCard, RiskBadge, ProgressBar, AlertStrip, PageWrapper, SectionHeader,
} from '../components/ui'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar,
  LineChart, Line,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Legend,
} from 'recharts'

/* ── Static Data ── */

const modules = [
  { name: 'Email Phishing',      acc: 93, icon: RiMailUnreadLine },
  { name: 'Credential Scanner',  acc: 97, icon: RiKeyLine        },
  { name: 'Attachment Analyzer', acc: 88, icon: RiAttachment2    },
  { name: 'Website Spoofing',    acc: 96, icon: RiGlobalLine     },
  { name: 'Deepfake Voice',      acc: 85, icon: RiMicLine        },
]

const feed = [
  { title: 'CEO Impersonation Email blocked',        detail: 'Score 89 · hr@target.com',    time: '2m',  level: 'critical'   },
  { title: 'AWS API key exposed in repo',             detail: 'Score 74 · devops/config.py', time: '8m',  level: 'high'       },
  { title: 'Phishing clone: paypa1-secure.com',       detail: 'Score 66 · Domain spoofing',  time: '22m', level: 'high'       },
  { title: 'Deepfake voice flagged — 91% confidence', detail: 'Score 55 · IVR channel',      time: '34m', level: 'suspicious' },
  { title: 'Malicious PDF attachment quarantined',    detail: 'Score 81 · finance@acme.com', time: '51m', level: 'high'       },
]

const areaData = [
  { day: 'Mon', scans: 1540, threats: 98  },
  { day: 'Tue', scans: 1720, threats: 114 },
  { day: 'Wed', scans: 1480, threats: 87  },
  { day: 'Thu', scans: 1890, threats: 131 },
  { day: 'Fri', scans: 1650, threats: 105 },
  { day: 'Sat', scans: 1780, threats: 119 },
  { day: 'Sun', scans: 1842, threats: 147 },
]

const pieData = [
  { name: 'Critical',   value: 38,   color: '#F87171' },
  { name: 'High Risk',  value: 74,   color: '#FB923C' },
  { name: 'Suspicious', value: 135,  color: '#FBBF24' },
  { name: 'Safe',       value: 1595, color: '#34D399' },
]

const barData = [
  { name: 'Email',      threats: 68, color: '#0EA5E9' },
  { name: 'Credential', threats: 42, color: '#38BDF8' },
  { name: 'Attachment', threats: 31, color: '#7DD3FC' },
  { name: 'Spoofing',   threats: 55, color: '#BAE6FD' },
  { name: 'Voice',      threats: 51, color: '#0284C7' },
]

const stackedData = [
  { day: 'Mon', critical: 12, high: 28, suspicious: 58 },
  { day: 'Tue', critical: 18, high: 34, suspicious: 62 },
  { day: 'Wed', critical: 8,  high: 22, suspicious: 57 },
  { day: 'Thu', critical: 22, high: 41, suspicious: 68 },
  { day: 'Fri', critical: 15, high: 31, suspicious: 59 },
  { day: 'Sat', critical: 19, high: 37, suspicious: 63 },
  { day: 'Sun', critical: 24, high: 45, suspicious: 78 },
]

const weekComparison = [
  { day: 'Mon', thisWeek: 98,  lastWeek: 72  },
  { day: 'Tue', thisWeek: 114, lastWeek: 88  },
  { day: 'Wed', thisWeek: 87,  lastWeek: 95  },
  { day: 'Thu', thisWeek: 131, lastWeek: 79  },
  { day: 'Fri', thisWeek: 105, lastWeek: 112 },
  { day: 'Sat', thisWeek: 119, lastWeek: 64  },
  { day: 'Sun', thisWeek: 147, lastWeek: 83  },
]

const radarData = [
  { subject: 'Accuracy', Email: 93, Credential: 97, Attachment: 88, Website: 96, Voice: 85 },
  { subject: 'Speed',    Email: 88, Credential: 92, Attachment: 78, Website: 94, Voice: 82 },
  { subject: 'Coverage', Email: 95, Credential: 89, Attachment: 85, Website: 92, Voice: 80 },
  { subject: 'Uptime',   Email: 99, Credential: 100, Attachment: 98, Website: 99, Voice: 97 },
  { subject: 'FP Rate',  Email: 91, Credential: 96, Attachment: 84, Website: 94, Voice: 79 },
]

const attackVectors = [
  { name: 'BEC / CEO Fraud',     count: 68, pct: 97 },
  { name: 'Phishing Links',      count: 57, pct: 81 },
  { name: 'Domain Spoofing',     count: 55, pct: 79 },
  { name: 'Credential Stuffing', count: 42, pct: 60 },
  { name: 'Malicious Files',     count: 31, pct: 44 },
  { name: 'Voice Deepfake',      count: 21, pct: 30 },
]

const fpTrend = [
  { day: 'Mon', rate: 4.2 },
  { day: 'Tue', rate: 3.8 },
  { day: 'Wed', rate: 5.1 },
  { day: 'Thu', rate: 3.2 },
  { day: 'Fri', rate: 2.9 },
  { day: 'Sat', rate: 3.6 },
  { day: 'Sun', rate: 2.4 },
]

const VECTOR_COLORS = ['#0EA5E9', '#38BDF8', '#7DD3FC', '#0284C7', '#0369A1', '#BAE6FD']

const tooltipStyle = {
  backgroundColor: '#fff',
  border: '1px solid #E2E8F0',
  borderRadius: '12px',
  fontSize: '12px',
  fontWeight: 600,
  color: '#374151',
  boxShadow: '0 4px 20px rgba(0,0,0,0.08)',
}

const RADIAN = Math.PI / 180
const renderCustomizedLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }) => {
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5
  const x = cx + radius * Math.cos(-midAngle * RADIAN)
  const y = cy + radius * Math.sin(-midAngle * RADIAN)
  if (percent < 0.05) return null
  return (
    <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" fontSize={10} fontWeight={700}>
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  )
}

export default function Dashboard() {
  return (
    <PageWrapper>
      {/* Alert strip */}
      <AlertStrip level="warning">
        <RiAlertLine className="text-base flex-shrink-0" />
        <span><strong>3 High-Risk Threats</strong> detected in the last hour — review recommended</span>
      </AlertStrip>

      {/* ── Stat cards ────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard icon={RiAlertLine}          value="247"   label="Threats Detected (24h)" change="18%"  changeDir="up"   delay={0.05} iconBg="icon-box icon-box-orange" />
        <StatCard icon={RiShieldCheckLine}    value="1842"  label="Scans Completed (24h)"  change="7%"   changeDir="up"   delay={0.10} iconBg="icon-box icon-box-blue"   />
        <StatCard icon={RiCheckboxCircleLine} value="94.2%" label="Detection Accuracy"      change="0.8%" changeDir="up"   delay={0.15} iconBg="icon-box icon-box-green"  />
        <StatCard icon={RiSpeedLine}          value="1.4s"  label="Avg Response Time"       change="0.2s" changeDir="down" delay={0.20} iconBg="icon-box icon-box-blue"   />
      </div>

      {/* ── Row 1: Area chart + Risk Donut ────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-5">
        <div className="lg:col-span-2">
          <Card>
            <div className="flex items-center justify-between mb-4">
              <SectionHeader title="Scan & Threat Volume" />
              <div className="flex items-center gap-4 text-[11px] font-medium text-gray-400 -mt-4">
                <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-sky-400 inline-block rounded" /> Scans</span>
                <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-amber-400 inline-block rounded" /> Threats</span>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={190}>
              <AreaChart data={areaData} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
                <defs>
                  <linearGradient id="gScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#0EA5E9" stopOpacity={0.18}/>
                    <stop offset="95%" stopColor="#0EA5E9" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="gThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#FBBF24" stopOpacity={0.15}/>
                    <stop offset="95%" stopColor="#FBBF24" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" />
                <XAxis dataKey="day" tick={{ fontSize: 10, fill: '#9CA3AF' }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 10, fill: '#9CA3AF' }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="scans"   stroke="#0EA5E9" strokeWidth={2} fill="url(#gScans)"   name="Scans"   dot={false} activeDot={{ r: 4, fill: '#0EA5E9' }} />
                <Area type="monotone" dataKey="threats" stroke="#FBBF24" strokeWidth={2} fill="url(#gThreats)" name="Threats" dot={false} activeDot={{ r: 4, fill: '#FBBF24' }} />
              </AreaChart>
            </ResponsiveContainer>
          </Card>
        </div>

        <Card>
          <SectionHeader title="Risk Distribution" />
          <div className="flex flex-col items-center">
            <PieChart width={180} height={170}>
              <Pie
                data={pieData}
                cx={90} cy={80}
                innerRadius={50} outerRadius={78}
                paddingAngle={2}
                dataKey="value"
                labelLine={false}
                label={renderCustomizedLabel}
              >
                {pieData.map((entry, index) => (
                  <Cell key={index} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} formatter={(v, n) => [v.toLocaleString(), n]} />
            </PieChart>
            <div className="w-full space-y-1.5 mt-1">
              {pieData.map(({ name, value, color }) => (
                <div key={name} className="flex items-center justify-between text-[11px]">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: color }} />
                    <span className="text-gray-600 font-medium">{name}</span>
                  </div>
                  <span className="font-semibold text-gray-900">{value.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>

      {/* ── Row 2: Stacked Bar + Grouped Bar ──────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
        {/* Stacked Bar — Threats by Severity */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <SectionHeader title="Threats by Severity (Daily)" />
            <div className="flex items-center gap-3 text-[10px] font-semibold text-gray-400 -mt-4">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-400 inline-block" /> Critical</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-orange-400 inline-block" /> High</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-amber-300 inline-block" /> Suspicious</span>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={stackedData} margin={{ top: 4, right: 4, left: -28, bottom: 0 }} barCategoryGap="25%">
              <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" vertical={false} />
              <XAxis dataKey="day" tick={{ fontSize: 10, fill: '#9CA3AF' }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#9CA3AF' }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#F0F9FF' }} />
              <Bar dataKey="critical"   name="Critical"   stackId="a" fill="#F87171" />
              <Bar dataKey="high"       name="High"       stackId="a" fill="#FB923C" />
              <Bar dataKey="suspicious" name="Suspicious" stackId="a" fill="#FCD34D" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* Grouped Bar — Week-over-Week */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <SectionHeader title="Week-over-Week Threats" />
            <div className="flex items-center gap-3 text-[10px] font-semibold text-gray-400 -mt-4">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-sky-500 inline-block" /> This Week</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-slate-300 inline-block" /> Last Week</span>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={weekComparison} margin={{ top: 4, right: 4, left: -28, bottom: 0 }} barCategoryGap="20%" barGap={2}>
              <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" vertical={false} />
              <XAxis dataKey="day" tick={{ fontSize: 10, fill: '#9CA3AF' }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#9CA3AF' }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#F0F9FF' }} />
              <Bar dataKey="thisWeek" name="This Week" fill="#0EA5E9" radius={[4, 4, 0, 0]} />
              <Bar dataKey="lastWeek" name="Last Week" fill="#CBD5E1" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* ── Row 3: Radar + Attack Vectors + FP Trend ──────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-5">
        {/* Radar — Module Health */}
        <Card>
          <SectionHeader title="Module Health Radar" />
          <ResponsiveContainer width="100%" height={220}>
            <RadarChart data={radarData} margin={{ top: 4, right: 16, left: 16, bottom: 4 }}>
              <PolarGrid stroke="#E2E8F0" />
              <PolarAngleAxis dataKey="subject" tick={{ fontSize: 9, fill: '#9CA3AF', fontWeight: 600 }} />
              <PolarRadiusAxis angle={90} domain={[60, 100]} tick={false} tickCount={3} axisLine={false} />
              <Radar name="Email"      dataKey="Email"      stroke="#0EA5E9" fill="#0EA5E9" fillOpacity={0.07} strokeWidth={1.5} dot={false} />
              <Radar name="Credential" dataKey="Credential" stroke="#34D399" fill="#34D399" fillOpacity={0.07} strokeWidth={1.5} dot={false} />
              <Radar name="Attachment" dataKey="Attachment" stroke="#FBBF24" fill="#FBBF24" fillOpacity={0.07} strokeWidth={1.5} dot={false} />
              <Radar name="Website"    dataKey="Website"    stroke="#A78BFA" fill="#A78BFA" fillOpacity={0.07} strokeWidth={1.5} dot={false} />
              <Radar name="Voice"      dataKey="Voice"      stroke="#FB923C" fill="#FB923C" fillOpacity={0.07} strokeWidth={1.5} dot={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Legend iconSize={6} wrapperStyle={{ fontSize: '10px', paddingTop: '6px' }} />
            </RadarChart>
          </ResponsiveContainer>
        </Card>

        {/* Horizontal — Top Attack Vectors */}
        <Card>
          <SectionHeader title="Top Attack Vectors" />
          <div className="space-y-3 pt-1">
            {attackVectors.map(({ name, count, pct }, i) => (
              <motion.div
                key={name}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <div className="flex justify-between text-[11px] font-medium mb-1">
                  <span className="text-gray-600">{name}</span>
                  <span className="text-gray-900 font-semibold">{count}</span>
                </div>
                <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
                  <motion.div
                    className="h-full rounded-full"
                    style={{ background: VECTOR_COLORS[i] }}
                    initial={{ width: 0 }}
                    animate={{ width: `${pct}%` }}
                    transition={{ duration: 0.9, delay: 0.05 * i, ease: [0.34, 1.2, 0.64, 1] }}
                  />
                </div>
              </motion.div>
            ))}
          </div>
        </Card>

        {/* Line — False Positive Rate Trend */}
        <Card>
          <SectionHeader title="False Positive Rate (%)" />
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={fpTrend} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" />
              <XAxis dataKey="day" tick={{ fontSize: 10, fill: '#9CA3AF' }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#9CA3AF' }} tickLine={false} axisLine={false} domain={[0, 8]} />
              <Tooltip contentStyle={tooltipStyle} formatter={(v) => [`${v}%`, 'FP Rate']} />
              <Line
                type="monotone"
                dataKey="rate"
                stroke="#34D399"
                strokeWidth={2.5}
                dot={{ r: 3.5, fill: '#34D399', strokeWidth: 0 }}
                activeDot={{ r: 5, fill: '#34D399' }}
                name="FP Rate"
              />
            </LineChart>
          </ResponsiveContainer>
          <div className="mt-3 flex items-center justify-between px-1">
            <span className="text-[10px] text-gray-400">Target: &lt;3%</span>
            <div className="flex items-center gap-1.5 text-[11px] font-semibold text-emerald-600">
              <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" />
              Improving ↓
            </div>
          </div>
        </Card>
      </div>

      {/* ── Row 4: Bar by Module + Live Feed ──────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Bar chart — Threats by Module + accuracy bars */}
        <Card>
          <SectionHeader
            title="Threats by Module"
            right={
              <span className="chip chip-safe">
                <span className="online-dot" style={{ width: '6px', height: '6px' }} />
                All Online
              </span>
            }
          />
          <ResponsiveContainer width="100%" height={185}>
            <BarChart data={barData} margin={{ top: 4, right: 4, left: -28, bottom: 0 }} barCategoryGap="30%">
              <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" vertical={false} />
              <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#9CA3AF' }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#9CA3AF' }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#F0F9FF' }} />
              <Bar dataKey="threats" name="Threats" radius={[6, 6, 0, 0]}>
                {barData.map((entry, index) => (
                  <Cell key={index} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div className="mt-4 pt-4 border-t border-slate-50 space-y-3">
            {modules.map(({ name, acc, icon: Icon }, i) => (
              <motion.div
                key={name}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
                className="flex items-center gap-3"
              >
                <div className="icon-box icon-box-blue flex-shrink-0" style={{ width: 28, height: 28, borderRadius: 8 }}>
                  <Icon className="text-xs" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-1">
                    <p className="text-[11px] font-semibold text-gray-700">{name}</p>
                    <span className="text-[11px] font-bold text-gray-900">{acc}%</span>
                  </div>
                  <ProgressBar value={acc} delay={0.1 + i * 0.05} color="blue" />
                </div>
              </motion.div>
            ))}
          </div>
        </Card>

        {/* Live Feed */}
        <Card>
          <SectionHeader
            title="Live Threat Feed"
            right={
              <div className="flex items-center gap-1.5 text-[11px] font-semibold">
                <span className="online-dot" />
                <span className="text-emerald-600">Live</span>
              </div>
            }
          />
          <div>
            {feed.map(({ title, detail, time, level }, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.07 }}
                className={`flex items-start gap-3 py-3 border-b border-slate-50 last:border-none group cursor-pointer pl-3 ${
                  level === 'critical'   ? 'alert-row-critical'   :
                  level === 'high'       ? 'alert-row-high'       :
                  level === 'suspicious' ? 'alert-row-suspicious' : ''
                }`}
              >
                <div className={`icon-box flex-shrink-0 ${
                  level === 'critical'   ? 'icon-box-red'    :
                  level === 'high'       ? 'icon-box-orange' :
                  level === 'suspicious' ? 'icon-box-amber'  : 'icon-box-green'
                }`} style={{ width: 32, height: 32, borderRadius: 8 }}>
                  <RiAlertLine className="text-sm" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-[13px] font-semibold text-gray-800 truncate group-hover:text-sky-600 transition-colors">{title}</p>
                  <p className="text-[11px] text-gray-400 mt-0.5">{detail}</p>
                </div>
                <div className="flex flex-col items-end gap-1 flex-shrink-0">
                  <RiskBadge level={level} />
                  <span className="text-[10px] text-gray-400">{time} ago</span>
                </div>
              </motion.div>
            ))}
          </div>
          <button className="mt-3 w-full text-center text-[12px] font-semibold text-sky-500 hover:text-sky-700 flex items-center justify-center gap-1 transition-colors py-1">
            View All Threats <RiArrowRightLine />
          </button>
        </Card>
      </div>
    </PageWrapper>
  )
}


