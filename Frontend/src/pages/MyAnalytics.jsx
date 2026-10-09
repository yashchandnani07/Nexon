import { motion } from 'framer-motion'
import {
  RiShieldCheckLine, RiAlertLine, RiCheckboxCircleLine, RiTimeLine,
  RiArrowRightLine, RiTrophyLine, RiCalendarLine, RiMoreLine,
} from 'react-icons/ri'
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Cell, PieChart, Pie,
} from 'recharts'
import {
  Card, StatCard, RiskBadge, ProgressBar, PageWrapper, PageHeader, SectionHeader, Tag,
} from '../components/ui'

/* ── Data ── */
const weeklyScans = [
  { day: 'Mon', scans: 18, threats: 2 },
  { day: 'Tue', scans: 24, threats: 5 },
  { day: 'Wed', scans: 31, threats: 1 },
  { day: 'Thu', scans: 19, threats: 3 },
  { day: 'Fri', scans: 27, threats: 4 },
  { day: 'Sat', scans: 8,  threats: 0 },
  { day: 'Sun', scans: 5,  threats: 0 },
]

const myRecentScans = [
  { subject: 'Invoice_Q1_2026.pdf',         module: 'Attachment', score: 72, level: 'high',       time: '10:42 AM' },
  { subject: 'ceo-urgent-wire.eml',          module: 'Email',      score: 89, level: 'critical',   time: '09:15 AM' },
  { subject: 'vendor-payroll-update.docx',   module: 'Attachment', score: 18, level: 'safe',       time: 'Yesterday' },
  { subject: 'GHUB_TOKEN=ghp_xxx in chat',  module: 'Credential', score: 76, level: 'high',       time: 'Mar 22'    },
  { subject: 'paypa1-secure.com/login',      module: 'Website',    score: 61, level: 'high',       time: 'Mar 21'    },
  { subject: 'Office newsletter March.pdf',   module: 'Attachment', score: 9,  level: 'safe',       time: 'Mar 20'    },
]

const moduleUsage = [
  { name: 'Email',      uses: 42, color: '#38bdf8' },
  { name: 'Attachment', uses: 31, color: '#34d399' },
  { name: 'Credential', uses: 18, color: '#a78bfa' },
  { name: 'Website',    uses: 15, color: '#fb923c' },
  { name: 'Voice',      uses: 9,  color: '#facc15' },
]

const achievements = [
  { icon: '🛡️', title: 'First Line of Defense',   desc: 'Blocked 10+ critical threats',   earned: true  },
  { icon: '⭐', title: 'Zero False Positive',       desc: 'No false alerts this week',      earned: false },
  { icon: '🏆', title: 'Perfect Score',             desc: '100% accuracy this month',       earned: false },
]

const tooltipStyle = {
  backgroundColor: '#fff',
  border: '1px solid #e2e8f0',
  borderRadius: '12px',
  fontSize: '12px',
  fontWeight: 600,
  color: '#475569',
  boxShadow: '0 4px 20px rgba(0,0,0,0.08)',
}

export default function MyAnalytics() {
  const totalScans = weeklyScans.reduce((a, b) => a + b.scans, 0)
  const totalThreats = weeklyScans.reduce((a, b) => a + b.threats, 0)

  return (
    <PageWrapper>
      <PageHeader
        title="My Analytics"
        sub="Your personal scan history, threat insights & activity overview"
        right={
          <div className="flex items-center gap-2 px-4 py-2 bg-sky-50 border border-sky-200 rounded-xl">
            <RiCalendarLine className="text-sky-500 text-sm" />
            <span className="text-[12px] font-semibold text-sky-700">Last 7 Days</span>
          </div>
        }
      />

      {/* Stat row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard icon={RiShieldCheckLine}    value={String(totalScans)}  label="Scans This Week"      change="12%"  changeDir="up"   delay={0.05} iconBg="bg-sky-50"     iconColor="text-sky-500"     />
        <StatCard icon={RiAlertLine}          value={String(totalThreats)} label="Threats Found"       change="2"    changeDir="up"   delay={0.10} iconBg="bg-red-50"     iconColor="text-red-500"     />
        <StatCard icon={RiCheckboxCircleLine} value="94.2%"  label="My Accuracy Rate"     change="0.8%" changeDir="up"   delay={0.15} iconBg="bg-emerald-50" iconColor="text-emerald-500" />
        <StatCard icon={RiTimeLine}           value="1.2s"   label="Avg Scan Time"         change="0.1s" changeDir="down" delay={0.20} iconBg="bg-sky-50"     iconColor="text-sky-500"     />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-5">
        {/* Scan Activity Chart */}
        <div className="lg:col-span-2">
          <Card>
            <SectionHeader
              title="Weekly Scan Activity"
              right={<button className="w-7 h-7 rounded-lg border border-slate-200 flex items-center justify-center text-slate-400 hover:text-slate-600"><RiMoreLine /></button>}
            />
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={weeklyScans} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
                <defs>
                  <linearGradient id="myScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.15}/>
                    <stop offset="95%" stopColor="#38bdf8" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="myThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f87171" stopOpacity={0.15}/>
                    <stop offset="95%" stopColor="#f87171" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis dataKey="day" tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="scans" stroke="#38bdf8" strokeWidth={2} fill="url(#myScans)" name="Scans" dot={false} activeDot={{ r: 4, fill: '#38bdf8' }} />
                <Area type="monotone" dataKey="threats" stroke="#f87171" strokeWidth={2} fill="url(#myThreats)" name="Threats Detected" dot={false} activeDot={{ r: 4, fill: '#f87171' }} />
              </AreaChart>
            </ResponsiveContainer>
            <div className="flex items-center gap-5 mt-3">
              <div className="flex items-center gap-1.5 text-[11px] text-slate-500 font-medium"><span className="w-3 h-0.5 bg-sky-400 inline-block rounded" /> Scans</div>
              <div className="flex items-center gap-1.5 text-[11px] text-slate-500 font-medium"><span className="w-3 h-0.5 bg-red-400 inline-block rounded" /> Threats</div>
            </div>
          </Card>
        </div>

        {/* Module Usage Donut */}
        <Card>
          <SectionHeader title="Module Usage" />
          <ResponsiveContainer width="100%" height={170}>
            <PieChart>
              <Pie
                data={moduleUsage}
                cx="50%" cy="50%"
                innerRadius={48} outerRadius={72}
                paddingAngle={2}
                dataKey="uses"
              >
                {moduleUsage.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} formatter={(v, n) => [`${v} scans`, n]} />
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-1.5 mt-1">
            {moduleUsage.slice(0, 4).map(({ name, uses, color }) => (
              <div key={name} className="flex items-center justify-between text-[11px]">
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: color }} />
                  <span className="text-slate-500 font-medium">{name}</span>
                </div>
                <span className="font-semibold text-slate-700">{uses}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Recent Scans Table */}
        <div className="lg:col-span-2">
          <Card hover={false} className="!p-0 overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
              <h3 className="text-[13px] font-semibold text-slate-800">Recent Scans</h3>
              <button className="text-[12px] font-semibold text-sky-500 hover:text-sky-700 flex items-center gap-1 transition-colors">
                View All <RiArrowRightLine />
              </button>
            </div>
            <table className="w-full">
              <thead>
                <tr>
                  <th className="tbl-th">Content</th>
                  <th className="tbl-th">Module</th>
                  <th className="tbl-th">Risk</th>
                  <th className="tbl-th">Time</th>
                </tr>
              </thead>
              <tbody>
                {myRecentScans.map((scan, i) => (
                  <motion.tr
                    key={i}
                    className="tbl-tr"
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.04 }}
                  >
                    <td className="tbl-td max-w-[200px]">
                      <p className="text-[12px] font-medium text-slate-700 truncate">{scan.subject}</p>
                    </td>
                    <td className="tbl-td"><Tag>{scan.module}</Tag></td>
                    <td className="tbl-td"><RiskBadge level={scan.level} /></td>
                    <td className="tbl-td text-[11px] text-slate-400">{scan.time}</td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </Card>
        </div>

        {/* Right: Accuracy breakdown + Achievements */}
        <div className="space-y-4">
          {/* Accuracy by module */}
          <Card>
            <SectionHeader title="Accuracy by Module" />
            <div className="space-y-3">
              {[
                { name: 'Credential', acc: 98 },
                { name: 'Email',      acc: 94 },
                { name: 'Website',    acc: 91 },
                { name: 'Attachment', acc: 87 },
                { name: 'Voice',      acc: 83 },
              ].map(({ name, acc }, i) => (
                <div key={name} className="flex items-center gap-3">
                  <span className="text-[11px] font-medium text-slate-500 w-20 flex-shrink-0">{name}</span>
                  <div className="flex-1">
                    <ProgressBar value={acc} delay={0.05 * i} />
                  </div>
                  <span className="text-[11px] font-bold text-slate-700 w-8 text-right">{acc}%</span>
                </div>
              ))}
            </div>
          </Card>

          {/* Achievements */}
          <Card>
            <SectionHeader
              title="Achievements"
              right={<RiTrophyLine className="text-amber-400 text-base" />}
            />
            <div className="grid grid-cols-3 gap-2">
              {achievements.map(({ icon, title, earned }, i) => (
                <motion.div
                  key={title}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: i * 0.06 }}
                  title={title}
                  className={`flex flex-col items-center p-2.5 rounded-xl border text-center cursor-default transition-colors ${
                    earned
                      ? 'bg-amber-50 border-amber-200'
                      : 'bg-slate-50 border-slate-200 opacity-40'
                  }`}
                >
                  <span className="text-xl mb-1">{icon}</span>
                  <p className="text-[9px] font-semibold text-slate-600 leading-tight">{title}</p>
                </motion.div>
              ))}
            </div>
            <p className="text-[11px] text-slate-400 mt-3 text-center">2 of 4 achievements earned</p>
          </Card>
        </div>
      </div>
    </PageWrapper>
  )
}
