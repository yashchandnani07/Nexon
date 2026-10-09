import { motion } from 'framer-motion'
import { useCountUp } from '../../hooks/useCountUp'
import { RiArrowUpLine, RiArrowDownLine } from 'react-icons/ri'

/* ──────────────────────────────────────────────
   Card
────────────────────────────────────────────── */
export function Card({ children, className = '', hover = true, ...props }) {
  return (
    <motion.div
      whileHover={hover ? { y: -1, boxShadow: '0 4px 24px rgba(14,165,233,0.10)' } : {}}
      transition={{ duration: 0.18 }}
      className={`bg-white rounded-xl border border-slate-100 shadow-[0_1px_3px_rgba(0,0,0,0.06),0_1px_2px_rgba(0,0,0,0.04)] p-5 ${className}`}
      {...props}
    >
      {children}
    </motion.div>
  )
}

/* ──────────────────────────────────────────────
   Button
────────────────────────────────────────────── */
export function Btn({ children, variant = 'primary', className = '', disabled, ...props }) {
  const base = 'inline-flex items-center gap-2 px-4 py-2 rounded-lg text-[13px] font-semibold transition-all duration-200 disabled:opacity-40 disabled:cursor-not-allowed active:scale-95'
  const variants = {
    primary: 'bg-sky-500 text-white hover:bg-sky-600',
    ghost:   'bg-white text-gray-700 border border-slate-200 hover:bg-sky-50 hover:border-sky-200 hover:text-sky-600',
    danger:  'bg-orange-500 text-white hover:bg-orange-600',
    outline: 'border border-sky-400 text-sky-600 hover:bg-sky-50',
  }
  return (
    <motion.button
      whileHover={!disabled ? { scale: 1.01 } : {}}
      whileTap={!disabled ? { scale: 0.97 } : {}}
      disabled={disabled}
      className={`${base} ${variants[variant]} ${className}`}
      {...props}
    >
      {children}
    </motion.button>
  )
}

/* ──────────────────────────────────────────────
   RiskBadge
────────────────────────────────────────────── */
const riskConfig = {
  critical:   { label: 'Critical',   cls: 'chip chip-critical'   },
  high:       { label: 'High Risk',  cls: 'chip chip-high'       },
  suspicious: { label: 'Suspicious', cls: 'chip chip-suspicious' },
  safe:       { label: 'Safe',       cls: 'chip chip-safe'       },
}
const dotColor = { critical: 'bg-red-400', high: 'bg-orange-400', suspicious: 'bg-amber-400', safe: 'bg-emerald-400' }

export function RiskBadge({ level, children }) {
  const cfg = riskConfig[level] ?? riskConfig.safe
  return (
    <span className={cfg.cls}>
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${dotColor[level] ?? dotColor.safe}`} />
      {children ?? cfg.label}
    </span>
  )
}

/* ──────────────────────────────────────────────
   StatCard
────────────────────────────────────────────── */
export function StatCard({ icon: Icon, value, label, change, changeDir = 'up', delay = 0, iconBg = 'icon-box' }) {
  const display  = useCountUp(value)
  const positive = changeDir === 'up'

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.35 }}
      whileHover={{ y: -2, boxShadow: '0 6px 30px rgba(14,165,233,0.10)' }}
      className="bg-white rounded-xl border border-slate-100 shadow-[0_1px_3px_rgba(0,0,0,0.06)] p-5 cursor-default"
    >
      <div className="flex items-start justify-between mb-4">
        <div className={iconBg}>
          <Icon className="text-lg" />
        </div>
        {change && (
          <div className={`inline-flex items-center gap-0.5 text-[11px] font-medium px-2 py-1 rounded-full ${
            positive ? 'bg-emerald-50 text-emerald-700' : 'bg-sky-50 text-sky-700'
          }`}>
            {positive ? <RiArrowUpLine /> : <RiArrowDownLine />}
            {change}
          </div>
        )}
      </div>
      <p className="text-[28px] font-bold text-gray-900 tracking-tight leading-none">{display}</p>
      <p className="text-[13px] text-gray-500 mt-1 font-medium">{label}</p>
    </motion.div>
  )
}

/* ──────────────────────────────────────────────
   ScoreMeter  — SVG ring gauge
────────────────────────────────────────────── */
export function ScoreMeter({ score, size = 100 }) {
  const r    = 38
  const circ = 2 * Math.PI * r
  const off  = circ - (score / 100) * circ
  const stroke = score >= 76 ? '#FB923C' : score >= 51 ? '#FBBF24' : score >= 21 ? '#34D399' : '#0EA5E9'

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg viewBox="0 0 100 100" width={size} height={size} className="-rotate-90">
        <circle cx="50" cy="50" r={r} fill="none" stroke="#E2E8F0" strokeWidth="9" />
        <motion.circle
          cx="50" cy="50" r={r} fill="none"
          stroke={stroke} strokeWidth="9" strokeLinecap="round"
          strokeDasharray={circ}
          initial={{ strokeDashoffset: circ }}
          animate={{ strokeDashoffset: off }}
          transition={{ duration: 1.2, ease: [0.34, 1.2, 0.64, 1] }}
        />
      </svg>
      <div className="absolute text-center">
        <p className="text-lg font-bold text-gray-900 leading-none">{score}</p>
        <p className="text-[9px] text-gray-400 mt-0.5 font-medium">Risk</p>
      </div>
    </div>
  )
}

/* ──────────────────────────────────────────────
   ProgressBar
────────────────────────────────────────────── */
export function ProgressBar({ value, delay = 0, className = '', color = 'blue' }) {
  const colors = {
    blue:   'from-sky-400 to-sky-500',
    green:  'from-emerald-400 to-emerald-500',
    yellow: 'from-amber-400 to-amber-500',
    red:    'from-orange-400 to-orange-500',
    sky:    'from-sky-400 to-sky-500',
  }
  return (
    <div className={`w-full h-1.5 bg-slate-100 rounded-full overflow-hidden ${className}`}>
      <motion.div
        className={`h-full bg-gradient-to-r ${colors[color] || colors.blue} rounded-full`}
        initial={{ width: 0 }}
        animate={{ width: `${value}%` }}
        transition={{ duration: 0.9, delay, ease: [0.34, 1.2, 0.64, 1] }}
      />
    </div>
  )
}

/* ──────────────────────────────────────────────
   ConfidenceRow
────────────────────────────────────────────── */
export function ConfidenceRow({ label, value, delay = 0 }) {
  const color = value >= 80 ? 'from-sky-400 to-sky-600' : value >= 60 ? 'from-amber-400 to-amber-500' : 'from-orange-400 to-orange-500'
  return (
    <div className="flex items-center gap-3 mb-3">
      <span className="text-[12px] font-medium text-gray-500 w-40 flex-shrink-0">{label}</span>
      <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
        <motion.div
          className={`h-full bg-gradient-to-r ${color} rounded-full`}
          initial={{ width: 0 }}
          animate={{ width: `${value}%` }}
          transition={{ duration: 0.9, delay, ease: [0.34, 1.2, 0.64, 1] }}
        />
      </div>
      <span className="text-[12px] font-bold text-gray-800 w-9 text-right">{value}%</span>
    </div>
  )
}

/* ──────────────────────────────────────────────
   ResultPanel
────────────────────────────────────────────── */
export function ResultPanel({ level = 'info', children }) {
  const styles = {
    danger:  'bg-orange-50 border-orange-400 text-orange-900',
    warning: 'bg-amber-50 border-amber-400 text-amber-900',
    success: 'bg-emerald-50 border-emerald-400 text-emerald-900',
    info:    'bg-sky-50 border-sky-400 text-sky-900',
  }
  return (
    <motion.div
      initial={{ opacity: 0, y: -6 }}
      animate={{ opacity: 1, y: 0 }}
      className={`border-l-4 rounded-r-xl p-4 text-[13px] font-medium ${styles[level]}`}
    >
      {children}
    </motion.div>
  )
}

/* ──────────────────────────────────────────────
   AlertStrip
────────────────────────────────────────────── */
export function AlertStrip({ children, level = 'warning', onDismiss }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
      className={`inline-alert mb-5 ${
        level === 'danger'  ? 'inline-alert-danger'  :
        level === 'warning' ? 'inline-alert-warning' :
                              'inline-alert-info'
      }`}
    >
      {children}
      {onDismiss && (
        <button onClick={onDismiss} className="ml-auto opacity-50 hover:opacity-100 transition-opacity text-lg leading-none">
          ×
        </button>
      )}
    </motion.div>
  )
}

/* ──────────────────────────────────────────────
   Form components
────────────────────────────────────────────── */
export function FormLabel({ children }) {
  return <label className="block text-[12px] font-semibold text-gray-600 mb-1.5">{children}</label>
}

export function FormInput({ className = '', ...props }) {
  return (
    <input
      className={`w-full bg-white border border-slate-200 rounded-xl px-3.5 py-2.5 text-[13px] text-gray-900 font-medium placeholder-gray-300 outline-none focus:border-sky-400 focus:ring-2 focus:ring-sky-100 transition-all ${className}`}
      {...props}
    />
  )
}

export function FormSelect({ className = '', children, ...props }) {
  return (
    <select
      className={`bg-white border border-slate-200 rounded-xl px-3 py-2 text-[12px] font-semibold text-gray-700 outline-none focus:border-sky-400 cursor-pointer transition-all ${className}`}
      {...props}
    >
      {children}
    </select>
  )
}

export function FormTextarea({ className = '', ...props }) {
  return (
    <textarea
      className={`w-full bg-white border border-slate-200 rounded-xl px-4 py-3 text-[13px] text-gray-900 font-medium placeholder-gray-300 outline-none focus:border-sky-400 focus:ring-2 focus:ring-sky-100 transition-all resize-y font-mono ${className}`}
      {...props}
    />
  )
}

/* ──────────────────────────────────────────────
   Tag
────────────────────────────────────────────── */
export function Tag({ children }) {
  return (
    <span className="chip chip-info">{children}</span>
  )
}

/* ──────────────────────────────────────────────
   SectionHeader
────────────────────────────────────────────── */
export function SectionHeader({ title, right }) {
  return (
    <div className="flex items-center justify-between mb-4">
      <h3 className="text-[14px] font-semibold text-gray-900">{title}</h3>
      {right}
    </div>
  )
}

/* ──────────────────────────────────────────────
   HorizBar
────────────────────────────────────────────── */
export function HorizBar({ label, count, max, delay = 0, color = 'sky' }) {
  const pct = max ? Math.round((count / max) * 100) : count
  const colors = {
    sky:    'from-sky-400 to-sky-500',
    amber:  'from-amber-400 to-amber-500',
    orange: 'from-orange-400 to-orange-500',
    indigo: 'from-violet-400 to-violet-500',
  }
  return (
    <div className="mb-3.5">
      <div className="flex justify-between text-[12px] font-medium text-gray-500 mb-1.5">
        <span>{label}</span>
        <span className="font-semibold text-gray-900">{count}</span>
      </div>
      <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
        <motion.div
          className={`h-full bg-gradient-to-r ${colors[color] || colors.sky} rounded-full`}
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.9, delay, ease: [0.34, 1.2, 0.64, 1] }}
        />
      </div>
    </div>
  )
}

/* ──────────────────────────────────────────────
   DropZone
────────────────────────────────────────────── */
export function DropZone({ icon: Icon, title, subtitle, onAction, actionLabel = 'Browse Files', extra }) {
  return (
    <motion.div
      whileHover={{ borderColor: '#7DD3FC', backgroundColor: '#F0F9FF' }}
      className="border-2 border-dashed border-slate-200 rounded-xl p-10 text-center cursor-pointer bg-slate-50 transition-colors"
      onClick={onAction}
    >
      <motion.div animate={{ y: [0, -4, 0] }} transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}>
        <Icon className="text-sky-300 text-4xl mx-auto mb-3" />
      </motion.div>
      <p className="text-[14px] font-semibold text-gray-700 mb-1">{title}</p>
      <p className="text-[12px] text-gray-400 mb-5">{subtitle}</p>
      <div className="flex justify-center gap-3">
        <Btn variant="primary">{actionLabel}</Btn>
        {extra}
      </div>
    </motion.div>
  )
}

/* ──────────────────────────────────────────────
   PageWrapper
────────────────────────────────────────────── */
export function PageWrapper({ children }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: [0.34, 1.1, 0.64, 1] }}
      className="p-6"
    >
      {children}
    </motion.div>
  )
}

/* ──────────────────────────────────────────────
   PageHeader
────────────────────────────────────────────── */
export function PageHeader({ title, sub, right }) {
  if (!right) return null
  return (
    <div className="flex items-center justify-end mb-6">
      {right}
    </div>
  )
}

/* ──────────────────────────────────────────────
   SubTabs
────────────────────────────────────────────── */
export function SubTabs({ tabs, active, onChange }) {
  return (
    <div className="flex border-b border-slate-100 mb-5">
      {tabs.map((tab) => (
        <button
          key={tab}
          onClick={() => onChange(tab)}
          className={`px-5 py-2.5 text-[13px] border-b-2 -mb-px transition-all ${
            active === tab ? 'tab-active' : 'tab-inactive'
          }`}
        >
          {tab}
        </button>
      ))}
    </div>
  )
}

/* ──────────────────────────────────────────────
   SidebarStat
────────────────────────────────────────────── */
export function SidebarStat({ value, label, accent = false }) {
  return (
    <div className="py-3.5 border-b border-slate-50 last:border-none">
      <p className={`text-2xl font-bold ${accent ? 'text-sky-600' : 'text-gray-900'}`}>{value}</p>
      <p className="text-[11px] text-gray-400 mt-0.5 font-medium">{label}</p>
    </div>
  )
}

/* ──────────────────────────────────────────────
   Pagination
────────────────────────────────────────────── */
export function Pagination({ current, total }) {
  return (
    <div className="flex items-center justify-center gap-1 mt-4">
      <button className="w-8 h-8 rounded-lg border bg-white text-gray-400 border-slate-200 hover:border-sky-300 text-sm transition-colors">‹</button>
      {[...Array(Math.min(total, 5))].map((_, i) => {
        const page = i + 1
        return (
          <button
            key={page}
            className={`w-8 h-8 rounded-lg text-[12px] font-semibold transition-all border ${
              page === current
                ? 'bg-sky-500 text-white border-sky-500'
                : 'bg-white text-gray-500 border-slate-200 hover:border-sky-300 hover:text-sky-600'
            }`}
          >
            {page}
          </button>
        )
      })}
      {total > 5 && (
        <>
          <span className="text-gray-400 text-sm px-1">…</span>
          <button className="w-8 h-8 rounded-lg text-[12px] font-semibold border bg-white text-gray-500 border-slate-200">{total}</button>
        </>
      )}
      <button className="w-8 h-8 rounded-lg border bg-white text-gray-400 border-slate-200 hover:border-sky-300 text-sm transition-colors">›</button>
    </div>
  )
}
