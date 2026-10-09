import { useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiMailLine, RiMailOpenLine, RiAttachment2, RiSearchLine,
  RiRefreshLine, RiFilterLine, RiArrowDownSLine, RiArrowUpSLine,
  RiFlagLine, RiFlagFill, RiLoader4Line, RiInboxLine,
  RiShieldCheckLine, RiAlertLine, RiCheckboxCircleLine,
  RiErrorWarningLine, RiTimeLine, RiSortAsc, RiSortDesc,
  RiArrowLeftLine, RiArrowRightLine, RiMailSendLine,
  RiSpam2Line, RiCheckDoubleLine, RiShieldLine, 
  RiVirusLine, RiBrainLine, RiGlobalLine,
} from 'react-icons/ri'
import { PageWrapper } from '../components/ui'

// ── Risk tier config ───────────────────────────────────────────────────────────
const RISK_CFG = {
  CRITICAL: { label: 'Critical', dot: 'bg-red-500',    pill: 'bg-red-50 text-red-700 border-red-200',       bar: 'bg-red-500'    },
  HIGH:     { label: 'High',     dot: 'bg-amber-500',  pill: 'bg-amber-50 text-amber-700 border-amber-200', bar: 'bg-amber-500'  },
  MEDIUM:   { label: 'Medium',  dot: 'bg-sky-400',    pill: 'bg-sky-50 text-sky-700 border-sky-200',       bar: 'bg-sky-400'    },
  LOW:      { label: 'Low',     dot: 'bg-emerald-400',pill: 'bg-emerald-50 text-emerald-700 border-emerald-200', bar: 'bg-emerald-400' },
  UNKNOWN:  { label: '—',       dot: 'bg-slate-300',  pill: 'bg-slate-50 text-slate-500 border-slate-200',  bar: 'bg-slate-300'  },
}

function riskCfg(tier) {
  return RISK_CFG[tier] || RISK_CFG.UNKNOWN
}

// Map smtp decision → risk tier
function smtpDecisionToTier(decision) {
  return { REJECT: 'CRITICAL', QUARANTINE: 'HIGH', TAG: 'MEDIUM', ACCEPT: 'LOW' }[decision] || 'UNKNOWN'
}

// ── Relative timestamp ─────────────────────────────────────────────────────────
function relTime(iso) {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60)  return 'just now'
  const m = Math.floor(s / 60)
  if (m < 60)  return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24)  return `${h}h ago`
  const d = Math.floor(h / 24)
  if (d < 7)   return `${d}d ago`
  return new Date(iso).toLocaleDateString()
}

function fullDate(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleString()
}

// ── Parse sender ──────────────────────────────────────────────────────────────
function parseSender(raw) {
  if (!raw) return { name: 'Unknown', email: '' }
  const m = raw.match(/^"?([^"<]+)"?\s*<?([^>]*)>?$/)
  if (m) {
    const name = m[1].trim()
    const email = m[2].trim()
    return { name: name || email, email }
  }
  return { name: raw, email: raw }
}

function SenderAvatar({ sender }) {
  const { name } = parseSender(sender)
  const initials = name.split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase() || '?'
  const colors = [
    'bg-sky-500', 'bg-indigo-500', 'bg-violet-500',
    'bg-teal-500', 'bg-cyan-600', 'bg-blue-600',
  ]
  const idx = name.charCodeAt(0) % colors.length
  return (
    <div className={`w-9 h-9 rounded-full ${colors[idx]} flex items-center justify-center flex-shrink-0`}>
      <span className="text-[11px] font-bold text-white">{initials}</span>
    </div>
  )
}

// ── Risk pill ──────────────────────────────────────────────────────────────────
function RiskPill({ tier }) {
  const cfg = riskCfg(tier)
  if (!tier || tier === 'UNKNOWN') return null
  return (
    <span className={`px-2 py-0.5 text-[10px] font-bold rounded-full border ${cfg.pill}`}>
      {cfg.label}
    </span>
  )
}

// ── SMTP Gateway badge ─────────────────────────────────────────────────────────
function SmtpBadge() {
  return (
    <span
      title="Intercepted at SMTP layer before delivery"
      className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[9px] font-bold rounded border bg-violet-50 text-violet-700 border-violet-200 flex-shrink-0"
    >
      <RiShieldLine className="text-[9px]" />
      SMTP
    </span>
  )
}

// ── Threat type icon ──────────────────────────────────────────────────────────
function ThreatIcon({ threatType, mlClass }) {
  const t = (threatType || mlClass || '').toUpperCase()
  if (t.includes('PHISH')) return <RiGlobalLine className="text-red-400 text-xs flex-shrink-0" title="Phishing" />
  if (t.includes('BEC'))   return <RiBrainLine   className="text-purple-400 text-xs flex-shrink-0" title="BEC / Wire Fraud" />
  if (t.includes('MALWARE') || t.includes('MACRO')) return <RiVirusLine className="text-red-500 text-xs flex-shrink-0" title="Malware" />
  if (t.includes('SCAM'))  return <RiSpam2Line   className="text-amber-400 text-xs flex-shrink-0" title="Scam" />
  return null
}

// ── Email row ──────────────────────────────────────────────────────────────────
function EmailRow({ email, onOpen, onFlag, source }) {
  const { name } = parseSender(email.sender)

  // Determine tier — from email_inbox directly OR from smtp_decisions
  const tier = email.risk_tier
    || smtpDecisionToTier(email.decision)
    || 'UNKNOWN'

  const cfg   = riskCfg(tier)
  const unread = !email.is_read
  const isSmtp = email.email_source === 'SMTP_GATEWAY' || source === 'smtp'

  // For smtp decisions, use created_at instead of received_at
  const timestamp = email.received_at || email.created_at

  // Analysis from stored JSON — may be top-level (list API) or nested (detail API)
  const analysis   = email.analysis || {}
  const threatType = email.threat_type || analysis.threat_type || analysis.ml_classification
  const mlClass    = analysis.ml_classification || analysis.ml_class
  // Combined score: top-level from list API or nested from detail API
  const gatewayScore = parseFloat(email.gateway_score || analysis.combined_score || analysis.gateway_score || 0)

  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.15 }}
      onClick={() => onOpen(email.id, source)}
      className={`flex items-center gap-3 px-4 py-3 cursor-pointer border-b border-slate-100 last:border-0 transition-colors group ${
        unread ? 'bg-white hover:bg-sky-50/40' : 'bg-slate-50/40 hover:bg-sky-50/30'
      }`}
    >
      {/* Risk accent */}
      <div className={`w-0.5 h-10 rounded-full flex-shrink-0 ${cfg.bar} ${tier === 'UNKNOWN' ? 'opacity-0' : ''}`} />

      {/* Avatar */}
      <SenderAvatar sender={email.sender} />

      {/* Main content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className={`text-[13px] truncate ${unread ? 'font-semibold text-slate-900' : 'font-medium text-slate-700'}`}>
            {name}
          </span>
          {(email.has_attachments || email.attachment_count > 0) && (
            <RiAttachment2 className="text-slate-400 text-xs flex-shrink-0" />
          )}
          {isSmtp && <SmtpBadge />}
          <ThreatIcon threatType={threatType} mlClass={mlClass} />
          <RiskPill tier={tier} />
        </div>
        <div className="flex items-baseline gap-1.5">
          <span className={`text-[12px] truncate ${unread ? 'text-slate-700' : 'text-slate-500'}`}>
            {email.subject || '(no subject)'}
          </span>
          {email.body_preview && (
            <span className="text-[11px] text-slate-400 truncate hidden sm:block">
              — {email.body_preview}
            </span>
          )}
          {/* Show combined score if available */}
          {gatewayScore > 0 && (
            <span className={`text-[10px] font-mono ml-auto flex-shrink-0 px-1.5 py-0.5 rounded ${cfg.pill}`}>
              {Math.round(gatewayScore)}/100
            </span>
          )}
        </div>
        {/* Threat explanation preview */}
        {(email.explanation || analysis.explanation) && (
          <p className="text-[11px] text-slate-400 truncate mt-0.5 max-w-lg">
            {email.explanation || analysis.explanation}
          </p>
        )}
      </div>

      {/* Right side */}
      <div className="flex items-center gap-2 flex-shrink-0">
        <span className="text-[11px] text-slate-400 whitespace-nowrap" title={fullDate(timestamp)}>
          {relTime(timestamp)}
        </span>
        <button
          onClick={(e) => { e.stopPropagation(); onFlag(email.id) }}
          className={`p-1 rounded transition-colors ${
            email.is_flagged ? 'text-amber-500' : 'text-slate-300 opacity-0 group-hover:opacity-100 hover:text-amber-400'
          }`}
        >
          {email.is_flagged ? <RiFlagFill className="text-sm" /> : <RiFlagLine className="text-sm" />}
        </button>
        {unread && <div className="w-2 h-2 rounded-full bg-sky-500 flex-shrink-0" />}
      </div>
    </motion.div>
  )
}

// ── Empty state ────────────────────────────────────────────────────────────────
function EmptyState({ filtered, tab }) {
  const msgs = {
    critical: { title: 'No blocked emails', sub: 'Emails blocked as spam or critical threats appear here.' },
    high:     { title: 'No high-risk emails', sub: 'Emails marked High risk will appear here.' },
    medium:   { title: 'No medium-risk emails', sub: 'Suspicious emails appear here.' },
    low:      { title: 'No safe emails', sub: 'Clean emails appear here.' },
    default:  { title: filtered ? 'No emails match your filters' : 'Your inbox is empty',
                sub:   filtered ? 'Try adjusting the filter or search query.' : 'Emails will appear here as they arrive.' },
  }
  const msg = msgs[tab?.toLowerCase()] || msgs.default
  return (
    <div className="flex flex-col items-center justify-center py-16 text-slate-400 gap-3">
      <RiInboxLine className="text-5xl text-slate-200" />
      <p className="text-[14px] font-semibold text-slate-500">{msg.title}</p>
      <p className="text-[12px]">{msg.sub}</p>
    </div>
  )
}

// ── Severity tab config ─────────────────────────────────────────────────────────
const SEVERITY_TABS = [
  { id: 'inbox',    label: 'Inbox',    icon: <RiInboxLine />,         desc: 'Low & Medium risk emails (default)',   riskFilters: ['LOW', 'MEDIUM'] },
  { id: 'high',     label: 'High Risk',icon: <RiErrorWarningLine />, desc: 'High risk emails',                     riskFilters: ['HIGH']          },
  { id: 'critical', label: 'Spam / Blocked', icon: <RiSpam2Line />,  desc: 'Blocked & Critical threat emails',     riskFilters: ['CRITICAL']      },
]

// ── Main Mailbox component ─────────────────────────────────────────────────────
export default function Mailbox({ onOpenEmail }) {
  const [emails, setEmails]             = useState([])
  const [total, setTotal]               = useState(0)
  const [loading, setLoading]           = useState(true)
  const [refreshing, setRefreshing]     = useState(false)
  const [error, setError]               = useState(null)
  const [stats, setStats]               = useState({})
  const [search, setSearch]             = useState('')
  const [searchInput, setSearchInput]   = useState('')
  const [activeTab, setActiveTab]       = useState('inbox')
  const [unreadOnly, setUnreadOnly]     = useState(false)
  const [flaggedOnly, setFlaggedOnly]   = useState(false)
  const [page, setPage]                 = useState(0)
  const [lastRefresh, setLastRefresh]   = useState(null)
  const [initialLoaded, setInitialLoaded] = useState(false)
  const [smtpDecisions, setSmtpDecisions] = useState([])
  const [tabCounts, setTabCounts]       = useState({})

  const PAGE_SIZE = 20
  const inputRef = useRef(null)

  // Get risk filters from the active tab
  const currentTab = SEVERITY_TABS.find(t => t.id === activeTab) || SEVERITY_TABS[0]

  const fetchSmtpDecisions = useCallback(async () => {
    try {
      const res = await fetch('/api/smtp-gateway/decisions?limit=200')
      if (res.ok) {
        const data = await res.json()
        const decisions = Array.isArray(data) ? data : (data.decisions || [])
        setSmtpDecisions(decisions)
      }
    } catch (e) {
      // non-fatal
    }
  }, [])

  const fetchEmails = useCallback(async (opts = {}) => {
    const isRefresh = opts.refresh || false
    if (isRefresh) setRefreshing(true)
    else if (!initialLoaded) setLoading(true)

    const tab = SEVERITY_TABS.find(t => t.id === (opts.tab ?? activeTab)) || currentTab
    const riskFilters = tab.riskFilters

    const params = new URLSearchParams({
      limit:  PAGE_SIZE,
      offset: (opts.page ?? page) * PAGE_SIZE,
    })
    // Build risk filter — pass multiple or a joined string
    if (riskFilters.length === 1) {
      params.set('risk_filter', riskFilters[0])
    } else if (riskFilters.length > 1) {
      // email-monitor supports risk_filter=LOW,MEDIUM
      params.set('risk_filter', riskFilters.join(','))
    }
    if (opts.search ?? search) params.set('search', opts.search ?? search)
    if (opts.unreadOnly ?? unreadOnly) params.set('unread_only', 'true')
    if (opts.flaggedOnly ?? flaggedOnly) params.set('flagged_only', 'true')

    try {
      const [emailRes, statsRes] = await Promise.all([
        fetch(`/api/email/emails?${params}`),
        fetch('/api/email/stats'),
      ])
      if (!emailRes.ok) throw new Error(`API error ${emailRes.status}`)
      const data = await emailRes.json()
      setEmails(data.emails || [])
      setTotal(data.total || 0)
      setLastRefresh(new Date())
      setError(null)
      setInitialLoaded(true)
      if (statsRes.ok) {
        const st = await statsRes.json()
        setStats(st)
        // Build tab counts from stats
        setTabCounts({
          inbox:    (st.low || 0) + (st.medium || 0),
          high:     st.high || 0,
          critical: st.critical || 0,
        })
      }
    } catch (e) {
      console.warn('Mailbox fetch failed:', e)
      setError('Could not load emails. Retrying…')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [page, activeTab, search, unreadOnly, flaggedOnly, initialLoaded, currentTab])

  // Initial fetch + auto-refresh every 10s
  useEffect(() => {
    fetchEmails()
    fetchSmtpDecisions()
    const interval = setInterval(() => {
      fetchEmails({ refresh: true })
      fetchSmtpDecisions()
    }, 10000)
    return () => clearInterval(interval)
  }, [fetchEmails, fetchSmtpDecisions])

  const handleSearch = (e) => {
    e.preventDefault()
    setSearch(searchInput)
    setPage(0)
    fetchEmails({ search: searchInput, page: 0 })
  }

  const handleTabChange = (tabId) => {
    setActiveTab(tabId)
    setPage(0)
    fetchEmails({ tab: tabId, page: 0 })
  }

  const handlePageChange = (newPage) => {
    setPage(newPage)
    fetchEmails({ page: newPage })
  }

  const handleFlag = async (id) => {
    await fetch(`/api/email/emails/${id}/flag`, { method: 'POST' })
    setEmails(prev => prev.map(e => e.id === id ? { ...e, is_flagged: !e.is_flagged } : e))
  }

  const handleOpenEmail = (id, source) => {
    if (onOpenEmail) onOpenEmail(id)
  }

  const totalPages = Math.ceil(total / PAGE_SIZE)
  const hasFilters = search || unreadOnly || flaggedOnly

  return (
    <PageWrapper>
      <div className="flex flex-col h-full">

        {/* Page header */}
        <div className="mb-5">
          <h1 className="text-[22px] font-bold text-slate-900">Mailbox</h1>
          <p className="text-[13px] text-slate-500 mt-0.5">
            Real-time email monitoring · Multi-layer security analysis · AI threat detection
          </p>
        </div>

        {/* Stats strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
          {[
            { label: 'Total',            value: stats.total || 0,             icon: <RiMailLine />,       color: 'text-slate-600 bg-slate-50 border-slate-200'   },
            { label: 'High / Critical',  value: (stats.high_risk || 0),       icon: <RiAlertLine />,      color: 'text-red-700 bg-red-50 border-red-200'         },
            { label: 'With Attachments', value: stats.with_attachments || 0,  icon: <RiAttachment2 />,   color: 'text-indigo-600 bg-indigo-50 border-indigo-200' },
            { label: 'Unread',           value: stats.unread || 0,            icon: <RiMailOpenLine />,   color: 'text-sky-600 bg-sky-50 border-sky-200'         },
          ].map(({ label, value, icon, color }) => (
            <div key={label} className={`p-3 rounded-xl border flex items-center gap-3 ${color}`}>
              <span className="text-lg opacity-70">{icon}</span>
              <div>
                <p className="text-xl font-bold leading-none">{value}</p>
                <p className="text-[11px] font-medium opacity-70 mt-0.5">{label}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Severity tabs */}
        <div className="flex items-center gap-1 mb-4 border-b border-slate-100 pb-2">
          {SEVERITY_TABS.map(tab => {
            const count = tabCounts[tab.id]
            const isActive = activeTab === tab.id
            const dotColor = {
              inbox:    'bg-emerald-400',
              high:     'bg-amber-500',
              critical: 'bg-red-500',
            }[tab.id]

            return (
              <button
                key={tab.id}
                onClick={() => handleTabChange(tab.id)}
                title={tab.desc}
                className={`flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-[12px] font-semibold transition-all ${
                  isActive
                    ? tab.id === 'critical'
                      ? 'bg-red-500 text-white shadow-sm'
                      : tab.id === 'high'
                        ? 'bg-amber-500 text-white shadow-sm'
                        : 'bg-sky-500 text-white shadow-sm'
                    : 'bg-white text-slate-600 border border-slate-200 hover:border-sky-300 hover:text-sky-600'
                }`}
              >
                <span className={`text-sm ${isActive ? 'text-white' : ''}`}>{tab.icon}</span>
                {tab.label}
                {count != null && (
                  <span className={`text-[10px] font-bold rounded-full px-1.5 py-0.5 min-w-[18px] text-center ${
                    isActive ? 'bg-white/20 text-white' : `${count > 0 ? dotColor + ' text-white' : 'bg-slate-100 text-slate-400'}`
                  }`}>
                    {count}
                  </span>
                )}
              </button>
            )
          })}

          <div className="flex-1" />

          {/* Controls */}
          <form onSubmit={handleSearch} className="flex items-center gap-1">
            <div className="relative">
              <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-sm" />
              <input
                ref={inputRef}
                value={searchInput}
                onChange={e => setSearchInput(e.target.value)}
                placeholder="Search…"
                className="w-48 pl-8 pr-3 py-1.5 text-[12px] bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-sky-300 focus:border-sky-400"
              />
            </div>
            {searchInput && (
              <button type="button" onClick={() => { setSearchInput(''); setSearch(''); fetchEmails({ search: '', page: 0 }) }}
                className="text-[11px] text-slate-400 hover:text-slate-600">✕</button>
            )}
          </form>

          <button
            onClick={() => { setUnreadOnly(v => !v); fetchEmails({ unreadOnly: !unreadOnly, page: 0 }) }}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-semibold border transition-colors ${
              unreadOnly ? 'bg-sky-500 text-white border-sky-500' : 'bg-white text-slate-600 border-slate-200 hover:border-sky-300'
            }`}
          >
            <RiMailLine className="text-sm" /> Unread
          </button>

          <button
            onClick={() => { setFlaggedOnly(v => !v); fetchEmails({ flaggedOnly: !flaggedOnly, page: 0 }) }}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-semibold border transition-colors ${
              flaggedOnly ? 'bg-amber-500 text-white border-amber-500' : 'bg-white text-slate-600 border-slate-200 hover:border-amber-300'
            }`}
          >
            <RiFlagLine className="text-sm" /> Flagged
          </button>

          <button
            onClick={() => fetchEmails({ refresh: true })}
            disabled={refreshing}
            className="flex items-center gap-1 text-[12px] text-slate-500 hover:text-sky-500 transition-colors disabled:opacity-40 ml-1"
          >
            <motion.span animate={refreshing ? { rotate: 360 } : {}} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
              <RiRefreshLine />
            </motion.span>
            {lastRefresh ? relTime(lastRefresh.toISOString()) : ''}
          </button>
        </div>

        {/* Tab description banner */}
        {activeTab === 'critical' && (
          <div className="flex items-center gap-2 px-4 py-2.5 mb-3 rounded-xl bg-red-50 border border-red-200 text-red-700">
            <RiSpam2Line className="text-red-500 flex-shrink-0" />
            <span className="text-[12px] font-semibold">Critical & Blocked — Emails flagged as high-threat spam, phishing, BEC, or malware, blocked by the SMTP gateway before delivery.</span>
          </div>
        )}
        {activeTab === 'high' && (
          <div className="flex items-center gap-2 px-4 py-2.5 mb-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-700">
            <RiAlertLine className="text-amber-500 flex-shrink-0" />
            <span className="text-[12px] font-semibold">High Risk — Suspicious emails that were quarantined or tagged for review. Exercise caution.</span>
          </div>
        )}

        {/* Email list card */}
        <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden flex-1">
          {loading ? (
            <div className="flex items-center justify-center py-16 gap-2 text-slate-400">
              <motion.span animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
                <RiLoader4Line className="text-xl" />
              </motion.span>
              <span className="text-[13px]">Loading emails…</span>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-12 gap-3 text-slate-400">
              <RiAlertLine className="text-4xl text-amber-400" />
              <p className="text-[13px] font-semibold text-slate-600">{error}</p>
              <button
                onClick={() => fetchEmails()}
                className="flex items-center gap-1.5 px-4 py-2 bg-sky-500 text-white text-[12px] font-semibold rounded-lg hover:bg-sky-600 transition-colors"
              >
                <RiRefreshLine /> Try Again
              </button>
            </div>
          ) : emails.length === 0 ? (
            <EmptyState filtered={hasFilters} tab={activeTab} />
          ) : (
            <div>
              {emails.map((email) => (
                <EmailRow
                  key={email.id}
                  email={email}
                  onOpen={handleOpenEmail}
                  onFlag={handleFlag}
                  source="inbox"
                />
              ))}
            </div>
          )}
        </div>

        {/* Pagination */}
        {total > PAGE_SIZE && (
          <div className="flex items-center justify-between mt-3">
            <span className="text-[12px] text-slate-400">
              Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total}
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => handlePageChange(page - 1)}
                disabled={page === 0}
                className="p-1.5 rounded-lg border border-slate-200 text-slate-500 hover:border-sky-300 hover:text-sky-500 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <RiArrowLeftLine className="text-sm" />
              </button>
              {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                const p = i
                return (
                  <button
                    key={p}
                    onClick={() => handlePageChange(p)}
                    className={`w-7 h-7 rounded-lg text-[12px] font-semibold transition-colors ${
                      page === p ? 'bg-sky-500 text-white' : 'text-slate-600 hover:bg-slate-100'
                    }`}
                  >
                    {p + 1}
                  </button>
                )
              })}
              <button
                onClick={() => handlePageChange(page + 1)}
                disabled={page >= totalPages - 1}
                className="p-1.5 rounded-lg border border-slate-200 text-slate-500 hover:border-sky-300 hover:text-sky-500 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <RiArrowRightLine className="text-sm" />
              </button>
            </div>
          </div>
        )}
      </div>
    </PageWrapper>
  )
}
