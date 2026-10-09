import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import {
  RiShieldCheckLine, RiAlertLine, RiCheckboxCircleLine,
  RiDatabaseLine, RiGlobalLine, RiSearchLine, RiFileList3Line,
  RiRefreshLine, RiTimeLine,
} from 'react-icons/ri'
import {
  Card, StatCard, RiskBadge, PageWrapper, PageHeader, SectionHeader, Tag, SubTabs,
} from '../../components/ui'

const DLP_API = '/api/dlp'

function useAutoRefresh(fn, intervalMs = 15000) {
  useEffect(() => {
    fn()
    const id = setInterval(fn, intervalMs)
    return () => clearInterval(id)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps
}

function relativeTime(isoStr) {
  if (!isoStr) return '—'
  const diff = Math.floor((Date.now() - new Date(isoStr)) / 1000)
  if (diff < 60)  return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function actionLabel(decision) {
  if (decision === 'BLOCK') return 'Blocked'
  if (decision === 'WARN')  return 'Warned'
  return 'Allowed'
}

function actionLevel(decision) {
  if (decision === 'BLOCK') return 'critical'
  if (decision === 'WARN')  return 'high'
  return 'safe'
}

export default function DLPGuardian() {
  const [tab, setTab]           = useState('Intercept Logs')
  const [stats, setStats]       = useState(null)
  const [events, setEvents]     = useState([])
  const [alerts, setAlerts]     = useState([])
  const [users, setUsers]       = useState([])
  const [search, setSearch]     = useState('')
  const [loading, setLoading]   = useState(true)
  const [lastRefresh, setLastRefresh] = useState(null)

  const fetchAll = useCallback(async () => {
    try {
      const [statsRes, eventsRes, alertsRes, usersRes] = await Promise.all([
        fetch(`${DLP_API}/admin/stats`),
        fetch(`${DLP_API}/admin/events?limit=100`),
        fetch(`${DLP_API}/admin/alerts?limit=50`),
        fetch(`${DLP_API}/admin/users?limit=20`),
      ])
      if (statsRes.ok)  setStats(await statsRes.json())
      if (eventsRes.ok) setEvents(await eventsRes.json())
      if (alertsRes.ok) setAlerts(await alertsRes.json())
      if (usersRes.ok)  setUsers(await usersRes.json())
      setLastRefresh(new Date())
    } catch (err) {
      console.error('DLP fetch error:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useAutoRefresh(fetchAll, 15000)

  // ── Dismiss an alert ────────────────────────────────────────────────────────
  const dismissAlert = async (alertId) => {
    try {
      await fetch(`${DLP_API}/admin/alerts/${alertId}/dismiss`, { method: 'POST' })
      setAlerts(prev => prev.filter(a => a.alert_id !== alertId))
    } catch (err) {
      console.error('Dismiss error:', err)
    }
  }

  // ── Filtered events ──────────────────────────────────────────────────────────
  const filteredEvents = events.filter(e =>
    !search ||
    e.user_id?.toLowerCase().includes(search.toLowerCase()) ||
    e.destination?.toLowerCase().includes(search.toLowerCase()) ||
    e.detected_types?.join(' ').toLowerCase().includes(search.toLowerCase())
  )

  // ── Destination breakdown from events ────────────────────────────────────────
  const destMap = {}
  events.forEach(e => {
    const key = e.destination || 'Unknown'
    destMap[key] = (destMap[key] || 0) + 1
  })
  const totalDest = Object.values(destMap).reduce((s, v) => s + v, 0) || 1
  const destinations = Object.entries(destMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({
      name,
      pct: Math.round((count / totalDest) * 100),
      color: name.toLowerCase().includes('chatgpt') ? 'bg-emerald-500'
           : name.toLowerCase().includes('claude')  ? 'bg-orange-400'
           : name.toLowerCase().includes('gemini')  ? 'bg-sky-500'
           : 'bg-slate-400',
    }))

  // ── Block-rate trend (daily breakdown from events) ─────────────────────────
  const blockCount  = events.filter(e => e.decision === 'BLOCK').length
  const warnCount   = events.filter(e => e.decision === 'WARN').length
  const passCount   = events.filter(e => e.decision === 'PASS').length

  if (loading) return (
    <PageWrapper>
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <RiRefreshLine className="text-4xl text-sky-400 animate-spin" />
        <p className="text-slate-500 text-sm">Connecting to DLP Gateway…</p>
      </div>
    </PageWrapper>
  )

  return (
    <PageWrapper>
      <PageHeader
        title="DLP Guardian for LLMs"
        sub="Live monitoring of sensitive data sent to external AI platforms — powered by the DLP Gateway."
      />

      {/* ── Stats ──────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard
          icon={RiShieldCheckLine}
          value={stats?.total_prompts?.toLocaleString() ?? '—'}
          label="Prompts Analyzed"
          iconBg="icon-box icon-box-blue"
        />
        <StatCard
          icon={RiAlertLine}
          value={stats?.total_blocked?.toLocaleString() ?? '—'}
          label="Data Leaks Blocked"
          iconBg="icon-box icon-box-red"
        />
        <StatCard
          icon={RiDatabaseLine}
          value={stats ? `${stats.block_rate_pct}%` : '—'}
          label="Block Rate"
          iconBg="icon-box icon-box-orange"
        />
        <StatCard
          icon={RiCheckboxCircleLine}
          value={stats?.active_alerts?.toLocaleString() ?? '—'}
          label="Active Alerts"
          iconBg="icon-box icon-box-green"
        />
      </div>

      {/* DPDP violations banner — inline alert */}
      {stats?.dpdp_violations > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          className="inline-alert inline-alert-danger"
        >
          <RiAlertLine className="text-[#DC2626] text-lg flex-shrink-0" />
          <span className="flex-1">
            <strong>{stats.dpdp_violations} DPDP compliance violations</strong> detected in recent scans — review required
          </span>
          <button className="ml-auto text-[#DC2626] opacity-60 hover:opacity-100 text-lg leading-none">×</button>
        </motion.div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-5">
        {/* ── Main panel ──────────────────────────────────────────────────── */}
        <div className="lg:col-span-3 space-y-5">
          <Card>
            <div className="flex items-center justify-between mb-4">
              <SubTabs
                tabs={['Intercept Logs', 'Active Alerts', 'User Risk Profiles', 'Destination Analytics']}
                active={tab}
                onChange={setTab}
              />
              <div className="flex items-center gap-2">
                {tab === 'Intercept Logs' && (
                  <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-lg px-3 py-1.5">
                    <RiSearchLine className="text-slate-400" />
                    <input
                      type="text"
                      value={search}
                      onChange={e => setSearch(e.target.value)}
                      placeholder="Search user or destination…"
                      className="bg-transparent text-[12px] outline-none w-44"
                    />
                  </div>
                )}
                <button
                  onClick={fetchAll}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 text-[11px] text-slate-500 hover:bg-sky-50 hover:text-sky-600 hover:border-sky-200 transition-colors"
                >
                  <RiRefreshLine className="text-sm" /> Refresh
                </button>
              </div>
            </div>

            {/* ── Tab: Intercept Logs ──────────────────────────────────────── */}
            {tab === 'Intercept Logs' && (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-100">
                      <th className="tbl-th">Event ID</th>
                      <th className="tbl-th">User</th>
                      <th className="tbl-th">Destination</th>
                      <th className="tbl-th">Detected Types</th>
                      <th className="tbl-th">Risk</th>
                      <th className="tbl-th">Action</th>
                      <th className="tbl-th">Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEvents.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="p-6 text-center text-slate-400 text-[12px]">
                          No events found
                        </td>
                      </tr>
                    ) : filteredEvents.map((evt, i) => (
                      <motion.tr
                        key={evt.event_id}
                        initial={{ opacity: 0, y: 5 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: i * 0.03 }}
                        className="border-b border-slate-50 last:border-none hover:bg-slate-50"
                      >
                        <td className="p-3 text-[11px] font-mono text-slate-500">
                          {evt.event_id?.slice(0, 8)}…
                        </td>
                        <td className="p-3 text-[12px] font-semibold text-slate-700">
                          {evt.user_id}
                        </td>
                        <td className="p-3">
                          <div className="flex items-center gap-1.5 text-[12px] text-slate-600">
                            <RiGlobalLine className="text-slate-400 flex-shrink-0" />
                            <span className="truncate max-w-[120px]">{evt.destination || 'Unknown'}</span>
                          </div>
                        </td>
                        <td className="p-3">
                          <div className="flex flex-wrap gap-1">
                            {(evt.detected_types || []).slice(0, 2).map(t => (
                              <Tag key={t}>{t}</Tag>
                            ))}
                            {evt.detected_types?.length > 2 && (
                              <Tag>+{evt.detected_types.length - 2}</Tag>
                            )}
                          </div>
                        </td>
                        <td className="p-3 text-[12px] font-mono font-semibold text-slate-600">
                          {evt.risk_score ? Math.round(evt.risk_score) : '—'}
                        </td>
                        <td className="p-3">
                          <RiskBadge level={actionLevel(evt.decision)}>
                            {actionLabel(evt.decision)}
                          </RiskBadge>
                        </td>
                        <td className="p-3 text-[11px] text-slate-400">
                          {relativeTime(evt.timestamp)}
                        </td>
                      </motion.tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* ── Tab: Active Alerts ───────────────────────────────────────── */}
            {tab === 'Active Alerts' && (
              <div className="space-y-3">
                {alerts.length === 0 ? (
                  <p className="text-[12px] text-slate-400 text-center py-8">No active alerts 🎉</p>
                ) : alerts.map((a, i) => (
                  <motion.div
                    key={a.alert_id}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.04 }}
                    className="flex items-start justify-between p-4 rounded-xl bg-red-50 border border-red-100"
                  >
                    <div className="flex items-start gap-3">
                      <RiAlertLine className="text-red-500 text-base mt-0.5 flex-shrink-0" />
                      <div>
                        <p className="text-[13px] font-semibold text-slate-800">{a.message}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">
                          User: <span className="font-mono">{a.user_id}</span> · Risk: {a.risk_score}
                          {a.dpdp_violation && <span className="ml-2 text-red-600 font-bold">· DPDP Violation</span>}
                        </p>
                        <p className="text-[10px] text-slate-400 mt-0.5">{relativeTime(a.timestamp)}</p>
                      </div>
                    </div>
                    <button
                      onClick={() => dismissAlert(a.alert_id)}
                      className="text-[11px] font-semibold text-slate-400 hover:text-red-500 transition-colors ml-4 flex-shrink-0"
                    >
                      Dismiss
                    </button>
                  </motion.div>
                ))}
              </div>
            )}

            {/* ── Tab: User Risk Profiles ──────────────────────────────────── */}
            {tab === 'User Risk Profiles' && (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-100">
                      <th className="tbl-th">User ID</th>
                      <th className="tbl-th">Department</th>
                      <th className="tbl-th">Total Prompts</th>
                      <th className="tbl-th">Blocked</th>
                      <th className="tbl-th">Warned</th>
                      <th className="tbl-th">Avg Risk Score</th>
                      <th className="tbl-th">Last Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.length === 0 ? (
                      <tr><td colSpan={7} className="p-6 text-center text-slate-400 text-[12px]">No user data yet</td></tr>
                    ) : users.map((u, i) => (
                      <motion.tr
                        key={u.user_id}
                        initial={{ opacity: 0, y: 5 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: i * 0.04 }}
                        className="border-b border-slate-50 last:border-none hover:bg-slate-50"
                      >
                        <td className="p-3 text-[12px] font-semibold text-slate-700 font-mono">{u.user_id}</td>
                        <td className="p-3 text-[12px] text-slate-600">{u.department}</td>
                        <td className="p-3 text-[12px] text-slate-600">{u.total_prompts}</td>
                        <td className="p-3"><RiskBadge level={u.total_blocked > 0 ? 'critical' : 'safe'}>{u.total_blocked}</RiskBadge></td>
                        <td className="p-3"><RiskBadge level={u.total_warned > 0 ? 'high' : 'safe'}>{u.total_warned}</RiskBadge></td>
                        <td className="p-3 text-[12px] font-mono font-semibold text-slate-700">{u.avg_risk_score}</td>
                        <td className="p-3 text-[11px] text-slate-400">{relativeTime(u.last_seen)}</td>
                      </motion.tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* ── Tab: Destination Analytics ───────────────────────────────── */}
            {tab === 'Destination Analytics' && (
              <div className="space-y-5 py-2">
                {/* Decision distribution */}
                <div>
                  <p className="text-[12px] font-semibold text-slate-600 mb-3">Decision Distribution (last 100 events)</p>
                  <div className="grid grid-cols-3 gap-3">
                    {[
                      { label: 'Blocked', count: blockCount, color: 'bg-red-500', text: 'text-red-600' },
                      { label: 'Warned',  count: warnCount,  color: 'bg-amber-400', text: 'text-amber-600' },
                      { label: 'Passed',  count: passCount,  color: 'bg-emerald-500', text: 'text-emerald-600' },
                    ].map(({ label, count, color, text }) => (
                      <div key={label} className="p-4 bg-slate-50 rounded-xl border border-slate-100 text-center">
                        <div className={`text-2xl font-bold ${text}`}>{count}</div>
                        <div className="text-[11px] text-slate-500 mt-1">{label}</div>
                        <div className={`h-1.5 rounded-full mt-2 ${color}`} style={{ width: `${Math.round(count / (events.length || 1) * 100)}%`, minWidth: '8px' }} />
                      </div>
                    ))}
                  </div>
                </div>
                {/* LLM destinations */}
                <div>
                  <p className="text-[12px] font-semibold text-slate-600 mb-3">Top Destination Models</p>
                  <div className="space-y-3">
                    {destinations.map(dest => (
                      <div key={dest.name}>
                        <div className="flex justify-between text-[11px] mb-1">
                          <span className="font-semibold text-slate-600">{dest.name}</span>
                          <span className="text-slate-500">{dest.pct}%</span>
                        </div>
                        <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${dest.pct}%` }}
                            transition={{ duration: 0.6, ease: 'easeOut' }}
                            className={`h-full ${dest.color}`}
                          />
                        </div>
                      </div>
                    ))}
                    {destinations.length === 0 && (
                      <p className="text-[12px] text-slate-400 text-center py-4">No destination data yet</p>
                    )}
                  </div>
                </div>
              </div>
            )}
          </Card>
        </div>

        {/* ── Sidebar ────────────────────────────────────────────────────────── */}
        <div className="space-y-5">
          {/* Live stats */}
          <Card>
            <SectionHeader title="Live Statistics" />
            <div>
              {[
                { label: 'Total Prompts',    value: stats?.total_prompts ?? '—', color: 'text-[#2563EB]' },
                { label: 'Blocked',          value: stats?.total_blocked ?? '—', color: 'text-[#DC2626]' },
                { label: 'Warned',           value: stats?.total_warned  ?? '—', color: 'text-[#D97706]' },
                { label: 'DPDP Violations',  value: stats?.dpdp_violations ?? '—', color: 'text-[#DC2626]' },
                { label: 'Restricted Docs',  value: stats?.restricted_docs ?? '—', color: 'text-[#EA580C]' },
              ].map(({ label, value, color }) => (
                <div key={label} className="flex items-center justify-between py-2.5 border-b border-[#F1F5F9] last:border-none">
                  <span className="text-[12px] text-[#64748B]">{label}</span>
                  <span className={`text-[13px] font-semibold ${color}`}>{value?.toLocaleString?.() ?? value}</span>
                </div>
              ))}
            </div>
          </Card>

          {/* Destination breakdown */}
          <Card>
            <SectionHeader title="Top Destinations" />
            <div className="space-y-3">
              {destinations.length > 0 ? destinations.map(dest => (
                <div key={dest.name}>
                  <div className="flex justify-between text-[11px] mb-1">
                    <span className="font-semibold text-slate-600 truncate mr-2">{dest.name}</span>
                    <span className="text-slate-500">{dest.pct}%</span>
                  </div>
                  <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                    <div className={`h-full ${dest.color}`} style={{ width: `${dest.pct}%` }} />
                  </div>
                </div>
              )) : (
                <p className="text-[12px] text-slate-400 text-center py-2">No events yet</p>
              )}
            </div>
          </Card>

          {/* Browser extension info */}
          <Card className="bg-gradient-to-br from-indigo-50 to-white border-indigo-100">
            <div className="flex items-center gap-2 mb-2">
              <RiFileList3Line className="text-indigo-600 text-lg" />
              <h3 className="font-semibold text-[13px] text-indigo-900">Browser Extension</h3>
            </div>
            <p className="text-[11px] text-indigo-700/80 mb-3 leading-relaxed">
              DLP Guardian intercepts HTTP requests to LLM URLs via the corporate Chrome extension before they leave the network.
            </p>
            <button className="w-full py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white text-[12px] font-semibold rounded-lg transition-colors">
              Manage Deployment
            </button>
          </Card>

          {/* Last refresh */}
          {lastRefresh && (
            <div className="flex items-center gap-1.5 text-[10px] text-slate-400 justify-center">
              <RiTimeLine />
              Last refreshed {relativeTime(lastRefresh.toISOString())}
            </div>
          )}
        </div>
      </div>
    </PageWrapper>
  )
}
