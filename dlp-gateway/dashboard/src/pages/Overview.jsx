import { useEffect, useState } from 'react'
import { getStats, getEvents } from '../api'
import StatCard from '../components/StatCard'

const DECISION_META = {
  BLOCK: { label: 'Blocked', color: 'text-red-400',    bg: 'bg-red-900/20',    dot: 'bg-red-500'    },
  WARN:  { label: 'Warning', color: 'text-yellow-400', bg: 'bg-yellow-900/20', dot: 'bg-yellow-500' },
  PASS:  { label: 'Passed',  color: 'text-green-400',  bg: 'bg-green-900/20',  dot: 'bg-green-500'  },
}

const DOC_CLASS_META = {
  RESTRICTED:   { icon: '🔴', color: 'text-red-400',    label: 'RESTRICTED'   },
  CONFIDENTIAL: { icon: '🟠', color: 'text-orange-400', label: 'CONFIDENTIAL' },
  INTERNAL:     { icon: '🟡', color: 'text-yellow-400', label: 'INTERNAL'     },
  PUBLIC:       { icon: '🟢', color: 'text-green-400',  label: 'PUBLIC'       },
}

export default function Overview() {
  const [stats, setStats]   = useState(null)
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)

  async function load() {
    setLoading(true)
    try {
      const [sr, er] = await Promise.all([getStats(), getEvents(8)])
      setStats(sr.data)
      setEvents(Array.isArray(er.data) ? er.data : [])
    } catch {}
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-tw-text">Dashboard Overview</h1>
          <p className="text-xs text-tw-textSoft mt-0.5">Real-time DLP monitoring — Guardrail v3</p>
        </div>
        <button
          onClick={load}
          className="text-xs text-tw-primary border border-tw-border px-3 py-1.5 rounded-lg hover:bg-tw-card transition-colors"
        >
          Refresh
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Total Scans"  value={stats?.total_prompts}  tone="primary" />
        <StatCard label="Blocked"      value={stats?.total_blocked}  tone="danger"  />
        <StatCard label="Warnings"     value={stats?.total_warned}   tone="warn"    />
        <StatCard label="Passed"       value={stats?.total_passed}   tone="success" />
      </div>

      {/* Second row of stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard
          label="Block Rate"
          value={stats ? `${stats.block_rate_pct ?? '0.0'}%` : null}
          tone="primary"
        />
        <StatCard label="Active Alerts"     value={stats?.active_alerts}    tone="danger"  />
        <StatCard label="DPDP Violations"   value={stats?.dpdp_violations}  tone="warn"    />
        <StatCard label="Restricted Docs"   value={stats?.restricted_docs}  tone="danger"  />
      </div>

      {/* Recent events table */}
      <div className="bg-tw-card border border-tw-border rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-tw-border flex items-center justify-between">
          <h2 className="text-sm font-semibold text-tw-text">Recent Events</h2>
          <a href="/events" className="text-xs text-tw-primary hover:underline">View all →</a>
        </div>

        {loading ? (
          <div className="px-5 py-10 text-center text-xs text-tw-textSoft animate-pulse">Loading…</div>
        ) : events.length === 0 ? (
          <div className="px-5 py-10 text-center text-xs text-tw-textSoft">No events yet — scan a prompt to get started.</div>
        ) : (
          <div className="divide-y divide-tw-border">
            {events.map(ev => {
              const dm    = DECISION_META[ev.decision] || DECISION_META.PASS
              const docMeta = ev.doc_classification ? DOC_CLASS_META[ev.doc_classification] : null
              return (
                <div key={ev.event_id} className="px-5 py-3 flex items-center gap-3 hover:bg-tw-bg/50 transition-colors">
                  {/* Decision dot + label */}
                  <div className={`flex-shrink-0 flex items-center gap-1.5 w-20`}>
                    <span className={`h-2 w-2 rounded-full flex-shrink-0 ${dm.dot}`} />
                    <span className={`text-xs font-semibold ${dm.color}`}>{dm.label}</span>
                  </div>

                  {/* User + destination */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-tw-text font-mono truncate max-w-[140px]">
                        {ev.user_id}
                      </span>
                      {ev.destination && (
                        <span className="text-xs text-tw-textSoft">→ {ev.destination}</span>
                      )}
                    </div>
                    {/* Detected types */}
                    {ev.detected_types?.length > 0 && (
                      <div className="flex gap-1 mt-0.5 flex-wrap">
                        {ev.detected_types.slice(0, 3).map(t => (
                          <span key={t} className="text-[10px] bg-tw-bg border border-tw-border px-1.5 py-0.5 rounded text-tw-textSoft">
                            {t}
                          </span>
                        ))}
                        {ev.detected_types.length > 3 && (
                          <span className="text-[10px] text-tw-textSoft">+{ev.detected_types.length - 3}</span>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Doc classification badge */}
                  {docMeta && (
                    <span className={`flex-shrink-0 text-[10px] font-bold px-2 py-0.5 rounded-full border border-tw-border/50 ${docMeta.color}`}>
                      {docMeta.icon} {docMeta.label}
                    </span>
                  )}

                  {/* DPDP badge */}
                  {ev.dpdp_violation && (
                    <span className="flex-shrink-0 text-[10px] text-orange-400 border border-orange-700/40 px-2 py-0.5 rounded-full">
                      🇮🇳 DPDP
                    </span>
                  )}

                  {/* LLM triggered badge */}
                  {ev.llm_triggered && (
                    <span className="flex-shrink-0 text-[10px] text-blue-400 border border-blue-700/40 px-2 py-0.5 rounded-full">
                      🧠 LLM
                    </span>
                  )}

                  {/* Risk score */}
                  <span className={`flex-shrink-0 text-xs font-bold w-14 text-right ${
                    ev.risk_score >= 80 ? 'text-red-400'
                    : ev.risk_score >= 50 ? 'text-orange-400'
                    : ev.risk_score >= 30 ? 'text-yellow-400'
                    : 'text-green-400'
                  }`}>
                    {ev.risk_score?.toFixed(1)}
                  </span>

                  {/* Time */}
                  <span className="flex-shrink-0 text-[10px] text-tw-textSoft w-20 text-right">
                    {ev.timestamp
                      ? new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                      : '—'}
                  </span>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Document Classification Legend */}
      <div className="bg-tw-card border border-tw-border rounded-xl p-5">
        <h2 className="text-sm font-semibold text-tw-text mb-4">Document Classification Taxonomy</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {[
            {
              level: 'RESTRICTED', icon: '🔴', color: 'border-red-700/50 bg-red-900/10',
              label: 'Restricted', action: 'Always blocked',
              desc: 'Board minutes, M&A data, master keys, executive compensation. Never leaves the organization.',
            },
            {
              level: 'CONFIDENTIAL', icon: '🟠', color: 'border-orange-700/50 bg-orange-900/10',
              label: 'Confidential', action: 'Block + approval',
              desc: 'Customer PII, account data, KYC documents, employee records, AML reports.',
            },
            {
              level: 'INTERNAL', icon: '🟡', color: 'border-yellow-700/50 bg-yellow-900/10',
              label: 'Internal', action: 'Block externally',
              desc: 'Org charts, project plans, training materials, internal memos. Allowed within org.',
            },
            {
              level: 'PUBLIC', icon: '🟢', color: 'border-green-700/50 bg-green-900/10',
              label: 'Public', action: 'Allow + log',
              desc: 'Press releases, marketing brochures, public annual reports.',
            },
          ].map(item => (
            <div key={item.level} className={`border rounded-lg p-3 ${item.color}`}>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-base">{item.icon}</span>
                <span className="text-xs font-bold text-tw-text">{item.label}</span>
                <span className="ml-auto text-[10px] text-tw-textSoft border border-tw-border px-2 py-0.5 rounded-full">
                  {item.action}
                </span>
              </div>
              <p className="text-[11px] text-tw-textSoft leading-relaxed">{item.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
