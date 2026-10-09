import { useEffect, useState } from 'react'
import { getAlerts, dismissAlert } from '../api'

const ALERT_TYPE_META = {
  HIGH_RISK:       { icon: '🚨', color: 'text-red-400',    bg: 'bg-red-900/30',    label: 'High Risk'         },
  REPEAT_OFFENDER: { icon: '🔁', color: 'text-yellow-400', bg: 'bg-yellow-900/30', label: 'Repeat Offender'   },
  DPDP_VIOLATION:  { icon: '🇮🇳', color: 'text-orange-400', bg: 'bg-orange-900/30', label: 'DPDP Violation'    },
  DOC_RESTRICTED:  { icon: '🔴', color: 'text-red-400',    bg: 'bg-red-900/30',    label: 'Restricted Doc'    },
}

const DOC_CLASS_META = {
  RESTRICTED:   { icon: '🔴', color: 'text-red-400',    label: 'RESTRICTED'   },
  CONFIDENTIAL: { icon: '🟠', color: 'text-orange-400', label: 'CONFIDENTIAL' },
  INTERNAL:     { icon: '🟡', color: 'text-yellow-400', label: 'INTERNAL'     },
  PUBLIC:       { icon: '🟢', color: 'text-green-400',  label: 'PUBLIC'       },
}

export default function Alerts() {
  const [alerts, setAlerts]       = useState([])
  const [loading, setLoading]     = useState(true)
  const [filter, setFilter]       = useState('ALL')
  const [dismissing, setDismissing] = useState(new Set())

  async function load() {
    setLoading(true)
    try {
      const { data } = await getAlerts(100, false)
      setAlerts(Array.isArray(data) ? data : [])
    } catch { setAlerts([]) }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  async function handleDismiss(alertId) {
    setDismissing(s => new Set([...s, alertId]))
    try {
      await dismissAlert(alertId)
      setAlerts(prev => prev.filter(a => a.alert_id !== alertId))
    } catch {}
    finally { setDismissing(s => { const n = new Set(s); n.delete(alertId); return n }) }
  }

  const filtered = filter === 'ALL'
    ? alerts
    : alerts.filter(a => a.alert_type === filter)

  const alertTypes = ['ALL', ...new Set(alerts.map(a => a.alert_type))]

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="text-tw-textSoft text-sm animate-pulse">Loading alerts…</div>
    </div>
  )

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-tw-text">Security Alerts</h1>
          <p className="text-xs text-tw-textSoft mt-0.5">
            {alerts.length} active alert{alerts.length !== 1 ? 's' : ''} — High-risk events requiring review
          </p>
        </div>
        <button
          onClick={load}
          className="text-xs text-tw-primary border border-tw-border px-3 py-1.5 rounded-lg hover:bg-tw-card transition-colors"
        >
          Refresh
        </button>
      </div>

      {/* Filter tabs */}
      <div className="flex gap-2 flex-wrap">
        {alertTypes.map(t => {
          const meta = ALERT_TYPE_META[t] || {}
          return (
            <button
              key={t}
              onClick={() => setFilter(t)}
              className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${
                filter === t
                  ? 'bg-tw-primary text-white border-tw-primary'
                  : 'border-tw-border text-tw-textSoft hover:text-tw-text'
              }`}
            >
              {meta.icon ? `${meta.icon} ` : ''}{(ALERT_TYPE_META[t]?.label) || t}
              {t !== 'ALL' && (
                <span className="ml-1 opacity-60">
                  ({alerts.filter(a => a.alert_type === t).length})
                </span>
              )}
            </button>
          )
        })}
      </div>

      {filtered.length === 0 ? (
        <div className="bg-tw-card border border-tw-border rounded-xl p-10 text-center">
          <div className="text-3xl mb-3">✅</div>
          <div className="text-sm font-semibold text-tw-text">No active alerts</div>
          <div className="text-xs text-tw-textSoft mt-1">All systems operating normally</div>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map(alert => {
            const meta = ALERT_TYPE_META[alert.alert_type] || { icon: '⚠️', color: 'text-tw-textSoft', bg: 'bg-tw-card', label: alert.alert_type }
            const docMeta = DOC_CLASS_META[alert.doc_classification] || null
            const isDismissing = dismissing.has(alert.alert_id)
            return (
              <div
                key={alert.alert_id}
                className={`border border-tw-border rounded-xl p-4 ${meta.bg} transition-all`}
              >
                <div className="flex items-start gap-3">
                  <span className="text-2xl flex-shrink-0 mt-0.5">{meta.icon}</span>
                  <div className="flex-1 min-w-0">
                    {/* Top row */}
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className={`text-xs font-bold ${meta.color}`}>{meta.label}</span>
                      {alert.dpdp_violation && (
                        <span className="text-xs bg-orange-900/40 text-orange-300 border border-orange-700/50 px-2 py-0.5 rounded-full">
                          🇮🇳 DPDP Violation
                        </span>
                      )}
                      {docMeta && (
                        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border border-tw-border ${docMeta.color}`}>
                          {docMeta.icon} {docMeta.label}
                        </span>
                      )}
                      <span className="text-xs text-tw-textSoft ml-auto flex-shrink-0">
                        {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : '—'}
                      </span>
                    </div>

                    {/* Message */}
                    <p className="text-sm text-tw-text leading-relaxed">{alert.message}</p>

                    {/* Meta row */}
                    <div className="flex items-center gap-3 mt-2 flex-wrap">
                      <span className="text-xs text-tw-textSoft">
                        👤 <span className="font-mono text-tw-text">{alert.user_id}</span>
                      </span>
                      <span className={`text-xs font-semibold ${
                        alert.risk_score >= 80 ? 'text-red-400'
                        : alert.risk_score >= 50 ? 'text-orange-400'
                        : 'text-yellow-400'
                      }`}>
                        Risk: {alert.risk_score?.toFixed(1)}/100
                      </span>
                      <span className="text-xs font-mono text-tw-textSoft truncate max-w-[140px]" title={alert.event_id}>
                        #{alert.event_id?.slice(0, 8)}
                      </span>
                    </div>
                  </div>

                  {/* Dismiss button */}
                  <button
                    onClick={() => handleDismiss(alert.alert_id)}
                    disabled={isDismissing}
                    className="flex-shrink-0 text-xs text-tw-textSoft hover:text-tw-danger border border-tw-border px-3 py-1.5 rounded-lg hover:border-tw-danger/50 transition-colors disabled:opacity-50"
                  >
                    {isDismissing ? '…' : 'Dismiss'}
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
