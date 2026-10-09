import { useEffect, useState } from 'react'
import { getEvents } from '../api'

const DECISIONS = ['', 'BLOCK', 'WARN', 'PASS']

const decisionBadge = (d) =>
  d === 'BLOCK'
    ? 'bg-red-100 text-tw-danger border-red-200'
    : d === 'WARN'
    ? 'bg-amber-50 text-amber-600 border-amber-200'
    : 'bg-emerald-50 text-emerald-600 border-emerald-200'

export default function Events() {
  const [events, setEvents] = useState([])
  const [filter, setFilter] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setLoading(true)
    getEvents(100, filter)
      .then((r) => setEvents(r.data))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [filter])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-tw-text">Events</h1>
        <div className="flex gap-2">
          {DECISIONS.map((d) => (
            <button
              key={d}
              onClick={() => setFilter(d)}
              className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${
                filter === d
                  ? 'bg-tw-primary border-tw-primary text-white'
                  : 'border-tw-border text-tw-textSoft hover:border-tw-primary hover:text-tw-primary'
              }`}
            >
              {d || 'All'}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-tw-card border border-tw-border rounded-xl2 overflow-hidden shadow-card/40">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-tw-border text-xs text-tw-textSoft uppercase tracking-wider bg-tw-bg">
              <th className="px-4 py-3 text-left">User</th>
              <th className="px-4 py-3 text-left">Dept</th>
              <th className="px-4 py-3 text-left">Destination</th>
              <th className="px-4 py-3 text-left">Decision</th>
              <th className="px-4 py-3 text-left">Risk</th>
              <th className="px-4 py-3 text-left">Detected</th>
              <th className="px-4 py-3 text-left">Time</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={7} className="text-center py-10 text-tw-textSoft">Loading…</td>
              </tr>
            )}
            {!loading && events.length === 0 && (
              <tr>
                <td colSpan={7} className="text-center py-10 text-tw-textSoft">No events yet. Try sending a prompt!</td>
              </tr>
            )}
            {events.map((ev) => (
              <tr key={ev.event_id} className="border-b border-tw-border/50 hover:bg-tw-bg transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-tw-text">{ev.user_id}</td>
                <td className="px-4 py-3 text-tw-textSoft text-xs">{ev.department}</td>
                <td className="px-4 py-3 text-tw-textSoft text-xs truncate max-w-28">{ev.destination}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${decisionBadge(ev.decision)}`}>
                      {ev.decision}
                    </span>
                    {ev.llm_triggered && (
                      <span className="text-[10px] text-blue-400 border border-blue-700/40 px-1.5 py-0.5 rounded flex items-center gap-1">
                        🧠 LLM
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3 text-xs font-mono text-tw-text">{ev.risk_score}</td>
                <td className="px-4 py-3 text-xs text-tw-textSoft truncate max-w-48">
                  {(ev.detected_types || []).slice(0, 2).join(', ')}
                  {(ev.detected_types || []).length > 2 && ` +${ev.detected_types.length - 2}`}
                </td>
                <td className="px-4 py-3 text-xs text-tw-textSoft whitespace-nowrap">
                  {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
