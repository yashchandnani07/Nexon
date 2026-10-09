import { useEffect, useRef, useState } from 'react'

const MAX_EVENTS = 50

function getWsUrl() {
  // In dev (npm run dev), Vite proxies /ws → ws://localhost:8001
  // In production (Docker), Nginx proxies /ws → gateway:8001
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${window.location.host}/ws/live`
}

const decisionColor = (d) =>
  d === 'BLOCK' ? 'text-tw-danger' :
  d === 'WARN'  ? 'text-amber-500' :
  'text-tw-success'

const decisionDot = (d) =>
  d === 'BLOCK' ? 'bg-tw-danger' :
  d === 'WARN'  ? 'bg-amber-500' :
  'bg-tw-success'

export default function LiveFeed() {
  const [events, setEvents] = useState([])
  const [connected, setConnected] = useState(false)
  const wsRef = useRef(null)

  useEffect(() => {
    function connect() {
      const ws = new WebSocket(getWsUrl())
      wsRef.current = ws

      ws.onopen  = () => setConnected(true)
      ws.onclose = () => { setConnected(false); setTimeout(connect, 3000) }
      ws.onerror = () => ws.close()
      ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data)
          setEvents((prev) => [data, ...prev].slice(0, MAX_EVENTS))
        } catch {}
      }
    }
    connect()
    return () => wsRef.current?.close()
  }, [])

  return (
    <div className="bg-tw-card border border-tw-border rounded-xl2 p-4 shadow-card/40">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-tw-text">Live DLP Feed</h3>
        <div className="flex items-center gap-1.5 text-[11px] text-tw-textSoft">
          <span className={`h-2 w-2 rounded-full ${connected ? 'bg-tw-success animate-pulse' : 'bg-slate-300'}`} />
          {connected ? 'Streaming' : 'Reconnecting…'}
        </div>
      </div>

      {events.length === 0 ? (
        <p className="text-xs text-tw-textSoft py-8 text-center">
          Waiting for DLP events… Try submitting a prompt!
        </p>
      ) : (
        <ul className="space-y-2 max-h-64 overflow-y-auto pr-1">
          {events.map((ev, idx) => {
            const data = ev?.data || ev
            const decision = data.decision || data.alert_type || 'E'
            return (
              <li
                key={idx}
                className="flex items-start gap-2 rounded-xl border border-tw-border/60 bg-tw-bg px-3 py-2 hover:bg-white transition-colors duration-150"
              >
                <div className="mt-1">
                  <span className={`inline-block h-2 w-2 rounded-full ${decisionDot(decision)}`} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 text-[11px] mb-0.5 flex-wrap">
                    <span className="font-medium text-tw-text">{data.user_id || 'event'}</span>
                    {data.risk_score != null && (
                      <span className={`font-mono ${decisionColor(decision)}`}>
                        {Number(data.risk_score).toFixed(0)}/100
                      </span>
                    )}
                    <span className={`text-[10px] font-semibold ${decisionColor(decision)}`}>
                      {decision}
                    </span>
                    <span className="ml-auto text-[10px] text-tw-textSoft">
                      {data.timestamp ? new Date(data.timestamp).toLocaleTimeString() : ''}
                    </span>
                  </div>
                  <p className="text-xs text-tw-textSoft line-clamp-1">
                    {data.message ||
                      (Array.isArray(data.detected_types) && data.detected_types.length > 0
                        ? data.detected_types.join(', ')
                        : data.block_reason || 'DLP event')}
                  </p>
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
