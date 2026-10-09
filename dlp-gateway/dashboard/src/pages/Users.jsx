import { useEffect, useState } from 'react'
import { getUsers } from '../api'

export default function Users() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setLoading(true)
    getUsers(100)
      .then((r) => setUsers(r.data))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  const riskColor = (score) =>
    score >= 70 ? 'text-tw-danger' : score >= 40 ? 'text-amber-500' : 'text-tw-success'

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-tw-text">Users</h1>

      <div className="bg-tw-card border border-tw-border rounded-xl2 overflow-hidden shadow-card/40">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-tw-border text-xs text-tw-textSoft uppercase tracking-wider bg-tw-bg">
              <th className="px-4 py-3 text-left">User ID</th>
              <th className="px-4 py-3 text-left">Dept</th>
              <th className="px-4 py-3 text-left">Role</th>
              <th className="px-4 py-3 text-left">Total Scans</th>
              <th className="px-4 py-3 text-left">Blocked</th>
              <th className="px-4 py-3 text-left">Warned</th>
              <th className="px-4 py-3 text-left">Avg Risk</th>
              <th className="px-4 py-3 text-left">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={8} className="text-center py-10 text-tw-textSoft">Loading…</td>
              </tr>
            )}
            {!loading && users.length === 0 && (
              <tr>
                <td colSpan={8} className="text-center py-10 text-tw-textSoft">No users yet</td>
              </tr>
            )}
            {users.map((u) => (
              <tr key={u.user_id} className="border-b border-tw-border/50 hover:bg-tw-bg transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-tw-text">{u.user_id}</td>
                <td className="px-4 py-3 text-tw-textSoft text-xs">{u.department}</td>
                <td className="px-4 py-3 text-tw-textSoft text-xs">{u.role}</td>
                <td className="px-4 py-3 text-xs text-tw-text">{u.total_prompts}</td>
                <td className="px-4 py-3 text-xs text-tw-danger font-medium">{u.total_blocked}</td>
                <td className="px-4 py-3 text-xs text-amber-500 font-medium">{u.total_warned}</td>
                <td className={`px-4 py-3 text-xs font-bold ${riskColor(u.avg_risk_score)}`}>
                  {u.avg_risk_score}
                </td>
                <td className="px-4 py-3 text-xs text-tw-textSoft whitespace-nowrap">
                  {u.last_seen ? new Date(u.last_seen).toLocaleString() : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
