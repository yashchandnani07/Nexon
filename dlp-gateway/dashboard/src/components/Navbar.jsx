import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useState } from 'react'

const links = [
  { to: '/', label: 'Overview' },
  { to: '/events', label: 'Events' },
  { to: '/users', label: 'Users' },
  { to: '/alerts', label: 'Alerts' },
]

export default function Navbar() {
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const [hovered, setHovered] = useState(false)

  const logout = () => {
    localStorage.removeItem('dlp_token')
    localStorage.removeItem('dlp_role')
    navigate('/login')
  }

  return (
    <header className="border-b border-tw-border bg-white/80 backdrop-blur-sm sticky top-0 z-30">
      <div className="max-w-6xl mx-auto px-4 h-14 flex items-center justify-between">
        <div
          className="flex items-center gap-2 cursor-default"
          onMouseEnter={() => setHovered(true)}
          onMouseLeave={() => setHovered(false)}
        >
          <div className="relative h-8 w-8 flex items-center justify-center">
            <div className="absolute inset-0 rounded-full bg-tw-primary/10 scale-0 group-hover:scale-100 transition-transform duration-300 ease-smooth" />
            <div className="h-8 w-8 rounded-full bg-tw-primary flex items-center justify-center shadow-card">
              <span className="text-white text-lg font-bold tracking-tight">G</span>
            </div>
          </div>
          <div className="flex flex-col leading-tight">
            <span className="font-bold text-sm text-tw-text">Guardrail DLP</span>
            <span className="text-[11px] text-tw-textSoft">
              {hovered ? 'Protecting your prompts.' : 'Twitter-inspired control plane'}
            </span>
          </div>
        </div>

        <nav className="flex items-center gap-1">
          {links.map((l) => {
            const active = pathname === l.to
            return (
              <Link
                key={l.to}
                to={l.to}
                className={[
                  'relative px-3 py-1.5 text-sm rounded-full transition-all duration-200 ease-smooth',
                  active
                    ? 'text-tw-primary bg-tw-primarySoft font-semibold shadow-sm'
                    : 'text-tw-textSoft hover:bg-slate-100 hover:text-tw-text',
                ].join(' ')}
              >
                {active && (
                  <span className="absolute inset-0 rounded-full border border-tw-primary/40 animate-[pulse_1.8s_ease-out_infinite]" />
                )}
                <span className="relative z-10">{l.label}</span>
              </Link>
            )
          })}
          <button
            onClick={logout}
            className="ml-2 text-xs px-3 py-1.5 rounded-full border border-slate-200 text-tw-textSoft hover:border-tw-danger hover:text-tw-danger transition-colors duration-150"
          >
            Logout
          </button>
        </nav>
      </div>
    </header>
  )
}
