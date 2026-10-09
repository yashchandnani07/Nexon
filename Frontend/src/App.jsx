import { useState } from 'react'

// Layout & Core
import Sidebar from './components/layout/Sidebar'
import Topbar  from './components/layout/Topbar'

// Auth
import Login from './pages/Login'

// Employee Pages
import Dashboard          from './pages/Dashboard'
import EmailPhishing      from './pages/EmailPhishing'
import CredentialScanner  from './pages/CredentialScanner'
import AttachmentAnalyzer from './pages/AttachmentAnalyzer'
import WebsiteSpoofing    from './pages/WebsiteSpoofing'
import DeepfakeVoice      from './pages/DeepfakeVoice'
import FeedbackRetraining from './pages/FeedbackRetraining'
import Mailbox            from './pages/Mailbox'
import EmailDetail        from './pages/EmailDetail'

// Full Admin Portal
import AdminPortal from './pages/AdminPortal'

function App() {
  const [user, setUser]               = useState(null)
  const [activePage, setActivePage]   = useState('dashboard')
  const [openEmailId, setOpenEmailId] = useState(null)   // non-null → show EmailDetail

  // ── LOGIN GATE ────────────────────────────────────────────────────────────
  if (!user) {
    return (
      <Login
        onLogin={(u) => {
          setUser(u)
          setActivePage(u.role === 'admin' ? 'admin' : 'dashboard')
        }}
      />
    )
  }

  // ── ADMIN MODE ────────────────────────────────────────────────────────────
  if (user.role === 'admin') {
    return (
      <AdminPortal
        user={user}
        onExit={() => { setUser(null) }}
      />
    )
  }

  // Resolve which page component to render
  const handleSetPage = (p) => {
    if (p === 'admin') {
      setUser(null)
    } else {
      setOpenEmailId(null)
      setActivePage(p)
    }
  }

  const getPageContent = () => {
    // Email detail view — overrides whatever page is active
    if (activePage === 'mailbox' && openEmailId !== null) {
      return (
        <EmailDetail
          emailId={openEmailId}
          onBack={() => setOpenEmailId(null)}
        />
      )
    }
    const PAGES = {
      dashboard:  <Dashboard />,
      email:      <EmailPhishing />,
      credential: <CredentialScanner />,
      attachment: <AttachmentAnalyzer />,
      website:    <WebsiteSpoofing />,
      voice:      <DeepfakeVoice />,
      feedback:   <FeedbackRetraining />,
      mailbox:    <Mailbox onOpenEmail={(id) => setOpenEmailId(id)} />,
    }
    return PAGES[activePage] || PAGES.dashboard
  }

  // ── EMPLOYEE MODE ─────────────────────────────────────────────────────────
  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar
        activePage={activePage}
        setActivePage={handleSetPage}
      />
      <div className="flex-1 flex flex-col min-w-0">
        <Topbar activePage={activePage} />
        <main className="flex-1 overflow-y-auto">
          {getPageContent()}
        </main>
      </div>
    </div>
  )
}

export default App
