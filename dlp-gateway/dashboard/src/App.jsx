import { Routes, Route, Navigate } from 'react-router-dom'
import Navbar    from './components/Navbar'
import Login     from './pages/Login'
import Overview  from './pages/Overview'
import Events    from './pages/Events'
import Users     from './pages/Users'
import Alerts    from './pages/Alerts'

function isLoggedIn() {
  return !!localStorage.getItem('dlp_token')
}

function PrivateLayout({ children }) {
  if (!isLoggedIn()) return <Navigate to="/login" replace />
  return (
    <div className="min-h-screen bg-tw-bg">
      <Navbar />
      <main className="max-w-6xl mx-auto px-4 pb-10 pt-6">
        {children}
      </main>
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={
        isLoggedIn() ? <Navigate to="/" replace /> : <Login />
      } />
      <Route path="/"        element={<PrivateLayout><Overview /></PrivateLayout>} />
      <Route path="/events"  element={<PrivateLayout><Events  /></PrivateLayout>} />
      <Route path="/users"   element={<PrivateLayout><Users   /></PrivateLayout>} />
      <Route path="/alerts"  element={<PrivateLayout><Alerts  /></PrivateLayout>} />
      <Route path="*"        element={<Navigate to="/" replace />} />
    </Routes>
  )
}
