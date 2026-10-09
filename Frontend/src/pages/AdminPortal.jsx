import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiUserLine, RiArrowRightSLine, RiLogoutBoxLine,
  RiBellLine, RiSettings3Line, RiArrowDownSLine, RiMenuLine, RiCloseLine,
  RiNotificationLine,
} from 'react-icons/ri'
import { ADMIN_NAV_ITEMS, PAGE_META } from '../constants/navigation.jsx'

// Admin pages
import AdminOverview      from './admin/AdminOverview'
import DLPGuardian        from './admin/DLPGuardian'
import PromptGuardChatbot from './PromptGuardChatbot'
import AgentSandbox       from './AgentSandbox'
import ModelAnalytics     from './admin/ModelAnalytics'
import ModelPolicies      from './admin/ModelPolicies'
import ModelRetraining    from './admin/ModelRetraining'

const ADMIN_PAGES = {
  adminoverview:  <AdminOverview />,
  dlpguardian:    <DLPGuardian />,
  prompt:         <PromptGuardChatbot />,
  sandbox:        <AgentSandbox />,
  modelanalytics: <ModelAnalytics />,
  modelpolicies:  <ModelPolicies />,
  modelretraining:<ModelRetraining />,
}

console.log('[AegisAI] Loading AdminPortal module...');

function AdminPortal({ onExit }) {
  const [activePage, setActivePage] = useState('adminoverview')
  const [collapsed, setCollapsed]   = useState(false)
  const meta = PAGE_META[activePage] ?? { title: '', sub: '' }

  return (
    <div className="flex min-h-screen bg-slate-50">
      {/* Admin Sidebar */}
      <motion.aside
        initial={false}
        animate={{ width: collapsed ? 64 : 240 }}
        transition={{ duration: 0.25, ease: [0.4, 0, 0.2, 1] }}
        className="fixed top-0 left-0 bottom-0 bg-white flex flex-col z-50 border-r border-slate-100 overflow-hidden"
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-4 py-4 border-b border-slate-100 min-h-[64px] bg-gradient-to-r from-sky-50/60 to-white">
          <div className="w-8 h-8 rounded-xl overflow-hidden flex-shrink-0 shadow-sm ring-1 ring-sky-100">
            <img src="/logo.jpeg" alt="FraudShield AI" className="w-full h-full object-cover" />
          </div>
          {!collapsed && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex-1 min-w-0">
              <p className="font-bold text-[13px] tracking-tight text-gray-900 leading-tight">FraudShield AI</p>
              <p className="text-[9px] font-semibold text-sky-500 uppercase tracking-wider">Admin Console</p>
            </motion.div>
          )}
          <button
            onClick={() => setCollapsed(c => !c)}
            className={`flex-shrink-0 w-7 h-7 rounded-lg flex items-center justify-center text-gray-400 hover:text-sky-500 hover:bg-sky-50 transition-all ${collapsed ? 'mx-auto' : ''}`}
          >
            {collapsed ? <RiMenuLine className="text-base" /> : <RiCloseLine className="text-base" />}
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-3">
          {ADMIN_NAV_ITEMS.map(({ section, items }) => (
            <div key={section} className="mb-4">
              {!collapsed && (
                <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-400 px-4 pt-1 pb-2">
                  {section}
                </p>
              )}
              {collapsed && <div className="h-px bg-slate-100 mx-3 mb-2" />}
              <div className="space-y-0.5 px-2">
                {items.map(({ id, label, icon: Icon, badge, badgeType }) => {
                  const active = activePage === id
                  return (
                    <button
                      key={id}
                      onClick={() => setActivePage(id)}
                      title={collapsed ? label : undefined}
                      className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-[13px] transition-all duration-150 group ${
                        active
                          ? 'bg-sky-50 text-sky-600 font-semibold'
                          : 'text-gray-500 hover:bg-slate-50 hover:text-gray-800 font-medium'
                      } ${collapsed ? 'justify-center px-0' : ''}`}
                      style={active && !collapsed ? { borderLeft: '3px solid #0EA5E9', borderRadius: '0 12px 12px 0', paddingLeft: '9px' } : {}}
                    >
                      <Icon className={`text-[17px] flex-shrink-0 ${active ? 'text-sky-500' : 'text-gray-400 group-hover:text-gray-600'}`} />
                      {!collapsed && <span className="flex-1 text-left">{label}</span>}
                      {!collapsed && badge != null && (
                        <span className="text-[10px] font-bold w-[18px] h-[18px] rounded-full flex items-center justify-center bg-sky-100 text-sky-600">
                          {badge}
                        </span>
                      )}
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Bottom */}
        {!collapsed ? (
          <div className="p-3 border-t border-slate-100 space-y-1">
            <button
              onClick={onExit}
              className="btn-ghost w-full justify-start text-[12px] py-2"
            >
              <RiLogoutBoxLine className="text-gray-400" />
              Switch to Employee View
            </button>
            <div className="flex items-center gap-2.5 p-2.5 rounded-xl cursor-pointer hover:bg-sky-50 transition-colors">
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-sky-400 to-sky-600 flex items-center justify-center flex-shrink-0">
                <span className="text-white text-[11px] font-bold">AM</span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-[12px] font-semibold text-gray-900 truncate">Arjun Mehta</p>
                <p className="text-[10px] text-gray-400">Super Admin</p>
              </div>
              <span className="online-dot" />
            </div>
          </div>
        ) : (
          <div className="p-2 border-t border-slate-100 flex justify-center">
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-sky-400 to-sky-600 flex items-center justify-center">
              <span className="text-white text-[11px] font-bold">AM</span>
            </div>
          </div>
        )}
      </motion.aside>

      {/* Spacer */}
      <motion.div
        animate={{ width: collapsed ? 64 : 240 }}
        transition={{ duration: 0.25, ease: [0.4, 0, 0.2, 1] }}
        className="flex-shrink-0"
        style={{ minWidth: collapsed ? 64 : 240 }}
      />

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Topbar */}
        <header className="h-16 sticky top-0 z-40 bg-white border-b border-slate-100 flex items-center px-6 gap-4">
          <motion.div
            key={activePage}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.25 }}
            className="flex-1 min-w-0"
          >
            <h1 className="text-[16px] font-bold text-gray-900">{meta.title}</h1>
            <p className="text-[11px] text-gray-400 mt-0.5 hidden md:block">{meta.sub}</p>
          </motion.div>

          <div className="flex items-center gap-2">
            {/* Admin Mode badge */}
            <div className="hidden md:flex items-center gap-1.5 px-3 py-1.5 bg-sky-50 rounded-full border border-sky-100">
              <span className="inline-block w-2 h-2 rounded-full bg-sky-500" />
              <span className="text-[11px] font-semibold text-sky-700">Admin Mode</span>
            </div>

            {/* Bell */}
            <button title="Notifications" className="w-9 h-9 rounded-full border border-slate-200 bg-white flex items-center justify-center text-gray-500 hover:text-sky-500 hover:border-sky-200 hover:bg-sky-50 transition-all">
              <RiNotificationLine className="text-[17px]" />
            </button>

            {/* Settings */}
            <button title="Settings" className="w-9 h-9 rounded-full border border-slate-200 bg-white flex items-center justify-center text-gray-500 hover:text-sky-500 hover:border-sky-200 hover:bg-sky-50 transition-all">
              <RiSettings3Line className="text-[16px]" />
            </button>

            {/* Round avatar */}
            <div className="relative cursor-pointer" title="Arjun Mehta — Super Admin">
              <div className="w-9 h-9 rounded-full bg-gradient-to-br from-sky-400 to-sky-600 flex items-center justify-center ring-2 ring-white hover:ring-sky-200 transition-all shadow-sm">
                <span className="text-white text-[12px] font-bold">AM</span>
              </div>
              <span className="absolute bottom-0 right-0 w-2.5 h-2.5 bg-emerald-400 rounded-full border-2 border-white" />
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto">
          <AnimatePresence mode="wait">
            <motion.div
              key={activePage}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.25 }}
            >
              {ADMIN_PAGES[activePage]}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  )
}

export default AdminPortal;
