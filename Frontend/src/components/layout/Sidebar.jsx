import { useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { RiUserLine, RiArrowRightSLine, RiMenuLine, RiCloseLine } from 'react-icons/ri'
import { NAV_ITEMS } from '../../constants/navigation.jsx'

export default function Sidebar({ activePage, setActivePage }) {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <>
      {/* Sidebar */}
      <motion.aside
        initial={false}
        animate={{ width: collapsed ? 64 : 240 }}
        transition={{ duration: 0.25, ease: [0.4, 0, 0.2, 1] }}
        className="fixed top-0 left-0 bottom-0 bg-white flex flex-col z-50 border-r border-slate-100 overflow-hidden shadow-[1px_0_0_0_#f1f5f9]"
      >
        {/* Logo + Collapse toggle */}
        <div className="flex items-center gap-3 px-4 py-4 border-b border-slate-100 min-h-[64px] bg-gradient-to-r from-sky-50/60 to-white">
          <div className="w-8 h-8 rounded-xl overflow-hidden flex-shrink-0 shadow-sm ring-1 ring-sky-100">
            <img src="/logo.jpeg" alt="FraudShield AI" className="w-full h-full object-cover" />
          </div>
          {!collapsed && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="flex-1 min-w-0"
            >
              <p className="font-bold text-[13px] tracking-tight text-gray-900 leading-tight">FraudShield AI</p>
              <p className="text-[9px] font-semibold text-sky-500 uppercase tracking-wider">Security Platform</p>
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
          {NAV_ITEMS.map(({ section, items }) => (
            <div key={section} className="mb-4">
              {!collapsed && (
                <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-400 px-4 pt-1 pb-2">
                  {section}
                </p>
              )}
              {collapsed && <div className="h-px bg-slate-100 mx-3 mb-2" />}
              <div className="space-y-0.5 px-2">
                {items.map(({ id, label, icon: Icon }) => {
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
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* User */}
        {!collapsed && (
          <div className="p-3 border-t border-slate-100">
            <div className="flex items-center gap-2.5 p-2.5 rounded-xl cursor-pointer hover:bg-sky-50 transition-colors group">
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-sky-400 to-sky-600 flex items-center justify-center flex-shrink-0 shadow-sm">
                <span className="text-white text-[11px] font-bold">AK</span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-[12px] font-semibold text-gray-900 truncate">Analyst Kumar</p>
                <p className="text-[10px] text-gray-400">Security Admin</p>
              </div>
              <span className="online-dot" />
            </div>
          </div>
        )}
        {collapsed && (
          <div className="p-2 border-t border-slate-100 flex justify-center">
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-sky-400 to-sky-600 flex items-center justify-center shadow-sm">
              <span className="text-white text-[11px] font-bold">AK</span>
            </div>
          </div>
        )}
      </motion.aside>

      {/* Spacer to push content right on desktop */}
      <motion.div
        animate={{ width: collapsed ? 64 : 240 }}
        transition={{ duration: 0.25, ease: [0.4, 0, 0.2, 1] }}
        className="flex-shrink-0"
        style={{ minWidth: collapsed ? 64 : 240 }}
      />
    </>
  )
}
