import { motion } from 'framer-motion'
import { RiBellLine, RiSettings3Line, RiSearchLine, RiArrowDownSLine, RiNotificationLine } from 'react-icons/ri'
import { PAGE_META } from '../../constants/navigation.jsx'

export default function Topbar({ activePage }) {
  const meta = PAGE_META[activePage] ?? { title: '', sub: '' }

  return (
    <header className="h-16 sticky top-0 z-40 bg-white/95 backdrop-blur-sm border-b border-slate-100 flex items-center px-6 gap-4 shadow-[0_1px_0_0_#f1f5f9]">
      {/* Title area */}
      <motion.div
        key={activePage}
        initial={{ opacity: 0, x: -8 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.25 }}
        className="flex-1 min-w-0"
      >
        <h1 className="text-[15px] font-semibold text-gray-900 leading-tight tracking-[-0.01em]">{meta.title}</h1>
        <p className="text-[11px] text-gray-400 mt-0.5 truncate hidden md:block font-normal">{meta.sub}</p>
      </motion.div>

      {/* Right controls */}
      <div className="flex items-center gap-2">
        {/* Search */}
        <div className="hidden lg:flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 w-44 focus-within:border-sky-300 focus-within:bg-sky-50/50 transition-all">
          <RiSearchLine className="text-gray-400 text-sm flex-shrink-0" />
          <input
            placeholder="Search..."
            className="bg-transparent text-[12px] text-gray-700 placeholder-gray-400 outline-none w-full font-medium"
          />
        </div>

        {/* Bell - notifications */}
        <button
          title="Notifications"
          className="relative w-9 h-9 rounded-full border border-slate-200 bg-white flex items-center justify-center text-gray-500 hover:text-sky-500 hover:border-sky-200 hover:bg-sky-50 transition-all"
        >
          <RiNotificationLine className="text-[17px]" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-sky-500 rounded-full border-2 border-white" />
        </button>

        {/* Settings */}
        <button
          title="Settings"
          className="w-9 h-9 rounded-full border border-slate-200 bg-white flex items-center justify-center text-gray-500 hover:text-sky-500 hover:border-sky-200 hover:bg-sky-50 transition-all"
        >
          <RiSettings3Line className="text-[16px]" />
        </button>

        {/* Divider */}
        <div className="w-px h-6 bg-slate-100 mx-1" />

        {/* Round user avatar */}
        <div className="relative cursor-pointer group" title="Analyst Kumar — Security Admin">
          <div className="w-9 h-9 rounded-full bg-gradient-to-br from-sky-400 to-sky-600 flex items-center justify-center ring-2 ring-white group-hover:ring-sky-200 transition-all shadow-sm">
            <span className="text-white text-[12px] font-bold">AK</span>
          </div>
          <span className="absolute bottom-0 right-0 w-2.5 h-2.5 bg-emerald-400 rounded-full border-2 border-white" />
        </div>

        {/* Divider */}
        <div className="w-px h-6 bg-slate-100 mx-1" />

        {/* FraudShield AI Brand — top-right corner */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.4 }}
          className="hidden md:flex items-center gap-2.5 px-3 py-1.5 rounded-xl bg-gradient-to-r from-sky-50 to-blue-50 border border-sky-100 cursor-default select-none"
          title="FraudShield AI Security Platform"
        >
          <img
            src="/logo.jpeg"
            alt="FraudShield AI"
            className="w-7 h-7 rounded-lg object-cover shadow-sm flex-shrink-0"
          />
          <div className="leading-none">
            <p className="text-[12px] font-bold text-gray-900 tracking-[-0.01em] leading-tight">FraudShield AI</p>
            <p className="text-[9px] font-semibold text-sky-500 uppercase tracking-wider leading-tight mt-0.5">Security Platform</p>
          </div>
        </motion.div>
      </div>
    </header>
  )
}
