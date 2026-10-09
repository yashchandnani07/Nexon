export default function StatCard({ label, value, sub, tone = 'default' }) {
  const toneClasses = {
    default: 'border-slate-200 hover:border-slate-300',
    primary: 'border-tw-primary/40 bg-tw-primarySoft/60 hover:bg-tw-primarySoft',
    danger: 'border-tw-danger/30 bg-red-50 hover:bg-red-100',
    warn: 'border-tw-warn/30 bg-amber-50 hover:bg-amber-100',
    success: 'border-tw-success/20 bg-emerald-50 hover:bg-emerald-100',
  }[tone]

  const valueClasses = {
    default: 'text-tw-text',
    primary: 'text-tw-primary',
    danger: 'text-tw-danger',
    warn: 'text-tw-warn',
    success: 'text-tw-success',
  }[tone]

  return (
    <div
      className={`bg-tw-card border rounded-xl2 px-4 py-3 shadow-card/40 hover:shadow-card transition-all duration-200 ease-smooth hover:-translate-y-0.5 ${toneClasses}`}
    >
      <p className="text-[11px] font-medium uppercase tracking-wide text-tw-textSoft mb-1">
        {label}
      </p>
      <p className={`text-2xl font-bold leading-none mb-1 ${valueClasses}`}>
        {value ?? '—'}
      </p>
      {sub && (
        <p className="text-xs text-tw-textSoft">
          {sub}
        </p>
      )}
    </div>
  )
}
