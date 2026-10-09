import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiDatabaseLine, RiShieldUserLine, RiToggleLine, RiToggleFill,
  RiAddLine, RiDeleteBinLine, RiEditLine, RiCloseLine,
  RiRefreshLine, RiPlantLine, RiCheckLine, RiAlertLine,
  RiShieldFlashLine,
} from 'react-icons/ri'
import { Card, PageWrapper, PageHeader, SectionHeader, Tag, Btn } from '../../components/ui'

const DLP_API = '/api/dlp'

const ENGINE_OPTIONS = ['Regex', 'NER (spaCy)', 'BERT', 'Entropy', 'YARA', 'Regex + BERT', 'Custom']
const ACTION_OPTIONS = ['Block', 'Redact', 'Alert']
const DEPT_OPTIONS   = ['finance', 'hr', 'engineering', 'strategy', 'legal', 'default']

const ACTION_STYLE = {
  Block:  'bg-red-50 text-red-600 border border-red-100',
  Redact: 'bg-orange-50 text-orange-600 border border-orange-100',
  Alert:  'bg-yellow-50 text-yellow-600 border border-yellow-100',
}

const EMPTY_FORM = {
  name: '', description: '', engine_type: 'Regex', action: 'Block',
  departments: [], patterns: [], is_active: true,
}

// ── Small helper: inline tag-style department pill ──────────────────────────
function DeptPill({ dept }) {
  const colors = {
    finance:'bg-blue-50 text-blue-600', hr:'bg-purple-50 text-purple-600',
    engineering:'bg-emerald-50 text-emerald-700', strategy:'bg-indigo-50 text-indigo-600',
    legal:'bg-pink-50 text-pink-700', default:'bg-slate-50 text-slate-600',
  }
  return (
    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${colors[dept] || 'bg-slate-50 text-slate-500'}`}>
      {dept}
    </span>
  )
}

// ── New/Edit Policy Modal ─────────────────────────────────────────────────────
function PolicyModal({ initial, onSave, onClose }) {
  const [form, setForm]       = useState(initial || EMPTY_FORM)
  const [saving, setSaving]   = useState(false)
  const [patInput, setPatInput] = useState('')
  const isEdit = !!initial?.id

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const toggleDept = (d) =>
    set('departments', form.departments.includes(d)
      ? form.departments.filter(x => x !== d)
      : [...form.departments, d])

  const addPattern = () => {
    const v = patInput.trim().toLowerCase().replace(/\s+/g, '_')
    if (v && !form.patterns.includes(v)) set('patterns', [...form.patterns, v])
    setPatInput('')
  }

  const submit = async (e) => {
    e.preventDefault()
    if (!form.name.trim()) return
    setSaving(true)
    try {
      const url    = isEdit ? `${DLP_API}/admin/policies/${initial.id}` : `${DLP_API}/admin/policies`
      const method = isEdit ? 'PUT' : 'POST'
      const res    = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      })
      if (!res.ok) throw new Error(await res.text())
      onSave(await res.json())
    } catch (err) {
      alert(`Save failed: ${err.message}`)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="bg-white rounded-2xl shadow-2xl w-full max-w-lg overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100 bg-gradient-to-r from-sky-50 to-white">
          <div className="flex items-center gap-2">
            <RiShieldFlashLine className="text-sky-500 text-lg" />
            <h2 className="text-[15px] font-bold text-slate-800">
              {isEdit ? 'Edit Policy' : 'New DLP Policy'}
            </h2>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 transition-colors">
            <RiCloseLine className="text-xl" />
          </button>
        </div>

        {/* Body */}
        <form onSubmit={submit} className="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
          {/* Name */}
          <div>
            <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-1">
              Policy Name *
            </label>
            <input
              required
              value={form.name}
              onChange={e => set('name', e.target.value)}
              placeholder="e.g. Source Code / Git Secrets"
              className="w-full border border-slate-200 rounded-lg px-3 py-2 text-[13px] text-slate-800 focus:outline-none focus:ring-2 focus:ring-sky-300"
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-1">
              Description
            </label>
            <textarea
              rows={2}
              value={form.description}
              onChange={e => set('description', e.target.value)}
              placeholder="Describe what this policy detects and blocks…"
              className="w-full border border-slate-200 rounded-lg px-3 py-2 text-[13px] text-slate-800 focus:outline-none focus:ring-2 focus:ring-sky-300 resize-none"
            />
          </div>

          {/* Engine + Action row */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-1">
                Detection Engine
              </label>
              <select
                value={form.engine_type}
                onChange={e => set('engine_type', e.target.value)}
                className="w-full border border-slate-200 rounded-lg px-3 py-2 text-[13px] text-slate-800 focus:outline-none focus:ring-2 focus:ring-sky-300"
              >
                {ENGINE_OPTIONS.map(o => <option key={o}>{o}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-1">
                Enforcement Action
              </label>
              <select
                value={form.action}
                onChange={e => set('action', e.target.value)}
                className="w-full border border-slate-200 rounded-lg px-3 py-2 text-[13px] text-slate-800 focus:outline-none focus:ring-2 focus:ring-sky-300"
              >
                {ACTION_OPTIONS.map(o => <option key={o}>{o}</option>)}
              </select>
            </div>
          </div>

          {/* Departments */}
          <div>
            <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-2">
              Applies to Departments <span className="text-slate-300 font-normal normal-case">(empty = all)</span>
            </label>
            <div className="flex flex-wrap gap-2">
              {DEPT_OPTIONS.map(d => (
                <button
                  type="button" key={d}
                  onClick={() => toggleDept(d)}
                  className={`text-[11px] px-3 py-1 rounded-full font-semibold border transition-colors ${
                    form.departments.includes(d)
                      ? 'bg-sky-500 text-white border-sky-500'
                      : 'bg-white text-slate-500 border-slate-200 hover:border-sky-300'
                  }`}
                >
                  {d}
                </button>
              ))}
            </div>
          </div>

          {/* Detection Patterns */}
          <div>
            <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-1">
              Detection Category Keys
            </label>
            <div className="flex gap-2 mb-2">
              <input
                value={patInput}
                onChange={e => setPatInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), addPattern())}
                placeholder="e.g. aws_access_key"
                className="flex-1 border border-slate-200 rounded-lg px-3 py-1.5 text-[12px] text-slate-800 focus:outline-none focus:ring-2 focus:ring-sky-300"
              />
              <button
                type="button" onClick={addPattern}
                className="px-3 py-1.5 bg-sky-50 text-sky-600 border border-sky-200 rounded-lg text-[12px] font-semibold hover:bg-sky-100"
              >
                Add
              </button>
            </div>
            <div className="flex flex-wrap gap-1.5 min-h-[28px]">
              {form.patterns.map(p => (
                <span key={p} className="inline-flex items-center gap-1 bg-slate-100 text-slate-600 text-[11px] font-mono px-2 py-0.5 rounded-md">
                  {p}
                  <button type="button" onClick={() => set('patterns', form.patterns.filter(x => x !== p))}
                    className="text-slate-400 hover:text-red-500 ml-0.5">×</button>
                </span>
              ))}
            </div>
          </div>

          {/* Active toggle */}
          <label className="flex items-center gap-3 cursor-pointer select-none">
            <button
              type="button"
              onClick={() => set('is_active', !form.is_active)}
              className="focus:outline-none"
            >
              {form.is_active
                ? <RiToggleFill className="text-3xl text-emerald-500" />
                : <RiToggleLine className="text-3xl text-slate-300" />}
            </button>
            <span className="text-[13px] font-semibold text-slate-700">Policy Active</span>
          </label>

          {/* Buttons */}
          <div className="flex justify-end gap-3 pt-2 border-t border-slate-100">
            <Btn type="button" variant="ghost" onClick={onClose}>Cancel</Btn>
            <Btn type="submit" variant="primary" disabled={saving}>
              {saving ? 'Saving…' : isEdit ? 'Update Policy' : 'Create Policy'}
            </Btn>
          </div>
        </form>
      </motion.div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function ModelPolicies() {
  const [policies, setPolicies]   = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [modal, setModal]         = useState(null)  // null | 'create' | policy object for edit
  const [seeding, setSeeding]     = useState(false)
  const [seedMsg, setSeedMsg]     = useState(null)
  const [deleteId, setDeleteId]   = useState(null)

  const fetchPolicies = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`${DLP_API}/admin/policies`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setPolicies(await res.json())
    } catch (err) {
      setError('Could not load policies — is the DLP Gateway running?')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchPolicies() }, [fetchPolicies])

  const handleToggle = async (id) => {
    try {
      const res = await fetch(`${DLP_API}/admin/policies/${id}/toggle`, { method: 'PATCH' })
      if (!res.ok) throw new Error()
      const updated = await res.json()
      setPolicies(prev => prev.map(p => p.id === id ? updated : p))
    } catch {
      alert('Failed to toggle policy.')
    }
  }

  const handleDelete = async (id) => {
    try {
      const res = await fetch(`${DLP_API}/admin/policies/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error()
      setPolicies(prev => prev.filter(p => p.id !== id))
      setDeleteId(null)
    } catch {
      alert('Failed to delete policy.')
    }
  }

  const handleSave = (policy) => {
    setPolicies(prev => {
      const idx = prev.findIndex(p => p.id === policy.id)
      return idx >= 0 ? prev.map(p => p.id === policy.id ? policy : p) : [...prev, policy]
    })
    setModal(null)
  }

  const handleSeed = async () => {
    setSeeding(true)
    setSeedMsg(null)
    try {
      const res = await fetch(`${DLP_API}/admin/policies/seed`, { method: 'POST' })
      const data = await res.json()
      setSeedMsg(`Seeded ${data.seeded} policies from policies.yaml`)
      fetchPolicies()
    } catch {
      setSeedMsg('Seed failed — check DLP Gateway logs.')
    } finally {
      setSeeding(false)
    }
  }

  const active   = policies.filter(p => p.is_active).length
  const inactive = policies.length - active

  return (
    <PageWrapper>
      <PageHeader
        title="DLP Policies & Enforcement Rules"
        sub="Configure data classification rules, actions (Block / Redact / Alert), and enforcement status."
        right={
          <div className="flex items-center gap-2">
            <Btn variant="ghost" onClick={fetchPolicies} disabled={loading}>
              <RiRefreshLine className={loading ? 'animate-spin' : ''} /> Refresh
            </Btn>
            <Btn variant="ghost" onClick={handleSeed} disabled={seeding}>
              <RiPlantLine /> {seeding ? 'Seeding…' : 'Seed from YAML'}
            </Btn>
            <Btn variant="primary" onClick={() => setModal('create')}>
              <RiAddLine /> New Policy
            </Btn>
          </div>
        }
      />

      {seedMsg && (
        <motion.div
          initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
          className="mb-4 flex items-center gap-2 p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-[12px] text-emerald-700 font-semibold"
        >
          <RiCheckLine className="text-base" /> {seedMsg}
          <button onClick={() => setSeedMsg(null)} className="ml-auto text-emerald-400 hover:text-emerald-600">×</button>
        </motion.div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-5">
        {/* Policy list */}
        <div className="lg:col-span-3 space-y-4">
          <Card>
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <SectionHeader title="Active Data Loss Prevention Rules" />
              <span className="text-[11px] text-slate-400">{policies.length} policies · {active} active</span>
            </div>

            {error && (
              <div className="flex items-center gap-2 mt-4 p-3 bg-red-50 border border-red-100 rounded-xl text-[12px] text-red-600">
                <RiAlertLine /> {error}
              </div>
            )}

            {loading && !error && (
              <div className="py-10 text-center text-[13px] text-slate-400">Loading policies…</div>
            )}

            {!loading && !error && policies.length === 0 && (
              <div className="py-10 text-center">
                <RiDatabaseLine className="text-4xl text-slate-200 mx-auto mb-3" />
                <p className="text-[13px] text-slate-400 mb-4">No policies yet. Create one or seed from the YAML file.</p>
                <Btn variant="outline" onClick={() => setModal('create')}><RiAddLine /> New Policy</Btn>
              </div>
            )}

            <div className="space-y-3 pt-2">
              {policies.map((pol) => (
                <motion.div
                  key={pol.id}
                  layout
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`p-4 border rounded-xl flex items-start gap-4 transition-colors ${
                    pol.is_active
                      ? 'border-sky-200 bg-white shadow-sm'
                      : 'border-slate-100 bg-slate-50 opacity-60'
                  }`}
                >
                  {/* Toggle */}
                  <button
                    onClick={() => handleToggle(pol.id)}
                    className="mt-1 flex-shrink-0 focus:outline-none"
                    title={pol.is_active ? 'Disable policy' : 'Enable policy'}
                  >
                    {pol.is_active
                      ? <RiToggleFill className="text-3xl text-emerald-500" />
                      : <RiToggleLine className="text-3xl text-slate-300" />}
                  </button>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex justify-between items-start mb-1 flex-wrap gap-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[13px] font-bold text-slate-800">{pol.name}</span>
                        <span className="text-[10px] font-mono bg-slate-100 text-slate-500 px-1.5 py-0.5 rounded border border-slate-200">
                          #{pol.id}
                        </span>
                        {pol.departments?.map(d => <DeptPill key={d} dept={d} />)}
                      </div>
                      <span className={`text-[11px] font-bold px-2.5 py-1 rounded-lg ${ACTION_STYLE[pol.action] || ACTION_STYLE.Alert}`}>
                        Action: {pol.action}
                      </span>
                    </div>

                    {pol.description && (
                      <p className="text-[12px] text-slate-500 mb-2 leading-relaxed">{pol.description}</p>
                    )}

                    <div className="flex items-center gap-3 flex-wrap">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">Engine:</span>
                        <Tag>{pol.engine_type}</Tag>
                      </div>
                      {pol.patterns?.length > 0 && (
                        <div className="flex items-center gap-1 flex-wrap">
                          <span className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">Patterns:</span>
                          {pol.patterns.slice(0, 4).map(p => (
                            <span key={p} className="text-[10px] font-mono bg-slate-100 text-slate-500 px-1.5 py-0.5 rounded">{p}</span>
                          ))}
                          {pol.patterns.length > 4 && (
                            <span className="text-[10px] text-slate-400">+{pol.patterns.length - 4} more</span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex gap-1 flex-shrink-0">
                    <button
                      onClick={() => setModal(pol)}
                      title="Edit policy"
                      className="p-1.5 rounded-lg text-slate-400 hover:text-sky-500 hover:bg-sky-50 transition-colors"
                    >
                      <RiEditLine className="text-base" />
                    </button>
                    {deleteId === pol.id ? (
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => handleDelete(pol.id)}
                          className="text-[11px] font-semibold text-red-600 bg-red-50 border border-red-200 px-2 py-1 rounded-lg hover:bg-red-100"
                        >Confirm</button>
                        <button
                          onClick={() => setDeleteId(null)}
                          className="text-[11px] text-slate-500 px-2 py-1 rounded-lg hover:bg-slate-100"
                        >Cancel</button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setDeleteId(pol.id)}
                        title="Delete policy"
                        className="p-1.5 rounded-lg text-slate-400 hover:text-red-500 hover:bg-red-50 transition-colors"
                      >
                        <RiDeleteBinLine className="text-base" />
                      </button>
                    )}
                  </div>
                </motion.div>
              ))}
            </div>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          <Card className="bg-sky-50 border border-sky-100">
            <div className="flex gap-3 items-center mb-3">
              <RiShieldUserLine className="text-sky-600 text-xl" />
              <h3 className="text-[13px] font-bold text-sky-900">Enforcement Mode</h3>
            </div>
            <p className="text-[11px] text-sky-700/80 mb-4">
              The DLP system is running in <strong>Strict Blocking</strong> mode.
              Redacted/Blocked payloads will not reach external LLM platforms.
            </p>
            <button className="w-full bg-white text-sky-600 border border-sky-300 font-bold text-[11px] py-1.5 rounded-lg hover:bg-sky-100">
              Switch to Audit Only
            </button>
          </Card>

          <Card>
            <h3 className="text-[12px] font-bold text-slate-700 mb-3">Policy Summary</h3>
            <div className="space-y-2">
              {[
                { label: 'Total Policies', val: policies.length,  color: 'text-slate-800' },
                { label: 'Active',         val: active,            color: 'text-emerald-600' },
                { label: 'Disabled',       val: inactive,          color: 'text-slate-400' },
                { label: 'Block Rules',    val: policies.filter(p => p.action === 'Block').length,  color: 'text-red-600' },
                { label: 'Redact Rules',   val: policies.filter(p => p.action === 'Redact').length, color: 'text-orange-600' },
                { label: 'Alert Rules',    val: policies.filter(p => p.action === 'Alert').length,  color: 'text-yellow-600' },
              ].map(({ label, val, color }) => (
                <div key={label} className="flex justify-between items-center">
                  <span className="text-[11px] text-slate-500">{label}</span>
                  <span className={`text-[13px] font-bold ${color}`}>{val}</span>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <h3 className="text-[12px] font-bold text-slate-700 mb-2">Quick Add</h3>
            <p className="text-[11px] text-slate-400 mb-3">Use "Seed from YAML" to import all department policies, or create a custom rule.</p>
            <Btn variant="outline" className="w-full justify-center" onClick={() => setModal('create')}>
              <RiAddLine /> Custom Rule
            </Btn>
          </Card>
        </div>
      </div>

      {/* Modal */}
      <AnimatePresence>
        {modal && (
          <PolicyModal
            initial={modal === 'create' ? null : modal}
            onSave={handleSave}
            onClose={() => setModal(null)}
          />
        )}
      </AnimatePresence>
    </PageWrapper>
  )
}

