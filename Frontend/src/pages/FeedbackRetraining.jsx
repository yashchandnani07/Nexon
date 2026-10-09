import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  RiCheckboxCircleLine, RiCloseCircleLine, RiRefreshLine,
  RiDownloadLine, RiFilterLine,
} from 'react-icons/ri'
import {
  Card, Btn, RiskBadge, PageWrapper, PageHeader,
  SectionHeader, SidebarStat, HorizBar, FormSelect, Tag, Pagination, ProgressBar,
} from '../components/ui'

const rows = [
  { ts: 'Mar 23, 09:42', subject: 'CEO wire transfer urgent',  module: 'Email',  model: 'critical',   analyst: 'critical',   correct: true,  reviewer: 'AK-001' },
  { ts: 'Mar 23, 09:15', subject: 'AWS_SECRET in config.py',   module: 'Creds',  model: 'critical',   analyst: 'critical',   correct: true,  reviewer: 'SR-002' },
  { ts: 'Mar 23, 08:50', subject: 'Monthly newsletter.pdf',     module: 'File',   model: 'high',       analyst: 'safe',       correct: false, reviewer: 'AK-001' },
  { ts: 'Mar 23, 08:30', subject: 'paypa1-secure.com login',    module: 'Web',    model: 'critical',   analyst: 'critical',   correct: true,  reviewer: 'SM-003' },
  { ts: 'Mar 23, 07:55', subject: 'Internal meeting invite',    module: 'Email',  model: 'suspicious', analyst: 'safe',       correct: false, reviewer: 'RD-004' },
  { ts: 'Mar 23, 07:20', subject: 'ceo_voice_msg.wav',          module: 'Voice',  model: 'critical',   analyst: 'critical',   correct: true,  reviewer: 'AK-001' },
  { ts: 'Mar 22, 18:40', subject: 'Ignore all previous instruct…', module: 'Prompt', model: 'critical', analyst: 'critical',  correct: true,  reviewer: 'SR-002' },
]

const moduleAccuracy = [
  { label: 'Email Phishing',      value: 93 },
  { label: 'Credential Scanner',  value: 97 },
  { label: 'Attachment Analyzer', value: 88 },
  { label: 'Website Spoofing',    value: 96 },
  { label: 'Deepfake Voice',      value: 85 },
  { label: 'Prompt Injection',    value: 94 },
]

const queueCount   = 49
const queueTarget  = 50
const queuePct     = Math.round((queueCount / queueTarget) * 100)
const canRetrain   = queueCount >= queueTarget

export default function FeedbackRetraining() {
  const [moduleFilter,  setModuleFilter]  = useState('All Modules')
  const [verdictFilter, setVerdictFilter] = useState('All Verdicts')
  const [dateFilter,    setDateFilter]    = useState('All Dates')
  const [correctFilter, setCorrectFilter] = useState('All Correctness')

  const filtered = rows.filter(r => {
    if (moduleFilter  !== 'All Modules'    && !r.module.toLowerCase().includes(moduleFilter.split(' ')[0].toLowerCase())) return false
    if (correctFilter === '✅ Correct'     && !r.correct) return false
    if (correctFilter === '❌ Incorrect'   &&  r.correct) return false
    return true
  })

  return (
    <PageWrapper>
      <PageHeader
        title="Feedback & Retraining Panel"
        sub="Human-in-the-loop verification · Model improvement pipeline · False positive reduction"
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left: table */}
        <div className="lg:col-span-2 space-y-4">
          {/* Filter bar */}
          <Card hover={false}>
            <div className="flex flex-wrap gap-2 items-center">
              <RiFilterLine className="text-slate-400 text-base flex-shrink-0" />

              <FormSelect value={moduleFilter} onChange={e => setModuleFilter(e.target.value)}>
                {['All Modules','Email','Credential','Attachment','Website','Voice','Prompt','Sandbox'].map(o => (
                  <option key={o}>{o}</option>
                ))}
              </FormSelect>

              <FormSelect value={verdictFilter} onChange={e => setVerdictFilter(e.target.value)}>
                {['All Verdicts','Critical','High Risk','Suspicious','Safe'].map(o => (
                  <option key={o}>{o}</option>
                ))}
              </FormSelect>

              <FormSelect value={dateFilter} onChange={e => setDateFilter(e.target.value)}>
                {['All Dates','Today','Last 7 Days','Last 30 Days'].map(o => (
                  <option key={o}>{o}</option>
                ))}
              </FormSelect>

              <FormSelect value={correctFilter} onChange={e => setCorrectFilter(e.target.value)}>
                {['All Correctness','✅ Correct','❌ Incorrect','Pending Review'].map(o => (
                  <option key={o}>{o}</option>
                ))}
              </FormSelect>

              <Btn variant="ghost" className="!px-3 !py-1.5 text-[12px] ml-auto">
                Clear Filters
              </Btn>
            </div>
          </Card>

          {/* Table */}
          <Card hover={false} className="!p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr>
                    <th className="tbl-th">Timestamp</th>
                    <th className="tbl-th">Subject / Content</th>
                    <th className="tbl-th">Module</th>
                    <th className="tbl-th">Model Verdict</th>
                    <th className="tbl-th">Analyst Verdict</th>
                    <th className="tbl-th text-center">Correct?</th>
                    <th className="tbl-th">Reviewer</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((r, i) => (
                    <motion.tr
                      key={i}
                      className={`tbl-tr ${!r.correct ? 'bg-yellow-50/60' : ''}`}
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.04 }}
                    >
                      <td className="tbl-td whitespace-nowrap text-[11px] text-slate-400">{r.ts}</td>
                      <td className="tbl-td max-w-[180px]">
                        <p className="truncate text-[12px] font-medium text-slate-700">{r.subject}</p>
                      </td>
                      <td className="tbl-td"><Tag>{r.module}</Tag></td>
                      <td className="tbl-td"><RiskBadge level={r.model} /></td>
                      <td className="tbl-td"><RiskBadge level={r.analyst} /></td>
                      <td className="tbl-td text-center">
                        {r.correct
                          ? <RiCheckboxCircleLine className="text-emerald-500 text-lg inline" />
                          : <RiCloseCircleLine   className="text-red-500 text-lg inline" />
                        }
                      </td>
                      <td className="tbl-td text-[12px] font-mono text-slate-500">{r.reviewer}</td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="px-4 py-3 border-t border-sky-50 bg-white">
              <Pagination current={1} total={12} />
            </div>
          </Card>
        </div>

        {/* Right sidebar */}
        <div className="space-y-4">
          {/* Accuracy hero */}
          <Card>
            <SectionHeader title="Feedback Stats" />
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5, ease: [0.34, 1.2, 0.64, 1] }}
              className="text-center py-5 border-b border-sky-100 mb-3"
            >
              <p className="text-5xl font-bold text-emerald-600 leading-none">94.2%</p>
              <p className="text-[12px] text-slate-400 mt-2">Human-Verified Accuracy</p>
            </motion.div>

            <SidebarStat value="842"  label="Total Feedback Submitted" />
            <SidebarStat value="32"   label="False Positives" accent />
            <SidebarStat value="17"   label="False Negatives" accent />
          </Card>

          {/* Retraining queue */}
          <Card>
            <SectionHeader title="Retraining Queue" />
            <div className="flex items-baseline justify-between mb-2">
              <p className="text-2xl font-bold font-mono text-slate-800">
                {queueCount}
                <span className="text-base text-slate-400 font-normal"> / {queueTarget}</span>
              </p>
              <Tag variant={canRetrain ? 'solid' : 'default'}>
                {canRetrain ? 'Ready' : 'Almost ready'}
              </Tag>
            </div>

            <ProgressBar value={queuePct} className="mb-3" />

            <p className="text-[12px] text-slate-400 mb-4 leading-relaxed">
              Minimum <strong className="text-slate-600">{queueTarget} corrections</strong> required to trigger retraining.{' '}
              {!canRetrain && <span className="text-sky-600 font-semibold">{queueTarget - queueCount} more needed.</span>}
            </p>

            <div className="space-y-2">
              <Btn
                variant="primary"
                className="w-full justify-center"
                disabled={!canRetrain}
              >
                <RiRefreshLine />
                {canRetrain ? 'Trigger Retraining' : `Retraining (${queueTarget - queueCount} more needed)`}
              </Btn>

              <Btn variant="ghost" className="w-full justify-center">
                <RiDownloadLine /> Export Corrections as CSV
              </Btn>
            </div>
          </Card>

          {/* Module accuracy */}
          <Card>
            <SectionHeader title="Accuracy by Module" />
            {moduleAccuracy.map(({ label, value }, i) => (
              <HorizBar key={label} label={label} count={`${value}%`} max={100} delay={i * 0.07} />
            ))}
          </Card>
        </div>
      </div>
    </PageWrapper>
  )
}
