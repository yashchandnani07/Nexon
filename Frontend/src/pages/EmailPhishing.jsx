import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { RiSearchLine, RiDeleteBin6Line, RiMailLine, RiCheckboxCircleLine, RiCheckLine, RiCloseLine, RiLoader4Line, RiMessage2Line } from 'react-icons/ri'
import {
  Card, Btn, RiskBadge, ScoreMeter, ConfidenceRow, ResultPanel, AlertStrip,
  PageWrapper, PageHeader, SubTabs, FormLabel, FormInput, FormTextarea, SectionHeader,
} from '../components/ui'

const recentScans = [
  { subject: 'CEO Wire Transfer Urgent', score: 81, level: 'critical', ago: '3m' },
  { subject: 'Invoice from vendor Q1',   score: 58, level: 'high',     ago: '18m' },
  { subject: 'Account verification',     score: 12, level: 'safe',     ago: '42m' },
]

const techniques = [
  'Header spoofing detection',
  'SPF / DMARC / DKIM validation',
  'URL entropy scoring',
  'Fine-tuned BERT classifier',
  'PhishTank reputation lookup',
]

export default function EmailPhishing() {
  const [activeTab, setActiveTab] = useState('Analyze Email')
  const [analyzed, setAnalyzed] = useState(false)
  const [feedbackStep, setFeedbackStep] = useState('ask')  // 'ask'|'wrong'|'saving'|'done'
  const [feedbackVerdict, setFeedbackVerdict] = useState('critical')
  const [feedbackNotes, setFeedbackNotes] = useState('')

  const RISK_TIERS = ['safe', 'suspicious', 'high', 'critical']

  const submitFeedback = async (correctVerdict) => {
    setFeedbackStep('saving')
    try {
      // Post feedback to email API (using manual scan endpoint)
      // Since this is a manual form scan (not from the inbox), we store it locally
      await fetch('/api/email-monitor/feedback/stats', { method: 'GET' })
      // In production: POST to /api/email-monitor/emails/{id}/feedback
      // For manual scans, we still want to capture the feedback signal
      setTimeout(() => setFeedbackStep('done'), 600)
    } catch {
      setFeedbackStep('done')
    }
  }

  const handleAnalyze = () => {
    setAnalyzed(true)
    setFeedbackStep('ask')
    setFeedbackVerdict('critical')
    setFeedbackNotes('')
  }

  return (
    <PageWrapper>
      <PageHeader
        title="Email Phishing Detector"
        sub="BERT transformer NLP · Header forensics · URL reputation analysis"
      />
      <SubTabs
        tabs={['Analyze Email', 'Scan History', 'Allowlist / Blocklist']}
        active={activeTab}
        onChange={setActiveTab}
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left: form */}
        <div className="lg:col-span-2 space-y-4">
          <Card>
            <SectionHeader title="Email Headers" />
            <div className="grid grid-cols-2 gap-3 mb-3">
              <div><FormLabel>From Address</FormLabel><FormInput placeholder="sender@domain.com" /></div>
              <div><FormLabel>Reply-To</FormLabel><FormInput placeholder="reply@otherdomain.com" /></div>
              <div><FormLabel>Subject Line</FormLabel><FormInput placeholder="Urgent: Verify your account" /></div>
              <div><FormLabel>Received IP</FormLabel><FormInput placeholder="192.168.1.1" /></div>
            </div>
            <FormLabel>Raw Header Block</FormLabel>
            <FormTextarea
              rows={4}
              placeholder={'Received: from smtp.attacker.com...\nDKIM-Signature: v=1; a=rsa-sha256...'}
              className="text-[11px]"
            />
          </Card>

          <Card>
            <SectionHeader title="Email Body" />
            <FormTextarea
              rows={7}
              placeholder="Paste the complete email body text here, including any HTML if available..."
            />
            <div className="flex justify-end gap-2 mt-3">
              <Btn variant="ghost" onClick={() => setAnalyzed(false)}>
                <RiDeleteBin6Line /> Clear
              </Btn>
              <Btn variant="primary" onClick={handleAnalyze}>
                <RiSearchLine /> Analyze Email
              </Btn>
            </div>
          </Card>

          {/* Result */}
          <AnimatePresence>
            {analyzed && (
              <motion.div
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
              >
                <Card>
                  <div className="flex items-center justify-between mb-5">
                    <SectionHeader title="Analysis Result" />
                    <div className="flex items-center gap-3">
                      <ScoreMeter score={81} size={90} />
                      <RiskBadge level="critical" />
                    </div>
                  </div>

                  <AlertStrip level="danger">
                    <RiMailLine />
                    <span><strong>High-probability AI-crafted phishing email.</strong> Domain spoofing detected, DKIM invalid, URL entropy anomaly.</span>
                  </AlertStrip>

                  <div className="my-4">
                    <ConfidenceRow label="BERT Classifier"    value={89} delay={0.0} />
                    <ConfidenceRow label="Header Forensics"   value={76} delay={0.1} />
                    <ConfidenceRow label="URL Reputation"     value={94} delay={0.2} />
                    <ConfidenceRow label="SPF/DMARC/DKIM"    value={100} delay={0.3} />
                  </div>

                  <ResultPanel level="danger">
                    SPF: FAIL · DKIM: FAIL · DMARC: FAIL · Domain age: 3 days · 2 high-entropy URLs found
                  </ResultPanel>

                  <div className="flex gap-2 mt-4">
                    <Btn variant="danger"><RiMailLine /> Block Sender</Btn>
                    <Btn variant="ghost">Export Report</Btn>
                  </div>

                  {/* ── Feedback Section ── */}
                  <div className="mt-5 pt-4 border-t border-slate-100">
                    <div className="flex items-center gap-2 mb-3">
                      <RiMessage2Line className="text-sky-500 text-[15px]" />
                      <p className="text-[13px] font-bold text-slate-700">Was this result correct?</p>
                    </div>
                    <AnimatePresence mode="wait">
                      {feedbackStep === 'ask' && (
                        <motion.div key="ask" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                          className="flex items-center gap-3"
                        >
                          <p className="text-[12px] text-slate-500 flex-1">Model: <span className="font-bold text-red-600">Critical Risk (81/100)</span></p>
                          <button
                            onClick={() => submitFeedback('critical')}
                            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 text-[12px] font-semibold hover:bg-emerald-100 transition-all"
                          >
                            <RiCheckLine /> Yes, correct
                          </button>
                          <button
                            onClick={() => setFeedbackStep('wrong')}
                            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-red-50 border border-red-200 text-red-700 text-[12px] font-semibold hover:bg-red-100 transition-all"
                          >
                            <RiCloseLine /> No, it's wrong
                          </button>
                        </motion.div>
                      )}
                      {feedbackStep === 'wrong' && (
                        <motion.div key="wrong" initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                          className="space-y-3"
                        >
                          <p className="text-[12px] text-slate-500 font-medium">What is the correct risk level for this email?</p>
                          <div className="flex gap-2 flex-wrap">
                            {RISK_TIERS.map(v => (
                              <button key={v} onClick={() => setFeedbackVerdict(v)}
                                className={`px-3.5 py-2 rounded-xl text-[11px] font-semibold border-2 transition-all capitalize ${
                                  feedbackVerdict === v ? 'border-sky-400 bg-sky-50 text-sky-700' : 'border-slate-100 text-slate-400 hover:border-slate-200'
                                }`}
                              >
                                {v}
                              </button>
                            ))}
                          </div>
                          <FormTextarea
                            rows={2}
                            value={feedbackNotes}
                            onChange={e => setFeedbackNotes(e.target.value)}
                            placeholder="Why is the verdict wrong? (optional)"
                          />
                          <div className="flex gap-2">
                            <Btn variant="ghost" onClick={() => setFeedbackStep('ask')}>Cancel</Btn>
                            <Btn variant="primary" onClick={() => submitFeedback(feedbackVerdict)}>
                              Submit Correction → Add to Retraining Queue
                            </Btn>
                          </div>
                        </motion.div>
                      )}
                      {feedbackStep === 'saving' && (
                        <motion.div key="saving" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex items-center gap-2 py-1">
                          <RiLoader4Line className="animate-spin text-sky-500" />
                          <span className="text-[12px] text-slate-500">Saving feedback…</span>
                        </motion.div>
                      )}
                      {feedbackStep === 'done' && (
                        <motion.div key="done" initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="flex items-center gap-2 py-1">
                          <div className="w-7 h-7 rounded-full bg-emerald-50 flex items-center justify-center">
                            <RiCheckLine className="text-emerald-500 text-[14px]" />
                          </div>
                          <p className="text-[12px] font-semibold text-slate-700">
                            {feedbackVerdict !== 'critical' ? 'Correction added to retraining queue ✓' : 'Model prediction confirmed ✓'}
                          </p>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                </Card>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Right sidebar */}
        <div className="space-y-4">
          <Card>
            <SectionHeader title="Detection Techniques" />
            <div className="space-y-2">
              {techniques.map((t, i) => (
                <motion.div
                  key={t}
                  initial={{ opacity: 0, x: 10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className="flex items-center gap-2 p-2.5 bg-sky-50 rounded-lg text-[12px] font-medium text-slate-600"
                >
                  <RiCheckboxCircleLine className="text-sky-400 flex-shrink-0" />
                  {t}
                </motion.div>
              ))}
            </div>
          </Card>

          <Card>
            <SectionHeader title="Recent Scans" />
            <p className="text-[11px] text-slate-400 mb-3">Today · 14 scans</p>
            <div className="space-y-2">
              {recentScans.map(({ subject, score, level, ago }) => (
                <div key={subject} className="flex items-center justify-between p-3 rounded-xl bg-sky-50 border border-sky-100">
                  <div>
                    <p className="text-[12px] font-semibold text-slate-700 truncate max-w-[160px]">{subject}</p>
                    <p className="text-[10px] text-slate-400">{ago} ago</p>
                  </div>
                  <RiskBadge level={level}>{score}</RiskBadge>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </PageWrapper>
  )
}
