import { motion } from 'framer-motion'
import {
  RiLineChartLine, RiCloudWindyLine, RiDatabaseLine, RiRefreshLine, RiLoader4Line,
} from 'react-icons/ri'
import {
  LineChart, Line, ReferenceLine, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts'
import {
  Card, StatCard, PageWrapper, PageHeader, SectionHeader, Tag, Btn,
} from '../../components/ui'

const modelPerformance = [
  { epoch: '10', acc: 88, valAcc: 86 },
  { epoch: '20', acc: 91, valAcc: 89 },
  { epoch: '30', acc: 93, valAcc: 90 },
  { epoch: '40', acc: 95, valAcc: 91 },
  { epoch: '50', acc: 96, valAcc: 92 },
  { epoch: '60', acc: 97, valAcc: 94 },
  { epoch: '70', acc: 98, valAcc: 96 },
  { epoch: '80', acc: 99, valAcc: 97 },
]

const recentRetrainings = [
  { model: 'Prompt Injection BERT', trigger: 'Concept Drift', time: '1h 20m', status: 'Completed',   improv: '+1.2%' },
  { model: 'DLP Regex Engine',      trigger: 'Manual Update', time: '2m',     status: 'Completed',   improv: 'N/A'  },
  { model: 'Email Phishing NLP',    trigger: 'Feedback Loop', time: '45m',    status: 'In Progress', improv: '...'  },
  { model: 'Wav2Vec2 Voice',        trigger: 'Low Accuracy',  time: 'Failed', status: 'Failed',      improv: '0%'   },
]

const statusChip = {
  'Completed':   'chip chip-safe',
  'In Progress': 'chip chip-info',
  'Failed':      'chip chip-critical',
}

const netChangeColor = (v) => {
  if (!v || v === 'N/A' || v === '...') return 'text-[#94A3B8] italic'
  if (v.startsWith('+')) return 'text-[#059669] font-semibold'
  return 'text-[#DC2626] font-semibold'
}

const netChangePrefix = (v) => {
  if (!v || v === 'N/A' || v === '...') return ''
  if (v.startsWith('+')) return '▲ '
  return ''
}

const tooltipStyle = {
  backgroundColor: '#fff', border: '1px solid #E2E8F0', borderRadius: '12px',
  fontSize: '11px', fontWeight: 600,
}

export default function ModelAnalytics() {
  return (
    <PageWrapper>
      <PageHeader
        title="Model Analytics"
        sub="Track detection model performance, accuracy metrics, and retraining pipelines."
        right={
          <button className="btn-primary group">
            <RiRefreshLine className="group-hover:rotate-180 transition-transform duration-500" />
            Trigger Retraining
          </button>
        }
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard icon={RiLineChartLine}  value="96.8%" label="Avg Fleet Accuracy"    change="0.4%"  changeDir="up"   iconBg="icon-box icon-box-green"  />
        <StatCard icon={RiCloudWindyLine} value="3"     label="Data Drifts Detected"  change="-1"    changeDir="down" iconBg="icon-box icon-box-amber"  />
        <StatCard icon={RiDatabaseLine}   value="1.2M"  label="Samples in Feedback"   change="40k"   changeDir="up"   iconBg="icon-box icon-box-blue"   />
        <StatCard icon={RiRefreshLine}    value="4"     label="Retrainings (7d)"       change="1"     changeDir="up"   iconBg="icon-box icon-box-indigo" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
        {/* Training Convergence Chart */}
        <Card>
          <div className="flex items-center justify-between mb-1">
            <SectionHeader title="Training Convergence (Prompt BERT)" />
          </div>
          <div className="flex items-center gap-4 text-[11px] font-medium text-[#64748B] mb-3">
            <span className="flex items-center gap-1.5"><span className="w-8 h-0.5 bg-[#2563EB] inline-block rounded" /> Training Accuracy</span>
            <span className="flex items-center gap-1.5"><span className="w-8 h-0.5 bg-[#6366F1] inline-block rounded" /> Validation Accuracy</span>
            <span className="flex items-center gap-1.5"><span className="w-5 h-0.5 bg-[#94A3B8] border-dashed inline-block" style={{borderTop:'1.5px dashed #94A3B8'}} /> Target (95%)</span>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={modelPerformance} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
              <XAxis dataKey="epoch" tick={{ fontSize: 10, fill: '#94A3B8' }} tickLine={false} axisLine={false} label={{ value: 'Epoch', position: 'insideBottom', offset: -2, fontSize: 10, fill: '#94A3B8' }} />
              <YAxis domain={[80, 100]} tick={{ fontSize: 10, fill: '#94A3B8' }} tickLine={false} axisLine={false} label={{ value: 'Accuracy (%)', angle: -90, position: 'insideLeft', fontSize: 10, fill: '#94A3B8', offset: 28 }} />
              <Tooltip contentStyle={tooltipStyle} />
              <ReferenceLine y={95} stroke="#94A3B8" strokeDasharray="4 2" strokeWidth={1.5} />
              <Line type="monotone" dataKey="acc"    stroke="#2563EB" strokeWidth={2.5} name="Training Accuracy"   dot={false} activeDot={{ r: 5 }} />
              <Line type="monotone" dataKey="valAcc" stroke="#6366F1" strokeWidth={2.5} name="Validation Accuracy" dot={false} activeDot={{ r: 5 }} />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        {/* Retraining Jobs */}
        <Card>
          <SectionHeader title="Recent Retraining Jobs" />
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr>
                  <th className="tbl-th">Model</th>
                  <th className="tbl-th">Trigger</th>
                  <th className="tbl-th">Status</th>
                  <th className="tbl-th">Net Change</th>
                </tr>
              </thead>
              <tbody>
                {recentRetrainings.map((job, i) => (
                  <motion.tr
                    key={i}
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.05 }}
                    className="tbl-tr"
                  >
                    <td className="tbl-td text-[12px] font-semibold text-[#374151]">{job.model}</td>
                    <td className="tbl-td text-[11px] text-[#64748B]">{job.trigger}</td>
                    <td className="tbl-td">
                      <div className="flex items-center gap-1.5">
                        <span className={statusChip[job.status]}>
                          {job.status === 'In Progress' && <RiLoader4Line className="animate-spin text-[10px]" />}
                          {job.status}
                        </span>
                      </div>
                    </td>
                    <td className={`tbl-td text-[12px] ${netChangeColor(job.improv)}`}>
                      {netChangePrefix(job.improv)}{job.improv}
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </PageWrapper>
  )
}
