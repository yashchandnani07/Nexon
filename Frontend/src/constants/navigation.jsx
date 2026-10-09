import {
  RiDashboardLine,
  RiMailSendLine,
  RiKeyLine,
  RiAttachment2,
  RiGlobalLine,
  RiMicLine,
  RiMessage3Line,
  RiRefreshLine,
  RiLineChartLine,
  RiShieldUserLine,
  RiDatabaseLine,
  RiRobotFill,
  RiInboxLine,
  RiBrainLine,
} from 'react-icons/ri'

/* ──────────────────────────────────────────────
   EMPLOYEE dashboard nav
────────────────────────────────────────────── */
export const NAV_ITEMS = [
  {
    section: 'Overview',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: RiDashboardLine },
    ],
  },
  {
    section: 'Detection Modules',
    items: [
      { id: 'mailbox',     label: 'Mailbox',               icon: RiInboxLine      },
      { id: 'email',       label: 'Email Phishing',        icon: RiMailSendLine   },
      { id: 'credential',  label: 'Credential Scanner',    icon: RiKeyLine        },
      { id: 'attachment',  label: 'Attachment Analyzer',   icon: RiAttachment2    },
      { id: 'website',     label: 'Website Spoofing',      icon: RiGlobalLine     },
      { id: 'voice',       label: 'Deepfake Voice',        icon: RiMicLine        },
    ],
  },
  {
    section: 'Management',
    items: [
      { id: 'feedback', label: 'Feedback & Retraining', icon: RiRefreshLine    },
      { id: 'admin',    label: 'Admin Portal',          icon: RiShieldUserLine },
    ],
  },
]

/* ──────────────────────────────────────────────
   ADMIN dashboard nav (separate)
────────────────────────────────────────────── */
export const ADMIN_NAV_ITEMS = [
  {
    section: 'Overview',
    items: [
      { id: 'adminoverview', label: 'Admin Dashboard',  icon: RiDashboardLine  },
    ],
  },
  {
    section: 'Security Operations',
    items: [
      { id: 'dlpguardian', label: 'DLP Guardian',       icon: RiShieldUserLine },
      { id: 'prompt',      label: 'Guard Chatbot',      icon: RiMessage3Line   },
      { id: 'sandbox',     label: 'Agent Sandbox',      icon: RiRobotFill      },
    ],
  },
  {
    section: 'Model Management',
    items: [
      { id: 'modelanalytics',  label: 'Model Analytics',     icon: RiLineChartLine },
      { id: 'modelpolicies',   label: 'DLP Policies',        icon: RiDatabaseLine  },
      { id: 'modelretraining', label: 'Model Retraining',    icon: RiBrainLine     },
    ],
  },
]

export const PAGE_META = {
  dashboard:      { title: 'Security Dashboard',        sub: 'Real-time AI threat detection overview'              },
  myanalytics:    { title: 'My Analytics',               sub: 'Personal scan history · Threat insights · Activity' },
  mailbox:        { title: 'Mailbox',                       sub: 'Real-time email monitoring · Security analysis · IMAP polling'          },
  email:          { title: 'Email Phishing Detector',   sub: 'BERT NLP · Header forensics · URL reputation'       },
  credential:     { title: 'Credential Leakage Scanner',sub: 'TruffleHog · High-entropy · spaCy PII extraction'   },
  attachment:     { title: 'Attachment Analyzer',        sub: 'YARA rules · PDF stream analysis · MalwareBazaar'   },
  website:        { title: 'Website Spoofing Detector',  sub: 'CNN visual fingerprinting · WHOIS · Cookie monitor' },
  voice:          { title: 'Deepfake Voice Detector',    sub: 'MFCC · SVM anti-spoofing · Wav2Vec2 ensemble'      },
  prompt:         { title: 'Prompt Injection Guard',     sub: 'ProtectAI DeBERTa v2 · Multi-turn detection · Safe Llama3 responses'  },
  sandbox:        { title: 'AI Agent Sandbox',           sub: 'Docker isolation · strace · Filesystem monitoring'  },
  feedback:       { title: 'Feedback & Retraining',      sub: 'Human-in-the-loop model improvement pipeline'      },
  // Admin pages
  adminoverview:  { title: 'Admin Dashboard',            sub: 'Enterprise security overview · Model health · DLP status' },
  dlpguardian:    { title: 'DLP Guardian',               sub: 'Guardrail-DLP · Block sensitive data to ChatGPT/Claude/Gemini' },
  modelanalytics: { title: 'Model Analytics',            sub: 'Detection model performance · Accuracy · Drift · Retraining' },
  modelpolicies:  { title: 'DLP Policies',               sub: 'Configure data classification rules & enforcement policies' },
  modelretraining: { title: 'Model Retraining Centre', sub: 'Human-in-the-loop feedback pipeline · Queue management · On-demand model improvement' },
}
