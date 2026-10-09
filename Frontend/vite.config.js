import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api/dlp': {
        target: 'http://localhost:8001',
        rewrite: (path) => path.replace(/^\/api\/dlp/, ''),
        changeOrigin: true,
      },
      '/api/sandbox': {
        target: 'http://localhost:8000',
        rewrite: (path) => path.replace(/^\/api\/sandbox/, ''),
        changeOrigin: true,
      },
      // Prompt Guard
      '/api/prompt-guard': {
        target: 'http://127.0.0.1:8005',
        rewrite: (path) => path.replace(/^\/api\/prompt-guard/, ''),
        changeOrigin: true,
      },
      // Voice scan WebSocket (real-time recording)
      '/api/voice-scan/ws': {
        target: 'ws://localhost:8006',
        ws: true,
        rewrite: (path) => path.replace(/^\/api\/voice-scan/, ''),
        changeOrigin: true,
      },
      // Voice scan HTTP
      '/api/voice-scan': {
        target: 'http://localhost:8006',
        rewrite: (path) => path.replace(/^\/api\/voice-scan/, ''),
        changeOrigin: true,
      },
      // Website Spoofing
      '/api/website-spoofing': {
        target: 'http://localhost:8008',
        rewrite: (path) => path.replace(/^\/api\/website-spoofing/, ''),
        changeOrigin: true,
      },
      // Attachment Scanner
      '/api/attachment-scan': {
        target: 'http://localhost:8007',
        rewrite: (path) => path.replace(/^\/api\/attachment-scan/, ''),
        changeOrigin: true,
      },
      // Credential Scanner
      '/api/cred-scan': {
        target: 'http://localhost:8002',
        rewrite: (path) => path.replace(/^\/api\/cred-scan/, ''),
        changeOrigin: true,
      },
      // Email Monitor
      '/api/email': {
        target: 'http://localhost:8009',
        rewrite: (path) => path.replace(/^\/api\/email/, ''),
        changeOrigin: true,
      },
      // Legacy WS
      '/ws/live': {
        target: 'ws://localhost:8001',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})
