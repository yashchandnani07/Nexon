/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        sky: {
          50:  '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'card':    '0 1px 3px rgba(0,0,0,0.04), 0 4px 20px rgba(14,165,233,0.05)',
        'card-lg': '0 4px 40px rgba(14,165,233,0.10)',
        'glow':    '0 0 20px rgba(14,165,233,0.20)',
        'glow-sm': '0 0 10px rgba(14,165,233,0.12)',
        'sidebar': '2px 0 20px rgba(0,0,0,0.04)',
      },
      animation: {
        'pulse-slow':    'pulse 3s cubic-bezier(0.4,0,0.6,1) infinite',
        'scan':          'scan 2s ease-in-out infinite',
        'wave':          'wave 1.4s ease-in-out infinite',
        'float':         'float 3s ease-in-out infinite',
        'slide-in-left': 'slideInLeft 0.35s ease both',
      },
      keyframes: {
        scan: {
          '0%':   { transform: 'scaleX(0)', opacity: '1' },
          '80%':  { transform: 'scaleX(1)', opacity: '1' },
          '100%': { transform: 'scaleX(1)', opacity: '0' },
        },
        wave: {
          '0%,100%': { transform: 'scaleY(0.35)' },
          '50%':     { transform: 'scaleY(1)' },
        },
        float: {
          '0%,100%': { transform: 'translateY(0)' },
          '50%':     { transform: 'translateY(-4px)' },
        },
        slideInLeft: {
          from: { opacity: '0', transform: 'translateX(-12px)' },
          to:   { opacity: '1', transform: 'translateX(0)' },
        },
      },
    },
  },
  plugins: [],
}
