/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        tw: {
          bg: '#f5f8fa',         // Twitter light background
          card: '#ffffff',       // White cards
          border: '#e1e8ed',     // Soft border
          primary: '#1d9bf0',    // Twitter blue
          primarySoft: '#e8f5fd',
          text: '#0f1419',
          textSoft: '#536471',
          danger: '#f4212e',
          warn: '#ffad1f',
          success: '#00ba7c',
        },
      },
      boxShadow: {
        card: '0 8px 24px rgba(15, 23, 42, 0.08)',
      },
      borderRadius: {
        xl2: '20px',
      },
      transitionTimingFunction: {
        smooth: 'cubic-bezier(0.22, 1, 0.36, 1)',
      },
    },
  },
  plugins: [],
}
