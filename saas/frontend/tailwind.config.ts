import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['var(--font-inter)', 'sans-serif'],
        display: ['var(--font-space-grotesk)', 'sans-serif'],
      },
      colors: {
        background: '#050816',
        foreground: '#ffffff',
        card: '#0B1220',
        'card-hover': '#111A2E',
        border: 'rgba(255, 255, 255, 0.08)',
        primary: {
          DEFAULT: '#3b82f6', // Electric Blue
          cyan: '#22d3ee', // Neon Cyan
          purple: '#9333ea', // Purple Aurora
          glow: 'rgba(59, 130, 246, 0.5)',
        },
        accent: {
          emerald: '#10b981',
          danger: '#ef4444', // Red Neon
        },
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'cyber-grid': 'url("https://res.cloudinary.com/dzl9yxixg/image/upload/v1714652431/grid-dark_l3rsw2.svg")',
        'aurora': 'linear-gradient(to right, #9333ea, #3b82f6, #22d3ee)',
      },
      animation: {
        'float': 'float 6s ease-in-out infinite',
        'aurora-pan': 'aurora-pan 15s linear infinite',
        'pulse-glow': 'pulse-glow 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scroll-left': 'scroll-left 30s linear infinite',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-20px)' },
        },
        'aurora-pan': {
          '0%': { backgroundPosition: '0% 50%' },
          '100%': { backgroundPosition: '100% 50%' },
        },
        'pulse-glow': {
          '0%, 100%': { opacity: '0.4' },
          '50%': { opacity: '0.8' },
        },
        'scroll-left': {
          '0%': { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(-100%)' },
        },
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
};

export default config;